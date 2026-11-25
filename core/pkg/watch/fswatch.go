package watch

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/kubescape/kubescape/v4/core/cautils"
)

// settleDelay is how long a directory that appeared is left before it is
// registered. On kqueue, fsnotify sends the event for a new subdirectory and
// then, from its own goroutine, watches the directory itself with fewer flags.
// A watch made here at the same moment races with that: it can leave a
// descriptor open that nothing owns, or the directory watched for its removal
// and no longer for what is made in it, while the backend still lists it as
// watched. Nothing the backend reports tells which. So a directory is registered
// once the backend has finished with it, which takes microseconds, not this
// long, and what was made in it meanwhile is found by reading it. On other
// backends the wait costs nothing that the read does not give back.
const settleDelay = 100 * time.Millisecond

// vcsDir is skipped whole: it holds no manifests, and a repository has hundreds
// of directories in it that would each take a watch.
const vcsDir = ".git"

// FileWatcherOptions configures a FileWatcher.
type FileWatcherOptions struct {
	// AcceptDependencies, when set, reports whether a file at path is accepted
	// as a dependency regardless of its extension (e.g. Kustomize patch files
	// and generator inputs), because a render reads the directory it is in,
	// keeping editor-file and path exclusions. It is called as files change
	// rather than once, so a directory that becomes, or stops being, one a
	// render reads is classified as it is when the change is seen.
	AcceptDependencies func(path string) bool

	// Exclude, when set, reports whether a path is kept out of the watch. It is
	// called with absolute paths. Excluded directories are not watched, and an
	// excluded file never signals a change. The root itself is never excluded:
	// it was asked for. The signature is that of (*cautils.PathFilter).Excluded,
	// so a scan's --exclude-path patterns and .kubescapeignore can be passed as
	// filter.Excluded.
	Exclude func(path string, isDir bool) bool

	// OnError, when set, receives problems that leave the watch working, such as
	// a subdirectory that cannot be read. It is called on the watcher's own
	// goroutine, so it must not block. Failures that leave the watch unable to
	// see changes end it instead, and are returned by Err.
	OnError func(error)
}

// FileWatcher reports, on one channel, that something a scan would read has
// changed below a file or directory. It does not say what changed: a scan reads
// the whole input again, so the kind of event does not matter, and a signal
// that turns out to be unnecessary costs one scan, while a missed one is a stale
// result. When in doubt, it signals.
//
// The watched input is either a directory, watched recursively, or one file.
// For a directory, the files that signal are those a scan would load, by their
// extension (.yaml, .yml, .json manifests, .tf and .tfvars Terraform files, and
// .tpl Helm template helpers), less editors' lock files. For a single file,
// that file signals whatever its extension, as does its sibling .kubescapeignore;
// other siblings do not.
//
// Changes are signalled on a channel of capacity one that is sent to without
// blocking, so any number of changes while the reader is busy leave exactly one
// signal behind. A reader that is mid-scan therefore loses nothing and is never
// waited for.
//
// A FileWatcher owns one goroutine, started by NewFileWatcher and ended by
// cancelling the context it was given, by Close, or by a failure that makes the
// watch unreliable. Its Changes channel is closed when that goroutine ends.
//
// A directory that appears below the root is watched after a short wait (see
// settleDelay), and what is in it then is read and signalled, so nothing made in
// it is missed.
//
// Limitations. A symbolic link to a directory below the root is not followed,
// which also keeps a link back up the tree from looping. If the root itself, or
// for a single file its directory, is removed or renamed, the watch ends with an
// error, as the OS drops the watch with it and a new directory of the same name
// cannot be told from another. Resource limits are the OS's: on Linux the
// number of watches (fs.inotify.max_user_watches), and on macOS and the BSDs a
// file descriptor for every file in a watched directory (ulimit -n); the OS
// limits are recognised on those systems only, and on Windows a failure to watch
// is reported as the OS's own error. On macOS and the BSDs a file is watched
// itself only just after it appears, so a rename or removal in that instant is
// seen only as the appearance, which has already asked for a scan.
type FileWatcher struct {
	root string // absolute path that was asked for
	file string // root, when it is a single file; empty for a directory
	dir  string // directory watched in single-file mode
	opts FileWatcherOptions

	fs      *fsnotify.Watcher
	dirs    map[string]struct{} // watched directories; owned by the goroutine once started
	changes chan struct{}

	// depFiles are the paths last seen as dependency files of a rendered root, so
	// their removal is recognised after the path is gone or is a directory.
	// Owned by the goroutine once started, like dirs; made on first use.
	depFiles map[string]struct{}

	// Render dependencies share directory registrations with the input tree.
	// Only the watcher goroutine reads or changes their selection.
	dependencyUpdates   chan dependencyUpdate
	dependencyPlan      dependencyDirectories
	dependencyDirs      dependencyDirectories
	dependencyRetry     <-chan time.Time
	dependencyLinks     map[string]string
	dependencyLinkCheck <-chan time.Time

	pending map[string]struct{} // directories that appeared, to be registered once settleDelay has passed
	settle  *time.Timer
	settleC <-chan time.Time // nil unless the timer is running

	cancel context.CancelFunc
	done   chan struct{} // closed once the goroutine has exited

	// queue holds what the backend delivered, in order, for run to handle.
	// pump, a goroutine of its own, keeps reading the backend's channels into
	// it until the backend is closed, because run also calls the backend's Add
	// and Remove: on Windows those wait for fsnotify's reader thread, which
	// blocks delivering events once the Events buffer is full, so with run as
	// the only reader a burst of events during an Add left each waiting on the
	// other. The queue keeps at most maxQueued deliveries; past that pump drops
	// them, never blocks, and sets overflowed, and run then reconciles as for
	// the backend's own overflow.
	qmu        sync.Mutex
	queue      []backendItem
	overflowed bool          // deliveries were dropped since run last took the queue
	maxQueued  int           // most deliveries the queue keeps
	queued     chan struct{} // capacity one: the queue may have items
	pumped     chan struct{} // closed once pump has exited

	mu  sync.Mutex
	err error // why it ended, if not asked to; set before changes is closed

	// signalHook, when set by a test, is called with the path behind each signal
	// before signals are coalesced.
	signalHook func(path string)

	// addWatch is the backend's Add. A test replaces it
	// to make it fail the way one backend's does.
	addWatch func(path string) error
}

// NewFileWatcher starts watching root, a file or a directory, until ctx is done.
// The watch is in place when it returns, so changes made from then on are not
// missed: start it before the scan whose input it watches. An error is returned
// when the watch cannot be established, including when an OS limit is reached,
// so a watcher never claims to be watching what it could not register.
func NewFileWatcher(ctx context.Context, root string, opts FileWatcherOptions) (*FileWatcher, error) {
	w, err := newFileWatcher(root, opts)
	if err != nil {
		return nil, err
	}
	w.start(ctx)
	return w, nil
}

// newFileWatcher registers the watches without starting the goroutine that reads
// events, which a test can then drive step by step.
func newFileWatcher(root string, opts FileWatcherOptions) (*FileWatcher, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("watch %q: %w", root, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("watch %q: %w", root, err)
	}

	backend, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, limitError(abs, err)
	}
	w := &FileWatcher{
		root:              abs,
		opts:              opts,
		fs:                backend,
		dirs:              make(map[string]struct{}),
		pending:           make(map[string]struct{}),
		changes:           make(chan struct{}, 1),
		done:              make(chan struct{}),
		queued:            make(chan struct{}, 1),
		pumped:            make(chan struct{}),
		maxQueued:         defaultMaxQueued,
		addWatch:          backend.Add,
		dependencyUpdates: make(chan dependencyUpdate),
	}

	if info.IsDir() {
		_, err = w.registerTree(abs, true)
	} else {
		// A file is watched through its directory: an editor that saves by
		// writing another file and renaming it over this one replaces the file,
		// and a watch on the old file would stay on the old one.
		w.file = abs
		w.dir = filepath.Dir(abs)
		err = w.addDir(w.dir)
	}
	if err != nil {
		_ = w.fs.Close()
		return nil, err
	}
	return w, nil
}

func (w *FileWatcher) start(ctx context.Context) {
	ctx, w.cancel = context.WithCancel(ctx)
	go w.pump()
	go w.run(ctx)
}

// backendItem is one thing the backend delivered: an event, an error, or the
// unexpected close of one of its channels (closed names it).
type backendItem struct {
	event  fsnotify.Event
	err    error
	closed string
}

// defaultMaxQueued is how many deliveries the queue keeps for run. A burst
// beyond it while run is busy is dropped, and run reconciles once instead.
const defaultMaxQueued = 4096

// pump moves what the backend delivers into the queue, in order, so the
// backend is never left waiting for run (see queue). It does not stop with the
// watcher's context: run may still be in the backend's Add or Remove then,
// which on Windows needs the events drained. It ends once the backend's
// channels are closed, which run does on its way out before waiting for it.
func (w *FileWatcher) pump() {
	defer close(w.pumped)
	events, failures := w.fs.Events, w.fs.Errors
	for events != nil || failures != nil {
		var item backendItem
		select {
		case event, ok := <-events:
			if !ok {
				events, item = nil, backendItem{closed: "event"}
			} else {
				item = backendItem{event: event}
			}
		case failure, ok := <-failures:
			if !ok {
				failures, item = nil, backendItem{closed: "error"}
			} else {
				item = backendItem{err: failure}
			}
		}
		w.enqueue(item)
	}
}

// enqueue adds item to the queue without ever blocking. Past maxQueued an
// event or error is dropped and overflowed set; the close of a channel is
// always kept, so run still learns the backend stopped.
func (w *FileWatcher) enqueue(item backendItem) {
	w.qmu.Lock()
	if item.closed == "" && len(w.queue) >= w.maxQueued {
		w.overflowed = true
	} else {
		w.queue = append(w.queue, item)
	}
	w.qmu.Unlock()
	select {
	case w.queued <- struct{}{}:
	default:
	}
}

// takeQueue returns what pump queued since the last call, and whether it
// dropped anything meanwhile.
func (w *FileWatcher) takeQueue() ([]backendItem, bool) {
	w.qmu.Lock()
	defer w.qmu.Unlock()
	items, overflowed := w.queue, w.overflowed
	w.queue, w.overflowed = nil, false
	return items, overflowed
}

// drainQueue handles what pump queued, stopping between items once ctx is
// done. Dropped deliveries are handled as the backend's own overflow: the
// registrations are brought back in line with the tree, and a change is
// signalled. Its error ends the watcher.
func (w *FileWatcher) drainQueue(ctx context.Context) error {
	items, overflowed := w.takeQueue()
	for _, item := range items {
		if ctx.Err() != nil {
			return nil
		}
		if err := w.handleItem(item); err != nil {
			return err
		}
	}
	if overflowed && ctx.Err() == nil {
		return w.handleError(fsnotify.ErrEventOverflow)
	}
	return nil
}

// handleItem handles one thing the backend delivered. Its error ends the
// watcher.
func (w *FileWatcher) handleItem(item backendItem) error {
	switch {
	case item.closed != "":
		return fmt.Errorf("watch: the %s channel was closed unexpectedly", item.closed)
	case item.err != nil:
		return w.handleError(item.err)
	default:
		return w.handle(item.event)
	}
}

// Changes returns the channel on which a change is signalled. It is closed when
// the watcher stops, after which Err says why.
func (w *FileWatcher) Changes() <-chan struct{} { return w.changes }

// Err returns why the watcher stopped, or nil while it is running and when it
// was stopped by its context or by Close. It is set before Changes is closed, so
// a reader that sees the channel close sees the reason.
func (w *FileWatcher) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

// Close stops the watcher and waits for its goroutine to end. It is safe to call
// more than once and after the context is done.
func (w *FileWatcher) Close() error {
	w.cancel()
	<-w.done
	return nil
}

// run is the watcher's goroutine, and the only one that touches w.dirs after
// start. It owns the fsnotify watcher and closes it on the way out.
func (w *FileWatcher) run(ctx context.Context) {
	var err error
	defer func() {
		if w.settle != nil {
			w.settle.Stop()
		}
		_ = w.fs.Close()
		w.mu.Lock()
		w.err = err
		w.mu.Unlock()
		w.cancel()
		<-w.pumped
		close(w.changes)
		close(w.done)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case update := <-w.dependencyUpdates:
			linksChanged := false
			switch runtime.GOOS {
			case "darwin", "dragonfly", "freebsd", "netbsd", "openbsd":
				linksChanged = w.watchDependencyLinks(update.dirs)
			}
			update.added <- w.syncDependencies(update.dirs, true) || linksChanged
		case <-w.dependencyRetry:
			if w.syncDependencies(w.dependencyPlan, false) {
				w.notify(w.root)
			}
		case <-w.dependencyLinkCheck:
			w.checkDependencyLinks()
		case <-w.queued:
			if err = w.drainQueue(ctx); err != nil {
				return
			}
		case <-w.settleC:
			if err = w.settled(); err != nil {
				return
			}
		}
	}
}

// handle turns one event into a signal, or into a change of what is watched.
// Its error ends the watcher.
func (w *FileWatcher) handle(event fsnotify.Event) error {
	name := filepath.Clean(event.Name)
	if w.dependencyEvent(name, event) {
		w.notify(name)
	}
	if event.Op == fsnotify.Chmod {
		// Selected dependencies may become readable after a permission change.
		// Some platforms also send these with every write.
		return nil
	}
	gone := event.Has(fsnotify.Remove | fsnotify.Rename)

	if _, dependency := w.dependencyDirs[name]; dependency && gone {
		if _, primary := w.dirs[name]; !primary {
			w.unregister(name)
			w.notify(name)
		}
	}

	if w.file != "" {
		// A single-file scan reads exclusions from its parent directory too.
		if name == w.file || name == filepath.Join(w.dir, cautils.IgnoreFileName) {
			w.notify(name)
		}
		if name == w.dir && gone {
			w.notify(name)
			return fmt.Errorf("watch %q: its directory was removed or renamed", w.file)
		}
		return nil
	}

	if name == w.root && gone {
		w.notify(name)
		return fmt.Errorf("watch %q: the directory was removed or renamed", w.root)
	}
	if _, watched := w.dirs[name]; watched && gone {
		// What was in it is not known any more, so this signals whatever it held.
		w.unregister(name)
		w.notify(name)
		// A directory made again under the name before its removal was seen gets
		// no event of its own from a backend that tells paths apart by name
		// (kqueue), which takes it for the one it already had. So what is there
		// now is looked at, and watched.
		return w.created(name)
	}
	if _, primary := w.dirs[filepath.Dir(name)]; !primary {
		return nil
	}
	if filepath.Base(name) == cautils.IgnoreFileName && filepath.Dir(name) == w.root {
		// The scan reads its exclusions from this file, so what it excludes may have
		// changed: a directory it now excludes is no longer watched, one it no
		// longer excludes is watched from now on, and the scan runs again. Exclude
		// is expected to read the file as it is now.
		w.dropExcluded()
		if _, err := w.registerTree(w.root, true); err != nil {
			return err
		}
		w.notify(name)
		return nil
	}
	if event.Has(fsnotify.Create) {
		return w.created(name)
	}
	if w.relevantFile(name) {
		w.notify(name)
	}
	return nil
}

// created handles a path that appeared: a file signals if it is one a scan
// loads, and a directory is, after settleDelay, watched and searched for such
// files.
func (w *FileWatcher) created(name string) error {
	info, err := os.Lstat(name)
	if err != nil || info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		// A path that is already gone again is judged by its name, and its
		// removal follows; a rescan costs little.
		if w.relevantFile(name) {
			w.notify(name)
		}
		return nil
	}
	if w.skipDir(name) {
		return nil
	}
	// Not at once: see settleDelay.
	w.pending[name] = struct{}{}
	w.armSettle()
	return nil
}

// handleError deals with a failure the backend reports. A queue overflow means
// events were lost: what is watched is reconciled with the tree and a change is
// signalled, so that a scan restores what the lost events would have said.
func (w *FileWatcher) handleError(failure error) error {
	if errors.Is(failure, fsnotify.ErrEventOverflow) {
		return w.reconcile()
	}
	if isLimit(failure) {
		return limitError(w.root, failure)
	}
	// Something may have been missed: say so, and rescan.
	w.report(fmt.Errorf("watch %q: %w", w.root, failure))
	w.notify(w.root)
	return nil
}

// reconcile brings the registrations back in line with the tree after events
// were lost, then signals. A directory that was replaced under the same name
// has lost its watch without a Remove event reaching us, which is why what the
// backend says it watches decides, and not what was recorded.
func (w *FileWatcher) reconcile() error {
	for dir := range w.dependencyDirs {
		if _, primary := w.dirs[dir]; !primary {
			_ = w.fs.Remove(dir)
		}
	}
	w.dependencyDirs = nil
	if w.file != "" {
		// The removal of the file's directory may be among what was lost, and
		// the backend drops its watch with the directory, so it is watched again
		// from a clean state, as every directory is below. If it cannot be, the
		// watch ends, as when the removal is seen.
		if err := w.rewatchDir(); err != nil {
			w.notify(w.file)
			return err
		}
	} else {
		// The lost events may include the ignore file's, so what it excludes now
		// is dropped first, as on its own event, rather than watched again below.
		w.dropExcluded()
		live := make(map[string]struct{})
		for _, path := range w.fs.WatchList() {
			live[path] = struct{}{}
		}
		for dir := range w.dirs {
			if _, ok := live[dir]; !ok {
				delete(w.dirs, dir)
			}
		}
		// A watch the backend lists may be one that no longer reports what is
		// made in it, so every registration is made again, not only the missing.
		for dir := range w.dirs {
			if err := w.refresh(dir); err != nil {
				return err
			}
		}
		if _, err := w.registerTree(w.root, true); err != nil {
			return err
		}
	}
	if w.dependencyPlan != nil {
		w.syncDependencies(w.dependencyPlan, true)
	}
	w.notify(w.root)
	return nil
}

// rewatchAttempts bounds retry when the directory is still there.
const rewatchAttempts = 5

// rewatchDir watches the single file's directory again from a clean state.
func (w *FileWatcher) rewatchDir() error {
	_ = w.fs.Remove(w.dir)
	err := w.addDirectoryWatch(w.dir)
	switch {
	case err == nil:
		return nil
	case !errors.Is(err, fs.ErrNotExist):
		return limitError(w.dir, err)
	default:
		if _, statErr := os.Stat(w.dir); errors.Is(statErr, fs.ErrNotExist) {
			return fmt.Errorf("watch %q: its directory was removed or renamed", w.file)
		}
		return fmt.Errorf("watch %q: its directory could not be watched again: %w", w.file, err)
	}
}

// kqueue can register a directory before failing with ErrNotExist when a
// child disappears during its listing. Discard that partial registration and
// retry if the directory itself is still there.
func (w *FileWatcher) addDirectoryWatch(dir string) error {
	var err error
	for range rewatchAttempts {
		if err = w.addWatch(dir); err == nil {
			return nil
		}
		_ = w.fs.Remove(dir)
		if !errors.Is(err, fs.ErrNotExist) {
			break
		}
		if _, statErr := os.Stat(dir); errors.Is(statErr, fs.ErrNotExist) {
			break
		}
	}
	return err
}

// settled registers the directories that appeared since the backend last
// settled, and reads each: it is registered before it is read, so what is made
// in it from then on is reported, and what was made before, while it was not
// watched, is found by the read and signalled. A directory that is already
// registered, as one found by a read made as it appeared can be, is registered
// again from a clean state first.
func (w *FileWatcher) settled() error {
	w.settleC = nil
	dirs := make([]string, 0, len(w.pending))
	for dir := range w.pending {
		dirs = append(dirs, dir)
		delete(w.pending, dir)
	}
	for _, dir := range dirs {
		info, err := os.Lstat(dir)
		if err != nil || info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() || w.skipDir(dir) {
			continue // gone again, or not a directory to watch
		}
		_, primary := w.dirs[dir]
		_, dependency := w.dependencyDirs[dir]
		if primary || dependency {
			if err := w.refresh(dir); err != nil {
				return err
			}
		}
		found, err := w.registerTree(dir, false)
		if err != nil {
			return err
		}
		if found {
			w.notify(dir)
		}
	}
	return nil
}

// refresh watches dir again from a clean state: whatever the backend holds for
// it is dropped, and it is added anew. A directory that is gone is forgotten,
// and one that cannot be watched is reported and forgotten. Only an OS limit is
// an error.
func (w *FileWatcher) refresh(dir string) error {
	_ = w.fs.Remove(dir) // absent is fine
	err := w.addDirectoryWatch(dir)
	switch {
	case err == nil:
		return nil
	case isLimit(err):
		return limitError(dir, err)
	case errors.Is(err, fs.ErrNotExist):
		w.unregister(dir)
		w.notify(dir) // what was in it is gone
	default:
		w.unregister(dir)
		w.report(limitError(dir, err))
	}
	return nil
}

func (w *FileWatcher) armSettle() {
	if w.settle == nil {
		w.settle = time.NewTimer(settleDelay)
	} else {
		w.settle.Reset(settleDelay)
	}
	w.settleC = w.settle.C
}

// registerTree watches dir and every directory below it that is not skipped,
// and reports whether it saw a file a scan would load. Each directory is watched
// before its entries are read. Only the root, and a failure from an OS limit,
// are errors: a subdirectory that cannot be watched or read is reported through
// OnError and left out, and one that vanished is simply gone.
func (w *FileWatcher) registerTree(dir string, isRoot bool) (found bool, err error) {
	if err := w.addDir(dir); err != nil {
		if isRoot || isLimit(err) {
			return false, err
		}
		if !errors.Is(err, fs.ErrNotExist) {
			w.report(err)
		}
		return false, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if isRoot {
			return false, fmt.Errorf("watch %q: %w", dir, err)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			w.report(fmt.Errorf("watch %q: %w", dir, err))
		}
		return false, nil
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() { // false for a link, which is not followed
			if w.skipDir(path) {
				continue
			}
			sub, err := w.registerTree(path, false)
			if err != nil {
				return false, err
			}
			found = found || sub
			continue
		}
		if w.relevantFile(path) {
			found = true
		}
	}
	return found, nil
}

// addDir watches dir, once.
func (w *FileWatcher) addDir(dir string) error {
	if _, ok := w.dirs[dir]; ok {
		return nil
	}
	if _, dependency := w.dependencyDirs[dir]; !dependency {
		if err := w.addDirectoryWatch(dir); err != nil {
			return limitError(dir, err)
		}
	}
	w.dirs[dir] = struct{}{}
	return nil
}

// unregister forgets dir and the directories below it, and drops their watches.
// A directory that was renamed keeps its watch under its old name, which would
// report its files under a path that no longer exists, so it is registered
// again under the new name when that appears.
func (w *FileWatcher) unregister(dir string) {
	prefix := dir + string(filepath.Separator)
	for watched := range w.dependencyDirs {
		if watched == dir || strings.HasPrefix(watched, prefix) {
			delete(w.dependencyDirs, watched)
			if _, primary := w.dirs[watched]; !primary {
				_ = w.fs.Remove(watched)
			}
		}
	}
	w.unregisterRootDirs(dir)
}

// Dropping an excluded scan directory preserves any render coverage it shares.
func (w *FileWatcher) unregisterRootDirs(dir string) {
	prefix := dir + string(filepath.Separator)
	for watched := range w.dirs {
		if watched == dir || strings.HasPrefix(watched, prefix) {
			delete(w.dirs, watched)
			delete(w.pending, watched)
			if _, dependency := w.dependencyDirs[watched]; !dependency {
				_ = w.fs.Remove(watched)
			}
		}
	}
	for path := range w.depFiles {
		if strings.HasPrefix(path, prefix) {
			delete(w.depFiles, path)
		}
	}
}

// dropExcluded forgets the directories that are now excluded, with what is
// below them, including those still waiting to be registered.
func (w *FileWatcher) dropExcluded() {
	for dir := range w.dirs {
		if dir != w.root && w.skipDir(dir) {
			w.unregisterRootDirs(dir)
		}
	}
	for dir := range w.pending {
		if w.excludedBelowRoot(dir) {
			delete(w.pending, dir)
		}
	}
}

// excludedBelowRoot reports whether path, or a directory between it and the
// root, is skipped.
func (w *FileWatcher) excludedBelowRoot(path string) bool {
	for dir := path; dir != w.root; {
		if w.skipDir(dir) {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
	return false
}

func (w *FileWatcher) skipDir(path string) bool {
	return filepath.Base(path) == vcsDir || (w.opts.Exclude != nil && w.opts.Exclude(path, true))
}

// relevantFile reports whether a change to path can change what a scan reads.
// It errs towards yes: a scan that was not needed is cheap, and one that was
// needed and did not happen is a stale result. A file is a manifest by the
// extension the scan loader goes by, so editors' backup, swap and temporary
// files (name~, .name.swp, name.tmp, #name#) are out already, being named with
// another extension; what is left to rule out is an Emacs lock file, which is a
// link named like the file it guards. The one manifest without an extension is a
// kustomization named Kustomization, which kustomize accepts. For rendered-input
// directory watches (AcceptDependencies), dependency files are accepted
// regardless of extension while preserving editor-file and path exclusions.
func (w *FileWatcher) relevantFile(path string) bool {
	if isEditorOrTempFile(path) {
		return false
	}
	if !cautils.IsYaml(path) && !cautils.IsJson(path) && !cautils.IsKustomizeFile(path) && !isTerraformOrHelmFile(path) && !isPatchFile(path) {
		if w.opts.AcceptDependencies == nil || !w.opts.AcceptDependencies(path) {
			return false
		}
		if !w.mayBeDependency(path) {
			return false
		}
	}
	return w.opts.Exclude == nil || !w.opts.Exclude(path, false)
}

// mayBeDependency reports whether a path without a manifest's extension can be
// a file a render reads. A dependency is a file: a directory that is watched
// reports what changes in it through its own watch, and one that isn't, .git
// or one the scan excludes, holds nothing the scan reads.
//
// A path last seen as a dependency file still counts once it is gone, or is a
// directory by the time its removal is handled: what the render read was
// removed, whatever the name means now. Without that, a removed file named like
// an excluded directory (a file "extra" with "extra/" excluded) would not
// count, nor one replaced by a directory of the same name before its removal
// was seen. A path that is gone and was never seen can't be looked at, so it
// counts unless it is skipped as a directory would be.
func (w *FileWatcher) mayBeDependency(path string) bool {
	info, err := os.Lstat(path)
	if err == nil && !info.IsDir() {
		if w.depFiles == nil {
			w.depFiles = make(map[string]struct{})
		}
		w.depFiles[path] = struct{}{}
		return true
	}
	if _, was := w.depFiles[path]; was {
		// Forgotten only once it is known to be gone or a directory: if it could
		// not be looked at (permissions, I/O), the record is kept, so its removal
		// is still recognised later.
		if err == nil || errors.Is(err, fs.ErrNotExist) {
			delete(w.depFiles, path)
		}
		return true
	}
	if err != nil {
		return !w.skipDir(path)
	}
	return false
}

func isEditorOrTempFile(path string) bool {
	base := filepath.Base(path)
	if strings.HasPrefix(base, ".#") {
		return true // Emacs lock file
	}
	if strings.HasPrefix(base, "#") && strings.HasSuffix(base, "#") {
		return true // Emacs auto-save file
	}
	if strings.HasSuffix(base, "~") {
		return true // Backup file
	}
	ext := strings.ToLower(filepath.Ext(base))
	switch ext {
	case ".swp", ".swo", ".swx", ".bak", ".tmp", ".orig":
		return true
	}
	return false
}

func isPatchFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".patch", ".diff":
		return true
	default:
		return false
	}
}

// isTerraformOrHelmFile reports whether a directory scan reads path besides
// the manifests: a Terraform configuration (.tf), the variable values it is
// evaluated with (terraform.tfvars and *.auto.tfvars; any .tfvars counts, to
// err towards yes), or a Helm template helper (_helpers.tpl and the like)
// that the chart's templates include.
func isTerraformOrHelmFile(path string) bool {
	if cautils.IsTerraformFile(path) {
		return true
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".tfvars", ".tpl":
		return true
	}
	return false
}

// notify signals a change without ever waiting for the reader.
func (w *FileWatcher) notify(path string) {
	if w.signalHook != nil {
		w.signalHook(path)
	}
	select {
	case w.changes <- struct{}{}:
	default: // one is already waiting: this change is part of it
	}
}

func (w *FileWatcher) report(err error) {
	if w.opts.OnError != nil {
		w.opts.OnError(err)
	}
}

// isLimit reports whether err says an OS limit on watches or open files was hit.
func isLimit(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE)
}

// limitError names the path and, for a resource limit, what can be done about it.
func limitError(path string, err error) error {
	switch {
	case errors.Is(err, syscall.ENOSPC):
		return fmt.Errorf("watch %q: the limit on file watches was reached (on Linux, raise fs.inotify.max_user_watches): %w", path, err)
	case errors.Is(err, syscall.EMFILE), errors.Is(err, syscall.ENFILE):
		return fmt.Errorf("watch %q: too many open files or watchers (on Linux, raise fs.inotify.max_user_instances; on macOS and the BSDs every watched file needs a descriptor, so raise ulimit -n): %w", path, err)
	}
	return fmt.Errorf("watch %q: %w", path, err)
}
