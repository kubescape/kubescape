package watch

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
// extension (.yaml, .yml, .json), less editors' lock files. For a single file,
// that file signals whatever its extension, and its siblings do not.
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

	pending map[string]struct{} // directories that appeared, to be registered once settleDelay has passed
	settle  *time.Timer
	settleC <-chan time.Time // nil unless the timer is running

	cancel context.CancelFunc
	done   chan struct{} // closed once the goroutine has exited

	mu  sync.Mutex
	err error // why it ended, if not asked to; set before changes is closed

	// signalHook, when set by a test, is called with the path behind each signal
	// before signals are coalesced.
	signalHook func(path string)
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
		root:    abs,
		opts:    opts,
		fs:      backend,
		dirs:    make(map[string]struct{}),
		pending: make(map[string]struct{}),
		changes: make(chan struct{}, 1),
		done:    make(chan struct{}),
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
		_ = backend.Close()
		return nil, err
	}
	return w, nil
}

func (w *FileWatcher) start(ctx context.Context) {
	ctx, w.cancel = context.WithCancel(ctx)
	go w.run(ctx)
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
		close(w.changes)
		close(w.done)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-w.fs.Events:
			if !ok {
				err = errors.New("watch: the event channel was closed unexpectedly")
				return
			}
			if err = w.handle(event); err != nil {
				return
			}
		case failure, ok := <-w.fs.Errors:
			if !ok {
				err = errors.New("watch: the error channel was closed unexpectedly")
				return
			}
			if err = w.handleError(failure); err != nil {
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
	if event.Op == fsnotify.Chmod {
		// A permission change is not a change to what a scan reads, and some
		// platforms send one with every write.
		return nil
	}
	gone := event.Has(fsnotify.Remove | fsnotify.Rename)

	if w.file != "" {
		if name == w.file {
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
	if w.file == "" {
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
	w.notify(w.root)
	return nil
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
		if _, registered := w.dirs[dir]; registered {
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
	err := w.fs.Add(dir)
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
	if err := w.fs.Add(dir); err != nil {
		return limitError(dir, err)
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
	for watched := range w.dirs {
		if watched == dir || strings.HasPrefix(watched, prefix) {
			delete(w.dirs, watched)
			delete(w.pending, watched)
			// Already gone from the backend when the directory was removed.
			_ = w.fs.Remove(watched)
		}
	}
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
// link named like the file it guards.
func (w *FileWatcher) relevantFile(path string) bool {
	if strings.HasPrefix(filepath.Base(path), ".#") {
		return false
	}
	if !cautils.IsYaml(path) && !cautils.IsJson(path) {
		return false
	}
	return w.opts.Exclude == nil || !w.opts.Exclude(path, false)
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
