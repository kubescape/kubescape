package watch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// waitTimeout only bounds how long a broken test waits; nothing passes by it.
const waitTimeout = 10 * time.Second

// recorder collects the path behind every signal a watcher makes, before the
// signals are coalesced. A test synchronizes on what the watcher has seen, and
// not on time.
type recorder struct {
	mu    sync.Mutex
	paths []string
	ping  chan struct{}
}

func newRecorder() *recorder { return &recorder{ping: make(chan struct{}, 1)} }

func (r *recorder) record(path string) {
	r.mu.Lock()
	r.paths = append(r.paths, path)
	r.mu.Unlock()
	select {
	case r.ping <- struct{}{}:
	default:
	}
}

func (r *recorder) has(match func(string) bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.paths {
		if match(p) {
			return true
		}
	}
	return false
}

func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.paths...)
}

// waitFor waits until a signal for a path that match accepts has been made.
func (r *recorder) waitFor(t *testing.T, what string, match func(string) bool) {
	t.Helper()
	deadline := time.After(waitTimeout)
	for !r.has(match) {
		select {
		case <-r.ping:
		case <-deadline:
			t.Fatalf("no signal for %s; signals so far: %v", what, r.all())
		}
	}
}

// mark returns a point in the signals made so far, for waitForAfter.
func (r *recorder) mark() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.paths)
}

// waitForAfter waits for a signal made after mark for a path match accepts, so
// that one an earlier step made for the same path does not stand for this one.
func (r *recorder) waitForAfter(t *testing.T, mark int, what string, match func(string) bool) {
	t.Helper()
	deadline := time.After(waitTimeout)
	for {
		r.mu.Lock()
		later := append([]string(nil), r.paths[mark:]...)
		r.mu.Unlock()
		for _, p := range later {
			if match(p) {
				return
			}
		}
		select {
		case <-r.ping:
		case <-deadline:
			t.Fatalf("no signal for %s after the change; signals since: %v", what, later)
		}
	}
}

// hasAfter reports whether a signal for a path match accepts was made after mark.
func (r *recorder) hasAfter(mark int, match func(string) bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.paths[mark:] {
		if match(p) {
			return true
		}
	}
	return false
}

// retryUntilSignalled makes the change again until a signal follows it. It is
// for a change made a moment after another to a file that did not exist before:
// kqueue watches such a file itself only just after it appears, and a change in
// that instant is seen only by the scan the first change already asked for. A
// change made once the file is watched is always seen, which is what is shown.
func (r *recorder) retryUntilSignalled(t *testing.T, what string, change func(attempt int), match func(string) bool) {
	t.Helper()
	deadline := time.After(waitTimeout)
	for attempt := 1; ; attempt++ {
		mark := r.mark()
		change(attempt)
		retry := time.After(200 * time.Millisecond)
	wait:
		for !r.hasAfter(mark, match) {
			select {
			case <-r.ping:
			case <-retry:
				break wait
			case <-deadline:
				t.Fatalf("no signal for %s after %d attempts; signals so far: %v", what, attempt, r.all())
			}
		}
		if r.hasAfter(mark, match) {
			return
		}
	}
}

func is(path string) func(string) bool { return func(got string) bool { return got == path } }

func under(dir string) func(string) bool {
	return func(got string) bool { return got == dir || strings.HasPrefix(got, dir+string(filepath.Separator)) }
}

// startWatcher watches root with a recorder attached, until the test ends.
func startWatcher(t *testing.T, root string, opts FileWatcherOptions) (*FileWatcher, *recorder) {
	t.Helper()
	w, err := newFileWatcher(root, opts)
	require.NoError(t, err)
	rec := newRecorder()
	w.signalHook = rec.record
	ctx, cancel := context.WithCancel(context.Background())
	w.start(ctx)
	t.Cleanup(func() {
		cancel()
		<-w.done
	})
	return w, rec
}

var sentinels atomic.Int64

// settle makes a manifest in dir that no test rule ignores and waits for its
// signal. Events are processed in the order the OS made them, so once this has
// signalled, anything made before it has been judged: a signal for it would
// already be recorded.
func settle(t *testing.T, rec *recorder, dir string) {
	t.Helper()
	path := filepath.Join(dir, fmt.Sprintf("zz-sentinel-%d.yaml", sentinels.Add(1)))
	write(t, path, "kind: Sentinel\n")
	rec.waitFor(t, "the sentinel "+path, is(path))
}

func write(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func TestFileWatcherSignalsForChangesToManifests(t *testing.T) {
	t.Parallel()

	t.Run("a file that is modified", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		file := filepath.Join(root, "app.yaml")
		write(t, file, "kind: Pod\n")
		_, rec := startWatcher(t, root, FileWatcherOptions{})

		write(t, file, "kind: Pod\nmetadata:\n  name: changed\n")
		rec.waitFor(t, file, is(file))
	})

	t.Run("a new yaml, yml and json file, whatever the case of the extension", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		_, rec := startWatcher(t, root, FileWatcherOptions{})

		for _, name := range []string{"a.yaml", "b.yml", "c.json", "D.YAML"} {
			path := filepath.Join(root, name)
			write(t, path, "{}\n")
			rec.waitFor(t, path, is(path))
		}
	})

	t.Run("a file that is deleted", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		file := filepath.Join(root, "gone.yaml")
		write(t, file, "kind: Pod\n")
		_, rec := startWatcher(t, root, FileWatcherOptions{})

		require.NoError(t, os.Remove(file))
		rec.waitFor(t, file, is(file))
	})

	t.Run("a file that is renamed, to another manifest name or away from one", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		from, to := filepath.Join(root, "from.yaml"), filepath.Join(root, "to.yaml")
		away, awayTo := filepath.Join(root, "away.yaml"), filepath.Join(root, "away.yaml.old")
		// Both exist when the watch starts, so both are watched from the start:
		// kqueue watches a file made later only just after it is made.
		write(t, from, "kind: Pod\n")
		write(t, away, "kind: Pod\n")
		_, rec := startWatcher(t, root, FileWatcherOptions{})

		// The kind and order of events differ between platforms: the rename is
		// seen at either name, and what matters is that the scan is asked for.
		require.NoError(t, os.Rename(from, to))
		rec.waitFor(t, "the rename", func(p string) bool { return p == from || p == to })

		// Away from a manifest name, to one a scan does not load: the old name is
		// what tells that a manifest is gone.
		require.NoError(t, os.Rename(away, awayTo))
		rec.waitFor(t, "the rename away from a manifest name", is(away))
	})

	t.Run("a file in a nested directory", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		file := filepath.Join(root, "a", "b", "c", "deep.yaml")
		write(t, file, "kind: Pod\n")
		_, rec := startWatcher(t, root, FileWatcherOptions{})

		write(t, file, "kind: Pod\nmetadata:\n  name: deep\n")
		rec.waitFor(t, file, is(file))
	})

	t.Run("Terraform and Helm files, in nested directories too", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		existing := []string{
			filepath.Join(root, "main.tf"),
			filepath.Join(root, "modules", "net", "main.tf"),
			filepath.Join(root, "envs", "prod", "prod.auto.tfvars"),
			filepath.Join(root, "chart", "templates", "_helpers.tpl"),
		}
		for _, path := range existing {
			write(t, path, "# v1")
		}
		_, rec := startWatcher(t, root, FileWatcherOptions{})

		for _, path := range existing {
			write(t, path, "# v2")
			rec.waitFor(t, path, is(path))
		}
		// a nested directory made after the watch started
		made := filepath.Join(root, "modules", "dns", "main.tf")
		rec.retryUntilSignalled(t, made, func(attempt int) { write(t, made, fmt.Sprintf("# %d", attempt)) }, is(made))
	})
}

func TestFileWatcherWatchesNewDirectories(t *testing.T) {
	t.Parallel()

	t.Run("a manifest created in a directory that did not exist", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		_, rec := startWatcher(t, root, FileWatcherOptions{})

		dir := filepath.Join(root, "new", "nested")
		first := filepath.Join(dir, "first.yaml")
		write(t, first, "kind: Pod\n") // the directories and the file, at once
		rec.waitFor(t, "the first manifest of the new directory", under(filepath.Join(root, "new")))

		// The directory stays watched: a later manifest in it is reported under
		// its own name, which only a registration made when it appeared allows.
		second := filepath.Join(dir, "second.yaml")
		write(t, second, "kind: Pod\n")
		rec.waitFor(t, second, is(second))
		deeper := filepath.Join(dir, "deeper", "third.yaml")
		write(t, deeper, "kind: Pod\n")
		rec.waitFor(t, deeper, under(filepath.Join(dir, "deeper")))
		// And the directory made under it is watched too, not only searched.
		fourth := filepath.Join(dir, "deeper", "fourth.yaml")
		mark := rec.mark()
		write(t, fourth, "kind: Pod\n")
		rec.waitForAfter(t, mark, fourth, is(fourth))
	})

	t.Run("a directory that is deleted", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		sub := filepath.Join(root, "sub")
		write(t, filepath.Join(sub, "x.yaml"), "kind: Pod\n")
		_, rec := startWatcher(t, root, FileWatcherOptions{})

		require.NoError(t, os.RemoveAll(sub))
		rec.waitFor(t, "the deleted directory", under(sub))

		// The watcher goes on, and a directory of the same name is watched anew.
		// A signal for the directory itself only says it was seen to be there;
		// that it is watched shows in a file made in it being reported by name.
		// Each attempt is a new file: those made before the watch was in place
		// are found by the search of the directory instead, and signal for it.
		write(t, filepath.Join(sub, "again.yaml"), "kind: Pod\n")
		rec.retryUntilSignalled(t, "a file made in the directory made again", func(attempt int) {
			write(t, filepath.Join(sub, fmt.Sprintf("next-%d.yaml", attempt)), "kind: Pod\n")
		}, func(p string) bool { return strings.HasPrefix(filepath.Base(p), "next-") })
	})

	t.Run("a directory that is renamed", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		before, after := filepath.Join(root, "before"), filepath.Join(root, "after")
		write(t, filepath.Join(before, "x.yaml"), "kind: Pod\n")
		_, rec := startWatcher(t, root, FileWatcherOptions{})

		require.NoError(t, os.Rename(before, after))
		rec.waitFor(t, "the renamed directory", under(after))

		// Watched under its new name, and not under the old one.
		later := filepath.Join(after, "later.yaml")
		write(t, later, "kind: Pod\n")
		rec.waitFor(t, later, is(later))
	})
}

func TestFileWatcherIgnoresWhatAScanDoesNotLoad(t *testing.T) {
	t.Parallel()

	t.Run("other extensions and editors' temporary files", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		_, rec := startWatcher(t, root, FileWatcherOptions{})

		ignored := []string{
			"notes.txt", "README.md", "script.sh",
			".app.yaml.swp", ".app.yaml.swx", // vim swap files
			"app.yaml~",            // backup
			"#app.yaml#",           // Emacs auto-save
			".#app.yaml",           // Emacs lock
			"app.yaml.tmp",         // temporary file
			"app.yaml.bak",         // backup
			"app.yaml___jb_tmp___", // JetBrains safe write
			"4913",                 // vim's check that a directory is writable
		}
		for _, name := range ignored {
			write(t, filepath.Join(root, name), "x")
		}
		settle(t, rec, root)

		for _, path := range rec.all() {
			assert.NotContains(t, ignored, filepath.Base(path), "a file a scan does not load signalled a change")
		}
	})

	t.Run("version control metadata", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		write(t, filepath.Join(root, ".git", "hooks", "pre.yaml"), "x")
		_, rec := startWatcher(t, root, FileWatcherOptions{})

		write(t, filepath.Join(root, ".git", "hooks", "pre.yaml"), "y")
		write(t, filepath.Join(root, ".git", "new.yaml"), "y")
		settle(t, rec, root)
		assert.False(t, rec.has(under(filepath.Join(root, ".git"))), "the .git directory was watched")
	})

	t.Run("a directory link, which is not followed, and cannot loop", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		if err := os.Symlink(root, filepath.Join(root, "loop")); err != nil {
			t.Skipf("cannot make symbolic links here: %v", err)
		}
		_, rec := startWatcher(t, root, FileWatcherOptions{}) // returns: no registration loops

		file := filepath.Join(root, "real.yaml")
		write(t, file, "kind: Pod\n")
		rec.waitFor(t, file, is(file))
		assert.False(t, rec.has(under(filepath.Join(root, "loop"))), "a path through the link signalled a change")
	})
}

func TestFileWatcherExclusions(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	exclude := func(path string, isDir bool) bool {
		base := filepath.Base(path)
		return (isDir && strings.HasPrefix(base, "vendor")) || (!isDir && base == "skip.yaml")
	}
	write(t, filepath.Join(root, "vendor", "pre.yaml"), "x") // there when the watch starts
	_, rec := startWatcher(t, root, FileWatcherOptions{Exclude: exclude})

	write(t, filepath.Join(root, "vendor", "pre.yaml"), "y")
	write(t, filepath.Join(root, "vendor", "new.yaml"), "y")
	write(t, filepath.Join(root, "vendor-late", "late.yaml"), "y") // made after it starts
	write(t, filepath.Join(root, "vendor-late", "more.yaml"), "y")
	write(t, filepath.Join(root, "skip.yaml"), "y")
	settle(t, rec, root)

	assert.False(t, rec.has(under(filepath.Join(root, "vendor"))), "an excluded directory was watched")
	assert.False(t, rec.has(under(filepath.Join(root, "vendor-late"))), "an excluded directory made later was watched")
	assert.False(t, rec.has(is(filepath.Join(root, "skip.yaml"))), "an excluded file signalled a change")
}

func TestFileWatcherOnASingleFile(t *testing.T) {
	t.Parallel()

	t.Run("signals for the file and not for its siblings", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		file := filepath.Join(dir, "app.yaml")
		write(t, file, "kind: Pod\n")
		w, rec := startWatcher(t, file, FileWatcherOptions{})
		assert.Equal(t, file, w.file)

		other := filepath.Join(dir, "other.yaml")
		write(t, other, "kind: Pod\n")
		write(t, filepath.Join(dir, "sub", "deep.yaml"), "kind: Pod\n")
		write(t, file, "kind: Pod\nmetadata:\n  name: changed\n")
		rec.waitFor(t, file, is(file))
		assert.False(t, rec.has(is(other)), "a sibling signalled a change")
		assert.False(t, rec.has(under(filepath.Join(dir, "sub"))), "a subdirectory was watched")
	})

	t.Run("a file replaced by writing another and renaming it over it", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		file := filepath.Join(dir, "app.yaml")
		write(t, file, "kind: Pod\n")
		_, rec := startWatcher(t, file, FileWatcherOptions{})

		replace := func(name string) {
			tmp := filepath.Join(dir, ".app.yaml."+name)
			write(t, tmp, "kind: Pod\nmetadata:\n  name: "+name+"\n")
			require.NoError(t, os.Rename(tmp, file))
		}
		replace("first")
		rec.waitFor(t, file, is(file))
		// kqueue is still putting a watch on the replacement when the first signal
		// is made, and a second replacement in that instant is lost to it. People
		// and tools save tens of milliseconds apart at the least (none was lost in
		// 1500 tries at 20 ms), so the next one is made after that, not at once.
		<-time.After(50 * time.Millisecond)

		// Later replacements are seen as well: a watch on the file itself would
		// have stayed with the first one's inode.
		rec.retryUntilSignalled(t, "a later replacement", func(attempt int) { replace(fmt.Sprintf("again-%d", attempt)) }, is(file))
	})

	t.Run("a file renamed away, and made again", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		file := filepath.Join(dir, "app.yaml")
		write(t, file, "kind: Pod\n")
		_, rec := startWatcher(t, file, FileWatcherOptions{})

		require.NoError(t, os.Rename(file, file+".moved"))
		rec.waitFor(t, "the file renamed away", is(file))

		mark := rec.mark()
		write(t, file, "kind: Pod\n") // it is back, under its name
		rec.waitForAfter(t, mark, "the file made again", is(file))
	})

	t.Run("a file that is deleted", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		file := filepath.Join(dir, "app.yaml")
		write(t, file, "kind: Pod\n")
		_, rec := startWatcher(t, file, FileWatcherOptions{})

		require.NoError(t, os.Remove(file))
		rec.waitFor(t, "the deletion", is(file))
	})

	t.Run("an extension that is not a manifest's is accepted for a file that was asked for", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		file := filepath.Join(dir, "deploy.txt")
		write(t, file, "kind: Pod\n")
		_, rec := startWatcher(t, file, FileWatcherOptions{})

		write(t, file, "kind: Pod\nmetadata:\n  name: x\n")
		rec.waitFor(t, file, is(file))
	})
}

func TestFileWatcherRelevantFile(t *testing.T) {
	t.Parallel()
	w := &FileWatcher{opts: FileWatcherOptions{Exclude: func(path string, isDir bool) bool {
		return !isDir && filepath.Base(path) == "excluded.yaml"
	}}}
	tests := []struct {
		name string
		want bool
	}{
		{"deploy.yaml", true}, {"deploy.yml", true}, {"deploy.json", true},
		{"DEPLOY.YAML", true}, {"Deploy.Yml", true}, {"a.b.yaml", true},
		{".hidden.yaml", true}, // a hidden manifest is still one a scan loads
		{"kustomization.yaml", true},
		// Terraform and Helm files a directory scan renders
		{"main.tf", true}, {"terraform.tfvars", true}, {"prod.auto.tfvars", true},
		{"terraform.tfvars.json", true}, {"_helpers.tpl", true},
		{"main.tf.bak", false}, {".terraform.lock.hcl", false},
		{"notes.txt", false}, {"deploy", false}, {"deploy.yaml.bak", false},
		{".deploy.yaml.swp", false}, {"deploy.yaml~", false}, {"#deploy.yaml#", false},
		{".#deploy.yaml", false}, // an Emacs lock file, named like the file it guards
		{"excluded.yaml", false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, w.relevantFile(filepath.Join("/tmp", "x", tt.name)), tt.name)
	}
}

func TestFileWatcherBurstsLeaveOneSignalAndNeverBlock(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	w, err := newFileWatcher(root, FileWatcherOptions{})
	require.NoError(t, err)
	defer w.fs.Close()

	// Nobody reads Changes, as when a scan is running. The watcher must not wait
	// for it, however many changes come.
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for i := 0; i < 1000; i++ {
			w.notify(filepath.Join(root, "x.yaml"))
		}
	}()
	select {
	case <-finished:
	case <-time.After(waitTimeout):
		t.Fatal("notify blocked on a reader that was not reading")
	}
	assert.Len(t, w.changes, 1, "a burst leaves exactly one signal")
	<-w.changes
	assert.Empty(t, w.changes)
}

func TestFileWatcherEventOverflowSignalsAndReconciles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	w, err := newFileWatcher(root, FileWatcherOptions{}) // no goroutine reads events: the test drives it
	require.NoError(t, err)
	defer w.fs.Close()

	// What was made while events were lost: a tree no event was seen for.
	write(t, filepath.Join(root, "late", "a.yaml"), "x")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "late", "inner"), 0o750))
	// A registration that no longer matches what the backend watches.
	w.dirs[filepath.Join(root, "stale")] = struct{}{}
	require.Empty(t, w.changes)

	require.NoError(t, w.handleError(fsnotify.ErrEventOverflow))

	assert.Len(t, w.changes, 1, "an overflow signals a change: events were lost")
	assert.Contains(t, w.dirs, filepath.Join(root, "late"))
	assert.Contains(t, w.dirs, filepath.Join(root, "late", "inner"), "a directory made while events were lost is watched")
	assert.NotContains(t, w.dirs, filepath.Join(root, "stale"), "a registration the backend does not have is dropped")

	// And it is not a loop: another overflow reconciles once more and signals once.
	<-w.changes
	require.NoError(t, w.handleError(fsnotify.ErrEventOverflow))
	assert.Len(t, w.changes, 1)
}

func TestFileWatcherOtherBackendErrors(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	var reported []error
	w, err := newFileWatcher(root, FileWatcherOptions{OnError: func(err error) { reported = append(reported, err) }})
	require.NoError(t, err)
	defer w.fs.Close()

	// An error that leaves the watch working is reported, and asks for a scan
	// in case something was missed.
	require.NoError(t, w.handleError(errors.New("read failed")))
	require.Len(t, reported, 1)
	assert.Len(t, w.changes, 1)

	// One from a resource limit does not: nothing can be relied on after it.
	err = w.handleError(syscall.ENOSPC)
	require.Error(t, err)
	assert.ErrorIs(t, err, syscall.ENOSPC)
	assert.Contains(t, err.Error(), "fs.inotify.max_user_watches")
}

func TestLimitErrorsSayWhatToDo(t *testing.T) {
	t.Parallel()
	assert.True(t, isLimit(syscall.ENOSPC))
	assert.True(t, isLimit(fmt.Errorf("wrapped: %w", syscall.EMFILE)))
	assert.True(t, isLimit(syscall.ENFILE))
	assert.False(t, isLimit(syscall.EACCES))
	assert.False(t, isLimit(os.ErrNotExist))

	assert.Contains(t, limitError("/x", syscall.ENOSPC).Error(), "fs.inotify.max_user_watches")
	assert.Contains(t, limitError("/x", syscall.EMFILE).Error(), "ulimit -n")
	assert.ErrorIs(t, limitError("/x", syscall.EMFILE), syscall.EMFILE)
	assert.NotContains(t, limitError("/x", syscall.EACCES).Error(), "limit")
}

func TestNewFileWatcherFailsForWhatItCannotWatch(t *testing.T) {
	t.Parallel()
	w, err := NewFileWatcher(context.Background(), filepath.Join(t.TempDir(), "does-not-exist"), FileWatcherOptions{})
	require.Error(t, err)
	assert.Nil(t, w, "a watcher was returned for a path that cannot be watched")
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestFileWatcherLifecycle(t *testing.T) {
	t.Parallel()

	// closed waits for the channel to be closed, and returns what it saw.
	closed := func(t *testing.T, w *FileWatcher) (signals int) {
		t.Helper()
		deadline := time.After(waitTimeout)
		for {
			select {
			case _, open := <-w.Changes():
				if !open {
					return signals
				}
				signals++
			case <-deadline:
				t.Fatal("the changes channel was not closed")
			}
		}
	}

	t.Run("cancelling the context stops it", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		w, err := NewFileWatcher(ctx, t.TempDir(), FileWatcherOptions{})
		require.NoError(t, err)
		assert.NoError(t, w.Err(), "a running watcher has no error")

		cancel()
		closed(t, w)
		<-w.done // the goroutine has ended
		assert.NoError(t, w.Err(), "stopping it is not an error")
		assert.NoError(t, w.Close(), "Close after the context is done")
	})

	t.Run("Close stops it, and can be called again", func(t *testing.T) {
		t.Parallel()
		w, err := NewFileWatcher(context.Background(), t.TempDir(), FileWatcherOptions{})
		require.NoError(t, err)

		require.NoError(t, w.Close())
		closed(t, w)
		assert.NoError(t, w.Close())
		assert.NoError(t, w.Err())
	})

	t.Run("a directory that is removed ends it with an error, after the last signal", func(t *testing.T) {
		t.Parallel()
		root := filepath.Join(t.TempDir(), "watched")
		require.NoError(t, os.Mkdir(root, 0o750))
		w, err := NewFileWatcher(context.Background(), root, FileWatcherOptions{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = w.Close() })

		require.NoError(t, os.RemoveAll(root))
		assert.GreaterOrEqual(t, closed(t, w), 1, "the removal was not signalled before the channel closed")
		require.Error(t, w.Err())
		assert.Contains(t, w.Err().Error(), "removed or renamed")
	})

	t.Run("the directory of a watched file that is removed ends it with an error", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join(t.TempDir(), "parent")
		file := filepath.Join(dir, "app.yaml")
		write(t, file, "kind: Pod\n")
		w, err := NewFileWatcher(context.Background(), file, FileWatcherOptions{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = w.Close() })

		require.NoError(t, os.RemoveAll(dir))
		closed(t, w)
		require.Error(t, w.Err())
	})
}

// A directory removed and made again before the removal is seen is watched
// again. A backend that tells paths apart by name (kqueue) sends the removal and
// nothing for the new directory, so without a look at what is there it would be
// left unwatched for good.
func TestFileWatcherWatchesADirectoryMadeAgainUnderTheSameName(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	write(t, filepath.Join(sub, "old.yaml"), "kind: Pod\n")
	w, err := newFileWatcher(root, FileWatcherOptions{}) // the test drives the events
	require.NoError(t, err)
	defer w.fs.Close()
	require.Contains(t, w.dirs, sub)

	require.NoError(t, os.RemoveAll(sub))
	write(t, filepath.Join(sub, "new", "inner.yaml"), "kind: Pod\n") // made again before anything was handled

	require.NoError(t, w.handle(fsnotify.Event{Name: sub, Op: fsnotify.Remove}))
	assert.Len(t, w.changes, 1, "the removal is signalled")
	assert.NotContains(t, w.dirs, sub, "the old registration is dropped")
	assert.Contains(t, w.pending, sub, "the directory that is there now is to be registered")

	require.NoError(t, w.settled())
	assert.Contains(t, w.dirs, sub, "a directory made again under its name is not watched")
	assert.Contains(t, w.dirs, filepath.Join(sub, "new"), "nor are the directories made in it")
	assert.Empty(t, w.pending)
}

// A directory that appears is not registered at the moment its event is handled,
// but once the backend has settled (see settleDelay), and it is then read, so
// that what was made in it meanwhile is found and signalled.
func TestFileWatcherRegistersANewDirectoryOnceItHasSettled(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	w, err := newFileWatcher(root, FileWatcherOptions{})
	require.NoError(t, err)
	defer w.fs.Close()

	dir := filepath.Join(root, "new")
	write(t, filepath.Join(dir, "inner", "made-meanwhile.yaml"), "kind: Pod\n")
	require.NoError(t, w.handle(fsnotify.Event{Name: dir, Op: fsnotify.Create}))

	assert.NotContains(t, w.dirs, dir, "registered at the moment of the event, which is what settleDelay is for")
	assert.Contains(t, w.pending, dir)
	assert.NotNil(t, w.settleC, "the settle timer is not running")
	assert.Empty(t, w.changes)

	require.NoError(t, w.settled())

	assert.Contains(t, w.dirs, dir)
	assert.Contains(t, w.dirs, filepath.Join(dir, "inner"), "a directory made in it is registered as well")
	assert.Empty(t, w.pending)
	assert.Len(t, w.changes, 1, "what was made while it was not watched is signalled")
}

// A registration that the backend has lost or degraded, and that it still lists
// or not, is made good: a directory that appears and is already registered is
// registered again from a clean state.
func TestFileWatcherMakesAGoodRegistrationOfADirectoryTheBackendLost(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dir := filepath.Join(root, "sub")
	write(t, filepath.Join(dir, "a.yaml"), "kind: Pod\n")
	w, err := newFileWatcher(root, FileWatcherOptions{})
	require.NoError(t, err)
	defer w.fs.Close()
	require.Contains(t, w.dirs, dir)

	// The backend no longer watches it, while the watcher believes it does.
	require.NoError(t, w.fs.Remove(dir))
	require.NotContains(t, w.fs.WatchList(), dir)
	w.pending[dir] = struct{}{}

	require.NoError(t, w.settled())

	assert.Contains(t, w.fs.WatchList(), dir, "the directory was not watched again")
	assert.Contains(t, w.dirs, dir)
}

// A directory that is gone again by the time it has settled is not an error and
// is not watched, and a path that turned into a file is left alone.
func TestFileWatcherSettlingSkipsWhatIsNoLongerADirectory(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	w, err := newFileWatcher(root, FileWatcherOptions{})
	require.NoError(t, err)
	defer w.fs.Close()

	gone, file := filepath.Join(root, "gone"), filepath.Join(root, "now-a-file")
	write(t, file, "kind: Pod\n")
	w.pending[gone] = struct{}{}
	w.pending[file] = struct{}{}

	require.NoError(t, w.settled())
	assert.NotContains(t, w.dirs, gone)
	assert.NotContains(t, w.dirs, file)
	assert.Empty(t, w.changes)
}

// After an overflow every registration is made again, not only the ones the
// backend no longer lists: one it lists can have stopped reporting.
func TestFileWatcherOverflowRefreshesEveryRegistration(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dir := filepath.Join(root, "sub")
	write(t, filepath.Join(dir, "a.yaml"), "kind: Pod\n")
	w, err := newFileWatcher(root, FileWatcherOptions{})
	require.NoError(t, err)
	defer w.fs.Close()

	require.NoError(t, w.fs.Remove(dir)) // lost to the backend, still in the watcher's records
	w.dirs[dir] = struct{}{}

	require.NoError(t, w.handleError(fsnotify.ErrEventOverflow))

	assert.Contains(t, w.fs.WatchList(), dir)
	assert.Contains(t, w.dirs, dir)
}

// Err says why once Changes is closed, with no window in which it does not.
func TestFileWatcherErrIsSetBeforeChangesCloses(t *testing.T) {
	t.Parallel()
	for i := 0; i < 20; i++ {
		root := filepath.Join(t.TempDir(), "watched")
		require.NoError(t, os.Mkdir(root, 0o750))
		w, err := NewFileWatcher(context.Background(), root, FileWatcherOptions{})
		require.NoError(t, err)

		require.NoError(t, os.Remove(root))
		deadline := time.After(waitTimeout)
	closing:
		for {
			select {
			case _, open := <-w.Changes():
				if !open {
					break closing
				}
			case <-deadline:
				t.Fatal("the changes channel was not closed")
			}
		}
		require.Error(t, w.Err(), "the channel closed before the reason was set")
		_ = w.Close()
	}
}
