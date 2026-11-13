package watch

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// integration wires a FileWatcher to a Scheduler the way a caller does: the
// watcher first, so nothing is missed while the first scan runs, and both on one
// context.
type integration struct {
	t       *testing.T
	root    string
	cancel  context.CancelFunc
	watcher *FileWatcher
	result  chan error

	scanned  chan string // what each scan read, in order
	gate     chan struct{}
	inFlight atomic.Int32
	overlaps atomic.Int32
}

// scanOf is what a scan of root reads here: the manifest and how many there are.
func scanOf(root string) (string, error) {
	content, err := os.ReadFile(filepath.Join(root, "app.yaml"))
	if err != nil {
		return "", err
	}
	count := 0
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".yaml") {
			count++
		}
		return err
	})
	return fmt.Sprintf("%s|%d", strings.TrimSpace(string(content)), count), err
}

func startIntegration(t *testing.T, gated bool) *integration {
	t.Helper()
	root := t.TempDir()
	write(t, filepath.Join(root, "app.yaml"), "v0")

	i := &integration{t: t, root: root, scanned: make(chan string, 256), result: make(chan error, 1)}
	if gated {
		i.gate = make(chan struct{})
	}
	ctx, cancel := context.WithCancel(context.Background())
	i.cancel = cancel
	t.Cleanup(cancel)

	w, err := NewFileWatcher(ctx, root, FileWatcherOptions{})
	require.NoError(t, err)
	i.watcher = w

	scan := func(ctx context.Context) error {
		if i.inFlight.Add(1) > 1 {
			i.overlaps.Add(1)
		}
		defer i.inFlight.Add(-1)
		got, err := scanOf(root)
		if err != nil {
			return err
		}
		i.scanned <- got
		if i.gate != nil {
			select {
			case <-i.gate:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	s := NewScheduler(w.Changes(), scan, SchedulerOptions{Debounce: 20 * time.Millisecond})
	go func() { i.result <- s.Run(ctx) }()
	return i
}

// waitScanned waits for a scan that read what want says, and returns how many
// scans it took to see it.
func (i *integration) waitScanned(want string) {
	i.t.Helper()
	deadline := time.After(waitTimeout)
	for {
		select {
		case got := <-i.scanned:
			if got == want {
				return
			}
		case <-deadline:
			i.t.Fatalf("no scan read %q", want)
		}
	}
}

func TestWatcherDrivesTheSchedulerToTheFinalState(t *testing.T) {
	t.Parallel()
	i := startIntegration(t, false)
	app := filepath.Join(i.root, "app.yaml")

	i.waitScanned("v0|1") // the initial scan, without any change

	// A burst of saves: however many scans it makes, the last one reads the end.
	for n := 1; n <= 25; n++ {
		write(t, app, fmt.Sprintf("v%d", n))
	}
	i.waitScanned("v25|1")

	// A manifest in a directory that did not exist.
	write(t, filepath.Join(i.root, "new", "nested", "extra.yaml"), "kind: Pod\n")
	i.waitScanned("v25|2")

	// And Ctrl+C: everything ends, and nothing is left running.
	i.cancel()
	select {
	case err := <-i.result:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(waitTimeout):
		t.Fatal("the scheduler did not stop")
	}
	select {
	case <-i.watcher.done:
	case <-time.After(waitTimeout):
		t.Fatal("the watcher did not stop")
	}
	assert.NoError(t, i.watcher.Err())
	_, open := <-i.watcher.Changes()
	assert.False(t, open, "the changes channel was left open")
	assert.Zero(t, i.overlaps.Load(), "scans overlapped")
}

func TestChangesDuringAScanAreScannedAfterIt(t *testing.T) {
	t.Parallel()
	i := startIntegration(t, true)
	app := filepath.Join(i.root, "app.yaml")

	i.waitScanned("v0|1") // the initial scan is running, and held

	// The files change while it runs, several times over.
	for n := 1; n <= 10; n++ {
		write(t, app, fmt.Sprintf("during-%d", n))
	}
	write(t, filepath.Join(i.root, "late.yaml"), "kind: Pod\n")
	i.gate <- struct{}{} // the scan ends

	// The scan after it reads the state the changes left, and so does not miss
	// one made while it was busy.
	i.waitScanned("during-10|2")
	i.gate <- struct{}{}

	i.cancel()
	require.ErrorIs(t, <-i.result, context.Canceled)
	assert.Zero(t, i.overlaps.Load(), "scans overlapped")
}

func TestAWatcherThatStopsEndsTheSchedulerWithItsReason(t *testing.T) {
	t.Parallel()
	i := startIntegration(t, false)
	i.waitScanned("v0|1")

	require.NoError(t, os.RemoveAll(i.root))

	select {
	case err := <-i.result:
		assert.ErrorIs(t, err, ErrChangesClosed)
	case <-time.After(waitTimeout):
		t.Fatal("the scheduler did not stop when its watcher did")
	}
	<-i.watcher.done
	require.Error(t, i.watcher.Err())
	assert.Contains(t, i.watcher.Err().Error(), "removed or renamed", "the watcher says why it stopped")
}
