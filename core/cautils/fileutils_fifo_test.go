//go:build unix

package cautils

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fifoTestManifest = `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cm","namespace":"default"}}`

// TestLoadFiles_NonRegularFileDoesNotBlock pins that a discovered FIFO can
// neither stall the scan nor vanish from it. Reading a FIFO waits for its
// writer: opening it blocks until one appears, and reading blocks until every
// writer closes, however few bytes it sent. loadFiles is sequential, so either
// wait would also hold back every manifest after it.
func TestLoadFiles_NonRegularFileDoesNotBlock(t *testing.T) {
	dir := t.TempDir()

	// A writer that sends a valid, under-limit manifest and keeps its end open.
	// O_RDWR opens without waiting for a reader and keeps a write end open.
	held := filepath.Join(dir, "held.json")
	require.NoError(t, syscall.Mkfifo(held, 0o600))
	writer, err := os.OpenFile(held, os.O_RDWR, 0)
	require.NoError(t, err)
	_, err = writer.WriteString(fifoTestManifest)
	require.NoError(t, err)

	// No writer at all.
	idle := filepath.Join(dir, "idle.json")
	require.NoError(t, syscall.Mkfifo(idle, 0o600))

	regular := filepath.Join(dir, "regular.json")
	require.NoError(t, os.WriteFile(regular, []byte(fifoTestManifest), 0o600))

	var (
		workloads map[string][]workloadinterface.IMetadata
		skips     []SkippedManifest
		errs      []error
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		workloads, skips, errs = loadFiles(dir, []string{held, idle, regular})
	}()

	// release lets a blocked loadFiles finish, so a failure here never leaves
	// the goroutine or the test behind: closing the writer ends the read on
	// held, and briefly opening a writer on idle ends the open waiting on it.
	release := func() {
		_ = writer.Close()
		deadline := time.After(10 * time.Second)
		for {
			select {
			case <-done:
				return
			case <-deadline:
				t.Error("loadFiles still blocked after its FIFO writers were released")
				return
			case <-time.After(10 * time.Millisecond):
				if w, err := os.OpenFile(idle, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					_ = w.Close()
				}
			}
		}
	}
	t.Cleanup(release)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		release()
		t.Fatal("loadFiles blocked on a FIFO and never reached the manifests after it")
	}

	assert.Len(t, workloads[regular], 1, "the manifest after the FIFOs was not loaded")
	assert.NotContains(t, workloads, held)
	assert.NotContains(t, workloads, idle)

	var skipped []string
	for _, s := range skips {
		skipped = append(skipped, s.Path)
	}
	assert.ElementsMatch(t, []string{held, idle}, skipped, "a FIFO must be reported as skipped, not dropped")
	require.Len(t, errs, 2)
	for _, e := range errs {
		assert.ErrorIs(t, e, ErrNotRegularFile)
	}
}
