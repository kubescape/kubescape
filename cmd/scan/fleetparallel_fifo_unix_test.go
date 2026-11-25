//go:build unix

package scan

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A FIFO with no writer blocks a plain open forever, so the call runs under a
// deadline, and the FIFO is released on cleanup in case a regression hangs it.
func TestReadChildCluster_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "child.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		_, err := readChildCluster(fifo, "ctx")
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrFleetFileNotRegular), "expected ErrFleetFileNotRegular, got %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("readChildCluster blocked on a FIFO with no writer")
	}
}
