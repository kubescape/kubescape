//go:build unix && !aix && !illumos && !solaris

package cautils

import (
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
func TestLoadIgnoreFilePatterns_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, IgnoreFileName)
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		_, err := LoadIgnoreFilePatterns(dir)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrIgnoreFileNotRegular)
	case <-time.After(5 * time.Second):
		t.Fatal("LoadIgnoreFilePatterns blocked on a FIFO with no writer")
	}
}
