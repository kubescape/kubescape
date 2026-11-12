//go:build unix && !aix && !illumos && !solaris

package locationresolver

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
func TestNewPathLocationResolver_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "manifest.yaml")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		_, err := NewPathLocationResolver(fifo)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrManifestNotRegular)
	case <-time.After(5 * time.Second):
		t.Fatal("NewPathLocationResolver blocked on a FIFO with no writer")
	}
}

// A FIFO with a live writer keeps the write end open with buffered data.
// NewPathLocationResolver must reject it promptly with ErrManifestNotRegular
// without blocking on reading or waiting for EOF.
func TestNewPathLocationResolver_FIFOWithLiveWriterIsRejectedPromptly(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "live_manifest.yaml")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))

	// O_RDWR opens without waiting for a reader and keeps a write end open.
	writer, err := os.OpenFile(fifo, os.O_RDWR, 0)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = writer.Close()
	})

	_, err = writer.WriteString("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test\n")
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		_, err := NewPathLocationResolver(fifo)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrManifestNotRegular)
	case <-time.After(5 * time.Second):
		t.Fatal("NewPathLocationResolver blocked on a FIFO with a live writer")
	}
}
