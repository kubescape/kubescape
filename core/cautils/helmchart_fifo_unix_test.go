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
func TestReadHelmTemplateFile_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "template.yaml")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		_, err := readHelmTemplateFile(fifo)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHelmTemplateNotRegular)
	case <-time.After(5 * time.Second):
		t.Fatal("readHelmTemplateFile blocked on a FIFO with no writer")
	}
}

func TestIsStaticTemplate_FIFOWithoutWriterDoesNotBlock(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "template.yaml")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		static, err := isStaticTemplate(fifo)
		if err == nil && static {
			done <- assert.AnError
			return
		}
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHelmTemplateNotRegular)
	case <-time.After(5 * time.Second):
		t.Fatal("isStaticTemplate blocked on a FIFO with no writer")
	}
}
