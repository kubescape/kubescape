//go:build unix && !aix && !illumos && !solaris

package cautils

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
func TestReadTerraformFile_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "manifest.tf")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		_, err := readTerraformFile(fifo)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrTerraformFileNotRegular)
	case <-time.After(5 * time.Second):
		t.Fatal("readTerraformFile blocked on a FIFO with no writer")
	}
}

func TestTerraformDirectory_GetWorkloads_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "main.tf")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan []error, 1)
	go func() {
		td := NewTerraformDirectory(dir)
		_, errs := td.GetWorkloads(dir)
		done <- errs
	}()

	select {
	case errs := <-done:
		require.NotEmpty(t, errs)
		found := false
		for _, e := range errs {
			if errors.Is(e, ErrTerraformFileNotRegular) {
				found = true
				break
			}
		}
		assert.True(t, found, "expected ErrTerraformFileNotRegular in errs: %v", errs)
	case <-time.After(5 * time.Second):
		t.Fatal("GetWorkloads blocked on a FIFO with no writer")
	}
}
