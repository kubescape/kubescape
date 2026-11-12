//go:build unix && !aix && !illumos && !solaris

package cautils

import (
	"context"
	"fmt"
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
func TestReadKustomizationFile_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "kustomization.yaml")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		_, err := readKustomizationFile(fifo)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrKustomizationFileNotRegular)
	case <-time.After(5 * time.Second):
		t.Fatal("readKustomizationFile blocked on a FIFO with no writer")
	}
}

func TestKustomizeInputOwnershipForPath_FIFOWithoutWriterDoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "kustomization.yaml")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		ownership, err := KustomizeInputOwnershipForPath(context.Background(), dir)
		if err == nil && len(ownership.SourcePaths) > 0 {
			done <- fmt.Errorf("expected no source paths from non-regular FIFO, got %v", ownership.SourcePaths)
			return
		}
		done <- err
	}()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("KustomizeInputOwnershipForPath blocked on a FIFO with no writer")
	}
}
