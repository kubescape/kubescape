//go:build unix && !aix && !illumos && !solaris

package policytest

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/pkg/ruledir"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A FIFO with no writer blocks a plain open forever, so the call runs under a
// deadline, and the FIFO is released on cleanup in case a regression hangs it.
func TestLoadCaseInput_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	dir := t.TempDir()
	inputDir := filepath.Join(dir, "input")
	require.NoError(t, os.MkdirAll(inputDir, 0o750))
	fifo := filepath.Join(inputDir, "manifest.yaml")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		_, err := LoadCaseInput(dir)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ruledir.ErrNotRegularFile)
	case <-time.After(5 * time.Second):
		t.Fatal("LoadCaseInput blocked on a FIFO with no writer")
	}
}

func TestLoadCaseExpected_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, expectedFileName)
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		_, err := LoadCaseExpected(dir)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ruledir.ErrNotRegularFile)
	case <-time.After(5 * time.Second):
		t.Fatal("LoadCaseExpected blocked on a FIFO with no writer")
	}
}

func TestLoadCaseData_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, dataFileName)
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		_, err := LoadCaseData(dir)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ruledir.ErrNotRegularFile)
	case <-time.After(5 * time.Second):
		t.Fatal("LoadCaseData blocked on a FIFO with no writer")
	}
}
