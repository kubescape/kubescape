//go:build unix && !aix && !illumos && !solaris

package cautils

import (
	"context"
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
func TestReadArtifactFile_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "artifact.json")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		_, err := readArtifactFile(fifo)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrArtifactFileNotRegular)
	case <-time.After(5 * time.Second):
		t.Fatal("readArtifactFile blocked on a FIFO with no writer")
	}
}

func TestSetUseArtifactsFrom_FIFOWithoutWriterDoesNotBlock(t *testing.T) {
	dir := t.TempDir()

	validFramework := `{"name":"custom-fw","controls":[]}`
	validFile := filepath.Join(dir, "framework.json")
	require.NoError(t, os.WriteFile(validFile, []byte(validFramework), 0o600))

	fifo := filepath.Join(dir, "idle.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	scanInfo := &ScanInfo{UseArtifactsFrom: dir}
	go func() {
		done <- scanInfo.setUseArtifactsFrom(context.Background())
	}()

	select {
	case err := <-done:
		require.NoError(t, err)
		assert.Contains(t, scanInfo.UseFrom, validFile)
		assert.NotContains(t, scanInfo.UseFrom, fifo)
	case <-time.After(5 * time.Second):
		t.Fatal("setUseArtifactsFrom blocked on a FIFO with no writer")
	}
}
