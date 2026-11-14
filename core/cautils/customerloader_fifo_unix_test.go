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

// A FIFO with no writer blocks a plain open or read forever. These tests verify
// that customerloader operations do not hang on FIFOs without writers.

func TestExistsConfigFile_FIFOWithoutWriterReturnsFalsePromptly(t *testing.T) {
	useTemporaryConfigStore(t)
	fifo := ConfigFileFullPath()
	require.NoError(t, os.MkdirAll(filepath.Dir(fifo), 0o700))
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan bool, 1)
	go func() {
		done <- existsConfigFile()
	}()

	select {
	case exists := <-done:
		assert.False(t, exists, "a FIFO is not a regular file and must return false")
	case <-time.After(5 * time.Second):
		t.Fatal("existsConfigFile blocked on a FIFO with no writer")
	}
}

func TestLoadConfigFromFile_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	useTemporaryConfigStore(t)
	fifo := ConfigFileFullPath()
	require.NoError(t, os.MkdirAll(filepath.Dir(fifo), 0o700))
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		done <- loadConfigFromFile(&ConfigObj{})
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConfigFileNotRegular)
	case <-time.After(5 * time.Second):
		t.Fatal("loadConfigFromFile blocked on a FIFO with no writer")
	}
}

func TestLoadUrlsFromFile_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "services.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
	useTemporaryServicesConfigPath(t, fifo)

	done := make(chan error, 1)
	go func() {
		done <- loadUrlsFromFile(&ConfigObj{})
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConfigFileNotRegular)
	case <-time.After(5 * time.Second):
		t.Fatal("loadUrlsFromFile blocked on a FIFO with no writer")
	}
}
