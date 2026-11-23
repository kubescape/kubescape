//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadNamespaceFilters_RejectsFIFOWithoutHanging(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "filters.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0600))
	defer func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	}()

	done := make(chan error, 1)
	go func() {
		_, err := readNamespaceFilters(fifo)
		done <- err
	}()

	select {
	case err := <-done:
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNamespaceFiltersNotRegular)
	case <-time.After(2 * time.Second):
		t.Fatal("readNamespaceFilters hung on FIFO without a writer")
	}
}
