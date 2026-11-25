//go:build !windows

package v1

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenBoundedResultFile_RejectsFIFOWithoutHanging(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "test.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0600))
	defer func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	}()

	done := make(chan error, 1)
	go func() {
		_, err := openBoundedResultFile(fifo, 1024)
		done <- err
	}()

	select {
	case err := <-done:
		assert.Error(t, err)
		assert.ErrorContains(t, err, "is not a regular file")
	case <-time.After(2 * time.Second):
		t.Fatal("openBoundedResultFile hung on FIFO without a writer")
	}
}

func TestReadResultsFile_RejectsFIFOWithoutHanging(t *testing.T) {
	dir := t.TempDir()

	oldOutputDir := OutputDir
	OutputDir = dir
	defer func() { OutputDir = oldOutputDir }()

	validUUID := "123e4567-e89b-12d3-a456-426614174000"
	fifo := filepath.Join(dir, validUUID+".json")
	require.NoError(t, syscall.Mkfifo(fifo, 0600))
	defer func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	}()

	done := make(chan error, 1)
	go func() {
		_, err := readResultsFile(validUUID)
		done <- err
	}()

	select {
	case err := <-done:
		assert.Error(t, err)
		assert.ErrorContains(t, err, "file 123e4567-e89b-12d3-a456-426614174000 not found")
	case <-time.After(2 * time.Second):
		t.Fatal("readResultsFile hung on FIFO in OutputDir without a writer")
	}
}
