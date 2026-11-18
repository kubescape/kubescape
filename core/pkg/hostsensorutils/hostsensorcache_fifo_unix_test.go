//go:build !windows

package hostsensorutils

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenHostSensorCacheFile_RejectsFIFOWithoutHanging(t *testing.T) {
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
		f, err := openHostSensorCacheFile(fifo)
		if f != nil {
			_ = f.Close()
		}
		done <- err
	}()

	select {
	case err := <-done:
		assert.Error(t, err)
		assert.ErrorContains(t, err, "is not a regular file")
	case <-time.After(2 * time.Second):
		t.Fatal("openHostSensorCacheFile hung on FIFO without a writer")
	}
}

func TestLoadFromCache_RejectsFIFOWithoutHanging(t *testing.T) {
	withTempCacheDir(t)
	withK8sHost(t, "https://cluster-a.example.com")
	t.Setenv(HostSensorCacheTtlEnvVar, "1h")

	path, err := getCacheFilePath("cluster-prod", "KubeletInfo")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
	require.NoError(t, syscall.Mkfifo(path, 0600))
	defer func() {
		if f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	}()

	done := make(chan error, 1)
	go func() {
		_, err := loadFromCache("cluster-prod", "KubeletInfo")
		done <- err
	}()

	select {
	case err := <-done:
		assert.Error(t, err)
		assert.ErrorContains(t, err, "is not a regular file")
	case <-time.After(2 * time.Second):
		t.Fatal("loadFromCache hung on FIFO cache file without a writer")
	}
}
