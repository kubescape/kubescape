//go:build unix

package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestLoadConfig_RejectsFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()

	t.Run("direct FIFO clusterData.json fails fast", func(t *testing.T) {
		fifo := filepath.Join(dir, "clusterData.json")
		require.NoError(t, unix.Mkfifo(fifo, 0o600))

		done := make(chan error, 1)
		go func() {
			_, err := LoadConfig(dir)
			done <- err
		}()

		select {
		case err := <-done:
			require.ErrorIs(t, err, ErrConfigNotRegular)
		case <-time.After(2 * time.Second):
			if f, err := os.OpenFile(fifo, os.O_RDWR|unix.O_NONBLOCK, 0); err == nil {
				_ = f.Close()
			}
			t.Fatal("LoadConfig blocked on FIFO")
		}
	})

	t.Run("symlink to FIFO fails fast", func(t *testing.T) {
		subDir := filepath.Join(dir, "symlink-case")
		require.NoError(t, os.MkdirAll(subDir, 0o700))

		fifo := filepath.Join(dir, "target.pipe")
		require.NoError(t, unix.Mkfifo(fifo, 0o600))
		require.NoError(t, os.Symlink(fifo, filepath.Join(subDir, "clusterData.json")))

		done := make(chan error, 1)
		go func() {
			_, err := LoadConfig(subDir)
			done <- err
		}()

		select {
		case err := <-done:
			require.ErrorIs(t, err, ErrConfigNotRegular)
		case <-time.After(2 * time.Second):
			if f, err := os.OpenFile(fifo, os.O_RDWR|unix.O_NONBLOCK, 0); err == nil {
				_ = f.Close()
			}
			t.Fatal("LoadConfig blocked on FIFO symlink")
		}
	})
}
