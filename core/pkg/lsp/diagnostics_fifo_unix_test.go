//go:build unix

package lsp

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReadBoundedRejectsFIFOWithoutWriter(t *testing.T) {
	for _, name := range []string{"fifo", "symlink"} {
		t.Run(name, func(t *testing.T) {
			fifo := filepath.Join(t.TempDir(), "manifest.yaml")
			require.NoError(t, syscall.Mkfifo(fifo, 0o600))
			// Release a blocked reader if this test catches a regression.
			t.Cleanup(func() {
				if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
					_ = f.Close()
				}
			})
			path := fifo
			if name == "symlink" {
				path = filepath.Join(t.TempDir(), "linked.yaml")
				require.NoError(t, os.Symlink(fifo, path))
			}

			done := make(chan error, 1)
			go func() {
				_, err := readBounded(path)
				done <- err
			}()

			select {
			case err := <-done:
				require.ErrorContains(t, err, "not a regular file")
			case <-time.After(time.Second):
				t.Fatal("readBounded blocked on a FIFO with no writer")
			}
		})
	}
}
