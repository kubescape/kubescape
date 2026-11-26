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

func TestHelmValueOptions_MergeValues_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	t.Run("FIFO -f values file", func(t *testing.T) {
		fifo := filepath.Join(t.TempDir(), "values.yaml")
		require.NoError(t, syscall.Mkfifo(fifo, 0o600))
		t.Cleanup(func() {
			if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
				_ = f.Close()
			}
		})

		done := make(chan error, 1)
		go func() {
			_, err := (HelmValueOptions{ValueFiles: []string{fifo}}).MergeValues()
			done <- err
		}()

		select {
		case err := <-done:
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrHelmTemplateNotRegular)
		case <-time.After(5 * time.Second):
			t.Fatal("MergeValues blocked on a FIFO -f values file with no writer")
		}
	})

	t.Run("FIFO --set-file source", func(t *testing.T) {
		fifo := filepath.Join(t.TempDir(), "secret.txt")
		require.NoError(t, syscall.Mkfifo(fifo, 0o600))
		t.Cleanup(func() {
			if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
				_ = f.Close()
			}
		})

		done := make(chan error, 1)
		go func() {
			_, err := (HelmValueOptions{FileValues: []string{"cfg=" + fifo}}).MergeValues()
			done <- err
		}()

		select {
		case err := <-done:
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrHelmTemplateNotRegular)
		case <-time.After(5 * time.Second):
			t.Fatal("MergeValues blocked on a FIFO --set-file source with no writer")
		}
	})
}
