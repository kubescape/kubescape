//go:build unix && !aix && !illumos && !solaris

package fixhandler

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A FIFO with no writer blocks a plain open forever, so the call runs under a
// deadline, and the FIFO is released on cleanup in case a regression hangs it.
func TestGetFileString_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "manifest.yaml")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		_, err := GetFileString(fifo)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrManifestNotRegular)
	case <-time.After(5 * time.Second):
		t.Fatal("GetFileString blocked on a FIFO with no writer")
	}
}

func TestApplyChanges_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "manifest.yaml")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		h := &FixHandler{
			fixInfo:   &metav1.FixInfo{},
			reportObj: &reporthandlingv2.PostureReport{},
		}
		fixes := []ResourceFixInfo{{FilePath: fifo, relativePath: "manifest.yaml"}}
		_, errs := h.ApplyChanges(context.Background(), fixes)
		if len(errs) > 0 {
			done <- errs[0]
		} else {
			done <- nil
		}
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrManifestNotRegular)
	case <-time.After(5 * time.Second):
		t.Fatal("ApplyChanges blocked on a FIFO with no writer")
	}
}

func TestBuildPatch_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	baseDir := t.TempDir()
	fifo := filepath.Join(baseDir, "manifest.yaml")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		h := patchHandler(baseDir, "")
		fixes := []ResourceFixInfo{{FilePath: fifo, relativePath: "manifest.yaml"}}
		_, err := h.BuildPatch(context.Background(), fixes)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrManifestNotRegular)
	case <-time.After(5 * time.Second):
		t.Fatal("BuildPatch blocked on a FIFO with no writer")
	}
}
