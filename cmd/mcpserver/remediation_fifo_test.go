//go:build !windows

package mcpserver

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A FIFO with no writer blocks a plain open forever, so the call runs under a
// deadline and the FIFO is unblocked on cleanup in case a regression hangs it.
func TestReadRemediationReport_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))

	type result struct {
		raw []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		raw, err := readRemediationReport(fifo)
		done <- result{raw, err}
	}()
	t.Cleanup(func() {
		// O_RDWR never blocks on a FIFO; holding it open lets a stuck reader
		// proceed to EOF so the goroutine does not outlive the test.
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	select {
	case r := <-done:
		require.Error(t, r.err)
		assert.Contains(t, r.err.Error(), "not a regular file")
		assert.Nil(t, r.raw)
	case <-time.After(5 * time.Second):
		t.Fatal("readRemediationReport blocked on a FIFO with no writer")
	}
}

func TestReadRemediationReport_RegularFileStillReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"ok":true}`), 0o600))

	raw, err := readRemediationReport(path)
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true}`, string(raw))
}

// The pre-open check can be raced, so the open itself must not block on a FIFO.
// This exercises the open flags directly, bypassing the pre-check.
func TestRemediationReportOpenDoesNotBlockOnFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))

	done := make(chan *os.File, 1)
	go func() {
		f, _ := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		done <- f
	}()
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	select {
	case f := <-done:
		require.NotNil(t, f)
		defer f.Close()
		info, err := f.Stat()
		require.NoError(t, err)
		assert.False(t, info.Mode().IsRegular())
	case <-time.After(5 * time.Second):
		t.Fatal("a non-blocking open of a FIFO blocked")
	}
}
