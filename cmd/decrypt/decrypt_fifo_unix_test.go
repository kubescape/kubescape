//go:build unix && !aix && !illumos && !solaris

package decrypt

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
// deadline, and the FIFO is released on cleanup in case a regression hangs it.
func TestDecryptCommand_FIFOWithoutWriterIsRejectedPromptly(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "report.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		cmd := GetDecryptCommand()
		done <- cmd.RunE(cmd, []string{fifo})
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.ErrorIs(t, err, errReportNotRegular)
	case <-time.After(5 * time.Second):
		t.Fatal("decrypt command blocked on a FIFO with no writer")
	}
}
