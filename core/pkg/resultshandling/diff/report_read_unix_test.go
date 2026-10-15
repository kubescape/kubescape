//go:build unix

package diff

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A FIFO with no writer blocks a plain open forever, so each call runs under a
// deadline, and the FIFO is released on cleanup in case a regression hangs it.
func TestReportReadsDoNotBlockOnFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})

	calls := map[string]func() error{
		"loadReport":              func() error { _, err := loadReport(fifo); return err },
		"loadVulnerabilityReport": func() error { _, err := loadVulnerabilityReport(fifo); return err },
		"ReportKindOf": func() error {
			if ReportKindOf(fifo) != UnreadableReport {
				return os.ErrInvalid
			}
			return errReportNotRegular
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() { done <- call() }()
			select {
			case err := <-done:
				assert.ErrorIs(t, err, errReportNotRegular)
			case <-time.After(5 * time.Second):
				t.Fatal("blocked on a FIFO with no writer")
			}
		})
	}
}
