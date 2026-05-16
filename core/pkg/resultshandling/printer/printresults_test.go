package printer

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetWriter_EmptyFileName(t *testing.T) {
	ctx := context.Background()
	outputFile := ""
	file := GetWriter(ctx, outputFile)
	assert.Equal(t, os.Stdout, file)
}

// Regression: GetWriterNoStdoutFallback must never hand back os.Stdout, even
// when the requested path is unwritable — the whole point is to protect TTYs
// from binary/markup formats.
func TestGetWriterNoStdoutFallback_UnwritableTargetFallsBackToTemp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission semantics required for this test")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file-mode permissions; cannot exercise the failure path")
	}
	ctx := context.Background()

	// Create a 0555 directory we cannot write into, then ask to create a file
	// inside it. This is the same shape as matthyx's reproducer (read-only cwd).
	roDir := filepath.Join(t.TempDir(), "ro")
	assert.NoError(t, os.Mkdir(roDir, 0o555))
	target := filepath.Join(roDir, "report.pdf")

	f := GetWriterNoStdoutFallback(ctx, target, "kubescape-report-*.pdf")
	if f != nil {
		t.Cleanup(func() {
			_ = f.Close()
			_ = os.Remove(f.Name())
		})
	}
	assert.NotNil(t, f)
	assert.NotEqual(t, os.Stdout.Name(), f.Name(),
		"must not fall back to stdout for binary/markup formats")
	assert.NotEqual(t, target, f.Name(),
		"target was unwritable; expected a fallback path")
}

func TestGetWriterNoStdoutFallback_EmptyFileNameStillAvoidsStdout(t *testing.T) {
	ctx := context.Background()
	f := GetWriterNoStdoutFallback(ctx, "", "kubescape-report-*.pdf")
	if f != nil {
		t.Cleanup(func() {
			_ = f.Close()
			_ = os.Remove(f.Name())
		})
	}
	assert.NotNil(t, f)
	assert.NotEqual(t, os.Stdout.Name(), f.Name())
}
