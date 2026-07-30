package printer

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestGetWriter_ValidFileName(t *testing.T) {
	ctx := context.Background()
	target := filepath.Join(t.TempDir(), "nested", "report.json")

	f := GetWriter(ctx, target)
	require.NotNil(t, f)
	t.Cleanup(func() { _ = f.Close() })

	assert.Equal(t, target, f.Name())
	assert.NotEqual(t, os.Stdout, f)
}

// MkdirAll fails when a path component that should be a directory is actually
// a regular file - exercises GetWriter's directory-creation failure branch.
func TestGetWriter_MkdirAllFailsFallsBackToStdout(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	target := filepath.Join(blocker, "subdir", "report.json")

	f := GetWriter(context.Background(), target)
	assert.Equal(t, os.Stdout, f)
}

func TestGetWriter_CreateFailsFallsBackToStdout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission semantics required for this test")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file-mode permissions; cannot exercise the failure path")
	}
	roDir := filepath.Join(t.TempDir(), "ro")
	require.NoError(t, os.Mkdir(roDir, 0o555))
	target := filepath.Join(roDir, "report.json")

	f := GetWriter(context.Background(), target)
	assert.Equal(t, os.Stdout, f)
}

func TestGetWriterNoStdoutFallback_ValidFileName(t *testing.T) {
	ctx := context.Background()
	target := filepath.Join(t.TempDir(), "nested", "report.pdf")

	f := GetWriterNoStdoutFallback(ctx, target, "kubescape-report-*.pdf")
	require.NotNil(t, f)
	t.Cleanup(func() { _ = f.Close() })

	assert.Equal(t, target, f.Name())
	assert.NotEqual(t, os.Stdout.Name(), f.Name())
}

// MkdirAll fails when a path component that should be a directory is actually
// a regular file - exercises the directory-creation failure branch, which is
// distinct from the "directory exists but is read-only" case already covered
// by TestGetWriterNoStdoutFallback_UnwritableTargetFallsBackToTemp.
func TestGetWriterNoStdoutFallback_MkdirAllFailsFallsBackToTemp(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	target := filepath.Join(blocker, "subdir", "report.pdf")

	f := GetWriterNoStdoutFallback(context.Background(), target, "kubescape-report-*.pdf")
	if f != nil {
		t.Cleanup(func() {
			_ = f.Close()
			_ = os.Remove(f.Name())
		})
	}
	require.NotNil(t, f)
	assert.NotEqual(t, os.Stdout.Name(), f.Name())
	assert.NotEqual(t, target, f.Name())
}

func TestLogOutputFile(t *testing.T) {
	// LogOutputFile only branches on the filename; calling it for each branch
	// is enough to confirm it does not panic and logs are skipped for the
	// stdout/stderr/devnull sinks.
	t.Run("regular file logs success", func(t *testing.T) {
		LogOutputFile(filepath.Join(t.TempDir(), "report.json"))
	})
	t.Run("stdout is not logged", func(t *testing.T) {
		LogOutputFile(os.Stdout.Name())
	})
	t.Run("stderr is not logged", func(t *testing.T) {
		LogOutputFile(os.Stderr.Name())
	})
	t.Run("devnull is not logged", func(t *testing.T) {
		LogOutputFile(os.DevNull)
	})
}
