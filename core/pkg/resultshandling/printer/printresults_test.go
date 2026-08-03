package printer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/go-logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureLog redirects the shared logger to a temp file for the duration of
// fn and returns everything written to it, so tests can assert on log
// content instead of just "it didn't panic".
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	buf, err := os.CreateTemp(t.TempDir(), "log-*")
	require.NoError(t, err)
	prev := logger.L().GetWriter()
	logger.L().SetWriter(buf)
	t.Cleanup(func() { logger.L().SetWriter(prev) })

	fn()

	require.NoError(t, buf.Sync())
	b, err := os.ReadFile(buf.Name())
	require.NoError(t, err)
	return string(b)
}

func TestGetWriter_EmptyFileName(t *testing.T) {
	ctx := context.Background()
	outputFile := ""
	file := GetWriter(ctx, outputFile)
	assert.Same(t, os.Stdout, file)
}

// Regression: GetWriterNoStdoutFallback must never hand back os.Stdout, even
// when the requested path is unwritable — the whole point is to protect TTYs
// from binary/markup formats. It must actually fall back to a usable temp
// file, not merely to "something that isn't stdout" (e.g. os.DevNull, which
// would silently discard the user's report).
func TestGetWriterNoStdoutFallback_UnwritableTargetFallsBackToTemp(t *testing.T) {
	ctx := context.Background()

	// os.Create on an existing directory fails with EISDIR regardless of uid,
	// so this exercises the failure path even when tests run as root.
	target := filepath.Join(t.TempDir(), "report.pdf")
	require.NoError(t, os.Mkdir(target, 0o755))

	f := GetWriterNoStdoutFallback(ctx, target, "kubescape-report-*.pdf")
	require.NotNil(t, f)
	t.Cleanup(func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	})

	assert.Equal(t, filepath.Clean(os.TempDir()), filepath.Dir(f.Name()))
	assert.True(t, strings.HasPrefix(filepath.Base(f.Name()), "kubescape-report-"))
	assert.True(t, strings.HasSuffix(f.Name(), ".pdf"))
	_, err := f.WriteString("pdf-bytes") // the handle must be usable, not a discard sink
	assert.NoError(t, err)
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
	assertDirNotMorePermissiveThan0750(t, filepath.Dir(target))
}

// assertDirNotMorePermissiveThan0750 fails the test if dir's permission bits
// grant group-write or any access to others - i.e. it is no more permissive
// than 0o750. This is a meaningful regression guard only when the process
// umask doesn't already mask out those bits: umask can strip bits from the
// mode MkdirAll requests but never add them, so under a restrictive umask
// (e.g. 077) even the old os.ModePerm (0777) code would satisfy this check,
// producing a false pass. CI's default umask (022) does make this
// effective; a locally reproducible false pass isn't worth the
// platform-specific (Unix-only) umask control it would take to close, given
// this repo also ships Windows builds.
func assertDirNotMorePermissiveThan0750(t *testing.T, dir string) {
	t.Helper()
	info, err := os.Stat(dir)
	require.NoError(t, err)
	mode := info.Mode().Perm()
	assert.Zerof(t, mode&0o027, "directory %s has mode %o, more permissive than 0750", dir, mode)
}

// MkdirAll fails when a path component that should be a directory is actually
// a regular file - exercises GetWriter's directory-creation failure branch.
func TestGetWriter_MkdirAllFailsFallsBackToStdout(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	target := filepath.Join(blocker, "subdir", "report.json")

	f := GetWriter(context.Background(), target)
	assert.Same(t, os.Stdout, f)
}

func TestGetWriter_CreateFailsFallsBackToStdout(t *testing.T) {
	// os.Create on an existing directory fails with EISDIR regardless of uid,
	// so this exercises the failure path even when tests run as root.
	target := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.Mkdir(target, 0o755))

	f := GetWriter(context.Background(), target)
	assert.Same(t, os.Stdout, f)
}

func TestGetWriterNoStdoutFallback_ValidFileName(t *testing.T) {
	ctx := context.Background()
	target := filepath.Join(t.TempDir(), "nested", "report.pdf")

	f := GetWriterNoStdoutFallback(ctx, target, "kubescape-report-*.pdf")
	require.NotNil(t, f)
	t.Cleanup(func() { _ = f.Close() })

	assert.Equal(t, target, f.Name())
	assert.NotEqual(t, os.Stdout.Name(), f.Name())
	assertDirNotMorePermissiveThan0750(t, filepath.Dir(target))
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
	require.NotNil(t, f)
	t.Cleanup(func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	})

	assert.Equal(t, filepath.Clean(os.TempDir()), filepath.Dir(f.Name()))
	assert.True(t, strings.HasPrefix(filepath.Base(f.Name()), "kubescape-report-"))
	assert.True(t, strings.HasSuffix(f.Name(), ".pdf"))
	_, err := f.WriteString("pdf-bytes") // the handle must be usable, not a discard sink
	assert.NoError(t, err)
}

func TestLogOutputFile(t *testing.T) {
	out := captureLog(t, func() { LogOutputFile(filepath.Join(t.TempDir(), "report.json")) })
	assert.Contains(t, out, "Scan results saved")

	for _, sink := range []string{os.Stdout.Name(), os.Stderr.Name(), os.DevNull} {
		out := captureLog(t, func() { LogOutputFile(sink) })
		assert.Empty(t, strings.TrimSpace(out), "expected no log for %s", sink)
	}
}
