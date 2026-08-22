package printer

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
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
	// Registered before the writer restore so it runs after it (cleanups are
	// LIFO), and after t.TempDir's own removal was registered so it runs
	// before that. Windows refuses to delete a file that is still open, so
	// leaving the handle around fails the test in TempDir cleanup.
	t.Cleanup(func() { _ = buf.Close() })
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
	// Windows does not model POSIX permission bits at all: os.Stat reports
	// 0777 for every directory, so the check below can only fail there, never
	// catch anything. Return rather than t.Skip so the assertions the caller
	// already made still count.
	if runtime.GOOS == "windows" {
		return
	}
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

func TestGetWriterNoFallback_ReturnsExplicitSetupError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	target := filepath.Join(blocker, "report.json")

	f, err := GetWriterNoFallback(target)

	require.Error(t, err)
	assert.Nil(t, f)
	assert.ErrorContains(t, err, "create output directory")
	assert.NoFileExists(t, target)
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

func TestFormatOutputExtCoversAllFormats(t *testing.T) {
	for _, format := range AllFormats {
		ext, ok := FormatOutputExt[format]
		assert.True(t, ok, "format %q has no entry in FormatOutputExt", format)
		assert.NotEmpty(t, ext, "format %q maps to an empty extension", format)
	}
}

func TestHasOutputExt(t *testing.T) {
	tests := []struct {
		name       string
		outputFile string
		ext        string
		want       bool
	}{
		{"exact lowercase match", "report.json", ".json", true},
		{"uppercase extension matches lowercase ext", "Report.JSON", ".json", true},
		{"mixed case extension matches", "Report.Json", ".json", true},
		{"different extension does not match", "report.yaml", ".json", false},
		{"no extension does not match", "report", ".json", false},
		{"empty outputFile does not match", "", ".json", false},
		{"compound lowercase match", "report.cdx.json", ".cdx.json", true},
		{"compound uppercase match", "Report.CDX.JSON", ".cdx.json", true},
		{"compound partial match", "report.cdx.json", ".json", true},
		{"compound different extension", "report.spdx.json", ".cdx.json", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, HasOutputExt(tt.outputFile, tt.ext))
		})
	}
}

func TestResolveOutputFile(t *testing.T) {
	tests := []struct {
		name         string
		format       string
		outputFile   string
		defaultBase  string
		wantFile     string
		wantExplicit bool
	}{
		{
			name:         "empty output remains implicit",
			format:       JsonFormat,
			outputFile:   "",
			defaultBase:  "report",
			wantFile:     "",
			wantExplicit: false,
		},
		{
			name:         "whitespace explicit output uses default base",
			format:       JsonFormat,
			outputFile:   "   ",
			defaultBase:  "report",
			wantFile:     "report.json",
			wantExplicit: true,
		},
		{
			name:         "trims explicit output before appending extension",
			format:       JsonFormat,
			outputFile:   "  reports/scan  ",
			defaultBase:  "report",
			wantFile:     filepath.Join("reports", "scan.json"),
			wantExplicit: true,
		},
		{
			name:         "keeps existing extension case-insensitively",
			format:       JsonFormat,
			outputFile:   "Report.JSON",
			defaultBase:  "report",
			wantFile:     "Report.JSON",
			wantExplicit: true,
		},
		{
			name:         "keeps yaml extension",
			format:       YamlFormat,
			outputFile:   "report.yaml",
			defaultBase:  "report",
			wantFile:     "report.yaml",
			wantExplicit: true,
		},
		{
			name:         "keeps yml extension",
			format:       YamlFormat,
			outputFile:   "report.yml",
			defaultBase:  "report",
			wantFile:     "report.yml",
			wantExplicit: true,
		},
		{
			name:         "appends compound cyclonedx extension",
			format:       CycloneDXFormat,
			outputFile:   "sbom",
			defaultBase:  "report",
			wantFile:     "sbom.cdx.json",
			wantExplicit: true,
		},
		{
			name:         "keeps compound spdx extension case-insensitively",
			format:       SPDXFormat,
			outputFile:   "Report.SPDX.JSON",
			defaultBase:  "report",
			wantFile:     "Report.SPDX.JSON",
			wantExplicit: true,
		},
		{
			name:         "unknown format only trims and marks explicit",
			format:       "custom",
			outputFile:   "  report.custom  ",
			defaultBase:  "report",
			wantFile:     "report.custom",
			wantExplicit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFile, gotExplicit := ResolveOutputFile(tt.format, tt.outputFile, tt.defaultBase)
			assert.Equal(t, tt.wantFile, gotFile)
			assert.Equal(t, tt.wantExplicit, gotExplicit)
		})
	}
}

func TestResolveDefaultOutputFile(t *testing.T) {
	assert.Equal(t, "report.html", ResolveDefaultOutputFile(HtmlFormat, "report"))
	assert.Equal(t, "report.pdf", ResolveDefaultOutputFile(PdfFormat, "report"))
	assert.Equal(t, "report.md", ResolveDefaultOutputFile(MarkdownFormat, "report"))
	assert.Equal(t, "report.yaml", ResolveDefaultOutputFile(PolicyReportFormat, "report"))
}
