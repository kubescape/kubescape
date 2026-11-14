package printer

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A printer's writer must not touch an existing report until the scan has a
// new one to write.
func TestGetPrinterWriterNoFallback_KeepsExistingContentUntilPrepared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(path, []byte("old report, longer than the new one"), 0o600))

	f, err := GetPrinterWriterNoFallback(path)
	require.NoError(t, err)

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "old report, longer than the new one", string(got), "opening must not truncate")

	require.NoError(t, PrepareOutput(f))
	_, err = f.WriteString("new")
	require.NoError(t, err)
	require.NoError(t, CloseOutput(f))

	got, err = os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "new", string(got), "a prepared file is fully replaced, no trailing bytes")
}

func TestCloseOutput_PreExistingFileIsKeptWhenNothingWasWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(path, []byte("old report"), 0o600))

	f, err := GetPrinterWriterNoFallback(path)
	require.NoError(t, err)
	require.NoError(t, CloseOutput(f))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "old report", string(got))
}

func TestCloseOutput_RemovesAFileItCreatedWhenNothingWasWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")

	f, err := GetPrinterWriterNoFallback(path)
	require.NoError(t, err)
	require.FileExists(t, path, "the file is created at open so path errors surface before the scan")
	require.NoError(t, CloseOutput(f))

	assert.NoFileExists(t, path)
}

func TestCloseOutput_KeepsAFileItCreatedOnceItWasPrepared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")

	f, err := GetPrinterWriterNoFallback(path)
	require.NoError(t, err)
	require.NoError(t, PrepareOutput(f))
	_, err = f.WriteString("report")
	require.NoError(t, err)
	require.NoError(t, CloseOutput(f))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "report", string(got))
}

// If the path was replaced by another file in the meantime, CloseOutput must
// not delete that file.
func TestCloseOutput_DoesNotRemoveAReplacedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")

	f, err := GetPrinterWriterNoFallback(path)
	require.NoError(t, err)
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.WriteFile(path, []byte("someone else's file"), 0o600))
	require.NoError(t, CloseOutput(f))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "someone else's file", string(got))
}

// The immediate variants keep their old behaviour for callers that write
// right away (diff, vap) and never call PrepareOutput.
func TestGetWriterNoFallback_StillTruncatesOnOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o600))

	f, err := GetWriterNoFallback(path)
	require.NoError(t, err)
	defer f.Close()

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Zero(t, info.Size())
}

func TestPrepareAndCloseOutput_AreNoOpsForStdoutAndNil(t *testing.T) {
	assert.NoError(t, PrepareOutput(nil))
	assert.NoError(t, PrepareOutput(os.Stdout))
	assert.NoError(t, CloseOutput(nil))
}

func TestGetPrinterWriterNoFallback_StillTightensPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not modeled on Windows")
	}
	path := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o600))
	require.NoError(t, os.Chmod(path, 0o644))

	f, err := GetPrinterWriterNoFallback(path)
	require.NoError(t, err)
	defer func() { _ = CloseOutput(f) }()

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}
