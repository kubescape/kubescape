package fixhandler

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// skipOnWindowsSymlink skips a test that requires creating a symlink, since
// doing so on Windows requires elevated privileges the CI runner may not have.
func skipOnWindowsSymlink(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}
}

func TestIsPathContained(t *testing.T) {
	t.Run("plain relative traversal is rejected", func(t *testing.T) {
		base := t.TempDir()
		outside := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(outside, "victim.yaml"), []byte("x"), 0o600))

		target := filepath.Join(base, "..", filepath.Base(outside), "victim.yaml")
		assert.False(t, isPathContained(base, target))
	})

	t.Run("absolute path outside base is rejected", func(t *testing.T) {
		base := t.TempDir()
		outside := t.TempDir()
		victim := filepath.Join(outside, "victim.yaml")
		require.NoError(t, os.WriteFile(victim, []byte("x"), 0o600))

		assert.False(t, isPathContained(base, victim))
	})

	t.Run("plain subpath is contained", func(t *testing.T) {
		base := t.TempDir()
		nested := filepath.Join(base, "a", "b.yaml")
		require.NoError(t, os.MkdirAll(filepath.Dir(nested), 0o750))
		require.NoError(t, os.WriteFile(nested, []byte("x"), 0o600))

		assert.True(t, isPathContained(base, nested))
	})

	t.Run("base equals target", func(t *testing.T) {
		base := t.TempDir()
		assert.True(t, isPathContained(base, base))
	})

	t.Run("nonexistent target is rejected, not silently allowed", func(t *testing.T) {
		base := t.TempDir()
		assert.False(t, isPathContained(base, filepath.Join(base, "ghost.yaml")))
	})

	// Regression for the symlink bypass found in review: filepath.Rel is
	// purely lexical, so a symlink inside base pointing outside it used to
	// be reported as "contained" even though writes through it land outside
	// the scanned directory.
	t.Run("symlink inside base pointing outside it is rejected", func(t *testing.T) {
		skipOnWindowsSymlink(t)
		base := t.TempDir()
		outside := t.TempDir()
		victim := filepath.Join(outside, "victim.yaml")
		require.NoError(t, os.WriteFile(victim, []byte("x"), 0o600))
		require.NoError(t, os.Symlink(outside, filepath.Join(base, "link")))

		target := filepath.Join(base, "link", "victim.yaml")
		assert.False(t, isPathContained(base, target),
			"a symlink inside base that resolves outside it must not be treated as contained")
	})

	t.Run("symlink inside base pointing back inside it is accepted", func(t *testing.T) {
		skipOnWindowsSymlink(t)
		base := t.TempDir()
		realDir := filepath.Join(base, "real")
		require.NoError(t, os.Mkdir(realDir, 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(realDir, "in.yaml"), []byte("x"), 0o600))
		require.NoError(t, os.Symlink(realDir, filepath.Join(base, "link")))

		target := filepath.Join(base, "link", "in.yaml")
		assert.True(t, isPathContained(base, target))
	})

	t.Run("dangling symlink is rejected", func(t *testing.T) {
		skipOnWindowsSymlink(t)
		base := t.TempDir()
		require.NoError(t, os.Symlink(filepath.Join(base, "does-not-exist"), filepath.Join(base, "dangling")))

		assert.False(t, isPathContained(base, filepath.Join(base, "dangling")))
	})
}

func TestSanitizeForLog(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain path unaffected", in: "a/b/c.yaml", want: "a/b/c.yaml"},
		{name: "CRLF stripped", in: "a.yaml\r\n[success] forged line", want: "a.yaml[success] forged line"},
		{name: "bare CR stripped", in: "a\rb", want: "ab"},
		{name: "bare LF stripped", in: "a\nb", want: "ab"},
		{name: "DEL stripped", in: "a\x7fb", want: "ab"},
		{name: "empty string", in: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sanitizeForLog(tt.in))
		})
	}
}

// buildDirectoryReport writes a minimal valid PostureReport JSON file whose
// scanning target is a Directory with the given basePath, and returns the
// report file's path.
func buildDirectoryReport(t *testing.T, reportDir, basePath string) string {
	t.Helper()
	report := reporthandlingv2.PostureReport{
		Metadata: reporthandlingv2.Metadata{
			ScanMetadata: reporthandlingv2.ScanMetadata{
				ScanningTarget: reporthandlingv2.Directory,
			},
			ContextMetadata: reporthandlingv2.ContextMetadata{
				DirectoryContextMetadata: &reporthandlingv2.DirectoryContextMetadata{
					BasePath: basePath,
				},
			},
		},
	}
	b, err := json.Marshal(report)
	require.NoError(t, err)
	reportFile := filepath.Join(reportDir, "scan.json")
	require.NoError(t, os.WriteFile(reportFile, b, 0o600))
	return reportFile
}

func TestNewFixHandler_NoBasePathFlag_TrustsReportsOwnPath(t *testing.T) {
	// Documents current, unchanged-by-default behavior: without --base-path,
	// the report's own recorded scan location is trusted regardless of where
	// the report file itself lives - exactly as before this fix.
	reportDir := t.TempDir()
	scannedDir := t.TempDir()
	reportFile := buildDirectoryReport(t, reportDir, scannedDir)

	h, err := NewFixHandler(&metav1.FixInfo{ReportFile: reportFile})
	require.NoError(t, err)
	assert.Equal(t, scannedDir, h.localBasePath)
}

func TestNewFixHandler_BasePathFlag_RejectsReportPathOutsideBasePath(t *testing.T) {
	// The core anchoring fix: when --base-path is set, a report can no
	// longer point kubescape fix at an arbitrary directory just by setting
	// its own basePath - it must resolve inside the caller-supplied root.
	reportDir := t.TempDir()
	attackerChosenDir := t.TempDir()
	trustedRoot := t.TempDir()
	reportFile := buildDirectoryReport(t, reportDir, attackerChosenDir)

	h, err := NewFixHandler(&metav1.FixInfo{ReportFile: reportFile, BasePath: trustedRoot})
	assert.Error(t, err)
	assert.Nil(t, h)
	assert.ErrorContains(t, err, "outside --base-path")
}

func TestNewFixHandler_BasePathFlag_AcceptsReportPathInsideBasePath(t *testing.T) {
	trustedRoot := t.TempDir()
	scannedDir := filepath.Join(trustedRoot, "subdir")
	require.NoError(t, os.Mkdir(scannedDir, 0o750))
	reportFile := buildDirectoryReport(t, trustedRoot, scannedDir)

	h, err := NewFixHandler(&metav1.FixInfo{ReportFile: reportFile, BasePath: trustedRoot})
	require.NoError(t, err)
	resolvedScannedDir, err := filepath.EvalSymlinks(scannedDir)
	require.NoError(t, err, "failed to resolve symlinks in test dir (needed on macOS)")
	assert.Equal(t, resolvedScannedDir, h.localBasePath)
}

func TestNewFixHandler_BasePathFlag_ReportPathEqualsBasePathIsAccepted(t *testing.T) {
	trustedRoot := t.TempDir()
	reportFile := buildDirectoryReport(t, trustedRoot, trustedRoot)

	h, err := NewFixHandler(&metav1.FixInfo{ReportFile: reportFile, BasePath: trustedRoot})
	require.NoError(t, err)
	resolvedTrustedRoot, err := filepath.EvalSymlinks(trustedRoot)
	require.NoError(t, err, "failed to resolve symlinks in test dir (needed on macOS)")
	assert.Equal(t, resolvedTrustedRoot, h.localBasePath)
}

func TestNewFixHandler_BasePathFlag_InvalidBasePathErrors(t *testing.T) {
	reportDir := t.TempDir()
	scannedDir := t.TempDir()
	reportFile := buildDirectoryReport(t, reportDir, scannedDir)

	h, err := NewFixHandler(&metav1.FixInfo{ReportFile: reportFile, BasePath: filepath.Join(reportDir, "does-not-exist")})
	assert.Error(t, err)
	assert.Nil(t, h)
	assert.ErrorContains(t, err, "invalid --base-path")
}

// TestPrepareResourcesToFix_SymlinkEscapeIsSkipped reproduces the second
// review bypass: a symlink inside the scanned directory pointing outside it.
// Before the isPathContained fix, this was accepted as "contained" (lexical
// check only) and ApplyChanges would write through the symlink to the file
// outside the scanned tree. This holds even for a fully trusted report/base
// path - e.g. scanning a cloned third-party repo containing such a symlink.
func TestPrepareResourcesToFix_SymlinkEscapeIsSkipped(t *testing.T) {
	skipOnWindowsSymlink(t)
	ctx := context.Background()

	base := t.TempDir()
	outside := t.TempDir()
	victimContent := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\nspec:\n  hostNetwork: true\n"
	victim := filepath.Join(outside, "victim.yaml")
	require.NoError(t, os.WriteFile(victim, []byte(victimContent), 0o600))
	require.NoError(t, os.Symlink(outside, filepath.Join(base, "link")))

	res := buildResource(t, base, filepath.Join("link", "victim.yaml"), "Pod", "x", 0)
	results := []resourcesresults.Result{
		{
			ResourceID:  res.GetID(),
			RawResource: res,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				failedControl("C-0001", "host network", failedRuleWithFix("spec.hostNetwork", "false")),
			},
		},
	}

	h := newHandlerForResources(base, results, []reporthandling.Resource{*res}, false)
	toFix := h.PrepareResourcesToFix(ctx)

	assert.Empty(t, toFix, "resource path escaping the scanned directory via a symlink must not be accepted")
	require.Len(t, h.UnfixedControls(), 1)
	assert.Equal(t, "skipped: resource path escapes scanned directory", h.UnfixedControls()[0].Reason)

	unchanged, err := os.ReadFile(victim)
	require.NoError(t, err)
	assert.Equal(t, victimContent, string(unchanged), "file outside the scanned directory must not be modified")
}
