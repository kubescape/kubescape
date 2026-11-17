package lsp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/locationresolver"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.lsp.dev/protocol"
)

func TestSeverityOf(t *testing.T) {
	tests := []struct {
		factor float32
		want   protocol.DiagnosticSeverity
	}{
		{10, protocol.DiagnosticSeverityError}, // critical
		{9, protocol.DiagnosticSeverityError},
		{8, protocol.DiagnosticSeverityError}, // high
		{7, protocol.DiagnosticSeverityError},
		{6, protocol.DiagnosticSeverityWarning}, // medium
		{4, protocol.DiagnosticSeverityWarning},
		{3, protocol.DiagnosticSeverityInformation}, // low
		{1, protocol.DiagnosticSeverityInformation},
		{0, protocol.DiagnosticSeverityInformation}, // unknown
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, severityOf(tt.factor), "score factor %v", tt.factor)
	}
}

func TestToPositionConvertsToZeroBasedUTF16(t *testing.T) {
	m := &manifest{lines: splitLines("kind: Pod\n  name: nginx\n\tname: tab\nname: héllo wörld\nname: 😀 emoji\n")}
	tests := []struct {
		name string
		loc  locationresolver.Location
		want protocol.Position
	}{
		{"first column of the first line", locationresolver.Location{Line: 1, Column: 1}, protocol.Position{Line: 0, Character: 0}},
		{"1-based column becomes 0-based", locationresolver.Location{Line: 2, Column: 3}, protocol.Position{Line: 1, Character: 2}},
		{"a tab is one character", locationresolver.Location{Line: 3, Column: 2}, protocol.Position{Line: 2, Character: 1}},
		{"a two-byte rune is one UTF-16 unit", locationresolver.Location{Line: 4, Column: 12}, protocol.Position{Line: 3, Character: 11}},
		{"a character outside the BMP is two units", locationresolver.Location{Line: 5, Column: 8}, protocol.Position{Line: 4, Character: 8}},
		{"the column after an emoji counts it as two units", locationresolver.Location{Line: 5, Column: 9}, protocol.Position{Line: 4, Character: 9}},
		{"a column past the end is clamped to the line", locationresolver.Location{Line: 1, Column: 99}, protocol.Position{Line: 0, Character: 9}},
		{"a line past the end is clamped to the last", locationresolver.Location{Line: 99, Column: 1}, protocol.Position{Line: 5, Character: 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, m.toPosition(tt.loc))
		})
	}
}

func TestUTF16Offset(t *testing.T) {
	assert.Equal(t, uint32(0), utf16Offset("abc", 0))
	assert.Equal(t, uint32(2), utf16Offset("abc", 2))
	assert.Equal(t, uint32(3), utf16Offset("abc", 10), "past the end is the end")
	assert.Equal(t, uint32(3), utf16Offset("a😀b", 2), "an emoji is two units")
	assert.Equal(t, uint32(2), utf16Offset("éé", 2), "é is one unit though two bytes")
	assert.Equal(t, uint32(4), utf16Len("a😀b"))
}

func TestSplitLines(t *testing.T) {
	assert.Equal(t, []string{"a", "b", "c", "d", ""}, splitLines("a\nb\r\nc\rd\n"))
}

func TestSortDiagnosticsIsStable(t *testing.T) {
	d := func(line, ch uint32, code, msg string) protocol.Diagnostic {
		return protocol.Diagnostic{
			Range:   protocol.Range{Start: protocol.Position{Line: line, Character: ch}},
			Code:    protocol.String(code),
			Message: protocol.String(msg),
		}
	}
	got := []protocol.Diagnostic{d(5, 0, "C-2", "b"), d(1, 4, "C-9", "z"), d(1, 4, "C-1", "z"), d(1, 0, "C-5", "a"), d(1, 4, "C-1", "a")}
	sortDiagnostics(got)
	var order []string
	for _, x := range got {
		order = append(order, codeString(x)+messageString(x))
	}
	assert.Equal(t, []string{"C-5a", "C-1a", "C-1z", "C-9z", "C-2b"}, order)
}

func TestDocumentIndex(t *testing.T) {
	assert.Equal(t, 0, mustIndex(t, fakeWorkload{"/repo/pod.yaml:0"}))
	assert.Equal(t, 3, mustIndex(t, fakeWorkload{"/repo/pod.yaml:3"}))
	_, ok := documentIndex(fakeWorkload{"/repo/pod.yaml"})
	assert.False(t, ok)
	_, ok = documentIndex(fakeWorkload{"/repo/pod.yaml:abc"})
	assert.False(t, ok)
	_, ok = documentIndex(nil)
	assert.False(t, ok)
}

func mustIndex(t *testing.T, w fakeWorkload) int {
	t.Helper()
	i, ok := documentIndex(w)
	require.True(t, ok)
	return i
}

// The scanner's real output, converted: where a finding is, how severe, and
// what it says.
func TestFindingsOfARealScan(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "pod.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte(podManifest("web", false)), 0o600))

	findings := scanForTest(t, dir)
	require.True(t, findings.complete)
	diagnostics := findings.byFile[manifestPath]
	require.Len(t, diagnostics, 1, "the one control that was asked for fails once")
	d := diagnostics[0]

	assert.Equal(t, protocol.String("C-0017"), d.Code)
	assert.Equal(t, protocol.NewOptional("kubescape"), d.Source)
	assert.Equal(t, protocol.DiagnosticSeverityInformation, d.Severity, "C-0017 has a low score factor (3) in the test policies")
	assert.Contains(t, messageString(d), "Immutable container filesystem")
	assert.Contains(t, messageString(d), "Pod/web")
	assert.NotContains(t, messageString(d), dir, "no filesystem path in a message")
	assert.Equal(t, d.Range.Start, d.Range.End, "the resolver gives a start and no end, so the range is zero-width")

	// The position is the container that fails the control: line 8 of the
	// manifest, "  - name: c", which is zero-based line 7.
	lines := splitLines(podManifest("web", false))
	require.Less(t, int(d.Range.Start.Line), len(lines))
	assert.Equal(t, "  - name: c", lines[d.Range.Start.Line])
}

func TestFindingsOfAScanWithNothingToReport(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pod.yaml"), []byte(podManifest("web", true)), 0o600))
	findings := scanForTest(t, dir)
	assert.True(t, findings.complete)
	assert.Empty(t, findings.byFile, "a clean manifest has no diagnostics, and the scan is complete")
}

func TestFindingsOfAMalformedManifestAreUnreliableNotResolved(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "pod.yaml")
	bad := filepath.Join(dir, "broken.yaml")
	require.NoError(t, os.WriteFile(good, []byte(podManifest("web", false)), 0o600))
	require.NoError(t, os.WriteFile(bad, []byte("kind: Pod\n  : : not yaml [\n"), 0o600))

	findings := scanForTest(t, dir)
	assert.Contains(t, findings.unreliable, pathKey(bad), "a manifest the scan could not load is not a clean one")
	assert.Len(t, findings.byFile[good], 1, "the other manifests are still reported")
}

// podManifest is a pod that fails C-0017 unless it sets a read-only root filesystem.
func podManifest(name string, readOnly bool) string {
	manifest := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: " + name + "\n  namespace: default\nspec:\n  containers:\n  - name: c\n    image: nginx\n"
	if readOnly {
		manifest += "    securityContext:\n      readOnlyRootFilesystem: true\n"
	}
	return manifest
}

// realScanner is the real scanner, with one control and the policies in the
// repository's testdata, so that no network is needed.
func realScanner(t *testing.T) *core.LocalScanner {
	t.Helper()
	abs := func(parts ...string) string {
		p, err := filepath.Abs(filepath.Join(parts...))
		require.NoError(t, err)
		return p
	}
	info := &cautils.ScanInfo{
		UseFrom:         []string{abs("..", "..", "cautils", "getter", "testdata", "NSA.json")},
		UseExceptions:   abs("..", "..", "core", "testdata", "empty_exceptions.json"),
		ControlsInputs:  abs("..", "..", "cautils", "getter", "testdata", "controls-inputs.json"),
		Local:           true,
		NoClusterAccess: true,
	}
	info.SetScanType(cautils.ScanTypeControl)
	scanner, err := (&core.Kubescape{Ctx: context.Background()}).NewLocalScanner(info, cautils.BuildPolicyIdentifiers([]string{"C-0017"}, apisv1.KindControl))
	require.NoError(t, err)
	return scanner
}

func scanForTest(t *testing.T, dir string) scanFindings {
	t.Helper()
	findings, err := scanWith(realScanner(t))(context.Background(), []string{dir})
	require.NoError(t, err)
	return findings
}
