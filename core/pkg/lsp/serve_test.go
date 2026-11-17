package lsp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A workspace folder without manifests, next to one with them, doesn't fail the
// scan of the other.
func TestAFolderWithoutManifestsDoesNotFailTheScanOfTheOthers(t *testing.T) {
	withManifests, without := t.TempDir(), t.TempDir()
	pod := filepath.Join(withManifests, "pod.yaml")
	require.NoError(t, os.WriteFile(pod, []byte(podManifest("web", false)), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(without, "README.md"), []byte("# docs\n"), 0o600))

	findings, err := scanWith(realScanner(t))(context.Background(), []string{withManifests, without})

	require.NoError(t, err)
	assert.True(t, findings.complete)
	assert.Len(t, findings.byFile[pod], 1)
}

// Without a workspace folder the open documents are the inputs, and one with no
// Kubernetes object in it, such as a Helm values file, doesn't fail the scan.
func TestAnOpenFileWithoutKubernetesObjectsDoesNotFailTheScan(t *testing.T) {
	dir := t.TempDir()
	pod := filepath.Join(dir, "pod.yaml")
	values := filepath.Join(dir, "values.yaml")
	require.NoError(t, os.WriteFile(pod, []byte(podManifest("web", false)), 0o600))
	require.NoError(t, os.WriteFile(values, []byte("replicaCount: 1\n"), 0o600))

	findings, err := scanWith(realScanner(t))(context.Background(), []string{pod, values})

	require.NoError(t, err)
	assert.True(t, findings.complete)
	assert.Len(t, findings.byFile[pod], 1)
}

// The inputs that have something to scan are scanned together, so what one of
// them says about another is still seen; with nothing to scan anywhere, the
// scan's own error is returned.
func TestTheInputsWithSomethingToScanAreScannedTogether(t *testing.T) {
	empty := map[string]bool{"b": true}
	s := &recordingScanner{empty: empty}

	_, err := scanWith(s)(context.Background(), []string{"a", "b", "c"})

	require.NoError(t, err)
	assert.Equal(t, [][]string{{"a", "b", "c"}, {"a"}, {"b"}, {"c"}, {"a", "c"}}, s.calls)

	s = &recordingScanner{empty: map[string]bool{"a": true, "b": true}}
	_, err = scanWith(s)(context.Background(), []string{"a", "b"})
	assert.ErrorIs(t, err, cautils.ErrNoManifestFiles)
}

// recordingScanner records the inputs of every scan, and fails a scan with an
// input in empty the way the real scanner fails an input without manifests.
type recordingScanner struct {
	empty map[string]bool
	calls [][]string
}

func (s *recordingScanner) Scan(_ context.Context, in core.LocalInput) (*core.ScanResult, error) {
	s.calls = append(s.calls, slices.Clone(in.Paths))
	for _, path := range in.Paths {
		if s.empty[path] {
			return nil, fmt.Errorf("%w for input %q", cautils.ErrNoManifestFiles, path)
		}
	}
	return &core.ScanResult{Coverage: cautils.ScanCoverage{TotalControls: 1}}, nil
}
