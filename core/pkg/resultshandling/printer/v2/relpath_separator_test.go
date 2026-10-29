package printer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/require"
)

// The privileged field in ghSessionFixture's manifest.
const nestedManifestPrivilegedLine = 13

// nestedManifestSession moves the fixture manifest to k8s/prod/deploy.yaml and
// records its relative path with the OS separator, as filesloader does through
// filepath.Rel. On Windows that path is k8s\prod\deploy.yaml.
func nestedManifestSession(t *testing.T) *cautils.OPASessionObj {
	t.Helper()
	session := ghSessionFixture(t, "C-0057", 8.0)
	for id, src := range session.ResourceSource {
		dir := filepath.Join(src.Path, "k8s", "prod")
		require.NoError(t, os.MkdirAll(dir, 0o750))
		require.NoError(t, os.Rename(filepath.Join(src.Path, src.RelativePath), filepath.Join(dir, "deploy.yaml")))
		src.RelativePath = filepath.Join("k8s", "prod", "deploy.yaml")
		session.ResourceSource[id] = src
	}
	return session
}

// Reports must use "/" separators on every OS, while the manifest is still
// read from its native path, so line numbers keep resolving.
func TestSARIFPrinter_RelativePathUsesForwardSlashes(t *testing.T) {
	session := nestedManifestSession(t)

	tmp, err := os.CreateTemp(t.TempDir(), "relpath-*.sarif")
	require.NoError(t, err)
	sp := NewSARIFPrinter(false)
	sp.writer = tmp
	require.NoError(t, sp.printConfigurationScan(context.Background(), session))
	require.NoError(t, tmp.Close())

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)
	var report struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				Fixes []struct {
					ArtifactChanges []struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Replacements []struct {
							DeletedRegion struct {
								StartLine int `json:"startLine"`
							} `json:"deletedRegion"`
						} `json:"replacements"`
					} `json:"artifactChanges"`
				} `json:"fixes"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(raw, &report))
	require.Len(t, report.Runs, 1)
	require.Len(t, report.Runs[0].Results, 1)
	result := report.Runs[0].Results[0]

	require.Len(t, result.Locations, 1)
	require.Equal(t, "k8s/prod/deploy.yaml", result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	require.Equal(t, nestedManifestPrivilegedLine, result.Locations[0].PhysicalLocation.Region.StartLine)

	require.NotEmpty(t, result.Fixes, "the fix is computed from the manifest on disk")
	for _, fix := range result.Fixes {
		require.NotEmpty(t, fix.ArtifactChanges)
		for _, change := range fix.ArtifactChanges {
			require.Equal(t, "k8s/prod/deploy.yaml", change.ArtifactLocation.URI)
			require.NotEmpty(t, change.Replacements)
			require.Equal(t, nestedManifestPrivilegedLine, change.Replacements[0].DeletedRegion.StartLine)
		}
	}
}

func TestGitHubActionsPrinter_RelativePathUsesForwardSlashes(t *testing.T) {
	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()
	require.NoError(t, os.Chdir(t.TempDir()))

	output := ghOutputFor(t, nestedManifestSession(t))

	firstLine := strings.SplitN(output, "\n", 2)[0]
	require.True(t,
		strings.HasPrefix(firstLine, fmt.Sprintf("::error file=k8s/prod/deploy.yaml,line=%d,title=C-0057 Privileged container::", nestedManifestPrivilegedLine)),
		"unexpected annotation: %s", firstLine)
}

func TestGitLabSASTPrinter_RelativePathUsesForwardSlashes(t *testing.T) {
	report := gitLabReportFor(t, nestedManifestSession(t))

	require.Len(t, report.Vulnerabilities, 1)
	require.Equal(t, "k8s/prod/deploy.yaml", report.Vulnerabilities[0].Location.File)
	require.Equal(t, nestedManifestPrivilegedLine, report.Vulnerabilities[0].Location.StartLine)
}
