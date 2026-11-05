package scan_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	gitv5 "github.com/go-git/go-git/v5"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var safeManifest = strings.ReplaceAll(privilegedManifest, "privileged: true", "privileged: false")

// Outside git each input is its own root. Two manifests with the same relative
// path and the same Kubernetes identity got the same resource ID, so whichever
// input came last replaced the other before evaluation.
func TestScanPreservesIndependentManifestSourcesAcrossInputRoots(t *testing.T) {
	root := tempDir(t)
	writeManifestSource(t, filepath.Join(root, "dev", "deployment.yaml"), privilegedManifest)
	writeManifestSource(t, filepath.Join(root, "prod", "deployment.yaml"), safeManifest)
	dev, prod := filepath.Join(root, "dev"), filepath.Join(root, "prod")

	var ids [][]string
	for _, inputs := range [][]string{{dev, prod}, {prod, dev}} {
		report, err := scanManifestSources(t, inputs...)

		assert.ErrorContains(t, err, "scan compliance-score is below permitted threshold")
		assert.Equal(t, map[string]string{
			"dev/deployment.yaml":  "failed",
			"prod/deployment.yaml": "passed",
		}, manifestSourceStatuses(t, report))
		assert.Equal(t, float32(50), report.SummaryDetails.ComplianceScore)
		assertSourcesResolveToScannedFiles(t, report)
		ids = append(ids, resourceIDs(report))
	}
	assert.Equal(t, ids[0], ids[1], "input order must not change resource IDs")
}

func TestScanKeepsManifestsOfDifferentInputRootsApart(t *testing.T) {
	multiDocument := func(deployment string) string {
		return "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\n  namespace: default\n---\n" + deployment
	}
	for _, tc := range []struct {
		name       string
		files      map[string]string
		inputs     []string
		gitRepos   []string
		want       map[string]string
		compliance float32
	}{
		{
			name: "three roots",
			files: map[string]string{
				"a/deployment.yaml": privilegedManifest,
				"b/deployment.yaml": safeManifest,
				"c/deployment.yaml": safeManifest,
			},
			inputs:     []string{"c", "a", "b"},
			want:       map[string]string{"a/deployment.yaml": "failed", "b/deployment.yaml": "passed", "c/deployment.yaml": "passed"},
			compliance: float32(200) / 3,
		},
		{
			name: "directory and file",
			files: map[string]string{
				"dev/deployment.yaml":  privilegedManifest,
				"prod/deployment.yaml": safeManifest,
			},
			inputs: []string{"prod/deployment.yaml", "dev"},
			want:   map[string]string{"dev/deployment.yaml": "failed", "prod/deployment.yaml": "passed"},
		},
		{
			name: "equal nested subpaths",
			files: map[string]string{
				"team1/k8s/deployment.yaml": privilegedManifest,
				"team2/k8s/deployment.yaml": safeManifest,
			},
			inputs: []string{"team2/k8s", "team1/k8s"},
			want:   map[string]string{"team1/k8s/deployment.yaml": "failed", "team2/k8s/deployment.yaml": "passed"},
		},
		{
			// base/overlay is read through both inputs and must be counted once.
			name: "one root inside another",
			files: map[string]string{
				"base/deployment.yaml":         privilegedManifest,
				"base/overlay/deployment.yaml": safeManifest,
			},
			inputs: []string{"base", "base/overlay"},
			want:   map[string]string{"deployment.yaml": "failed", "overlay/deployment.yaml": "passed"},
		},
		{
			name: "different git repositories",
			files: map[string]string{
				"repo-a/deployment.yaml": privilegedManifest,
				"repo-b/deployment.yaml": safeManifest,
			},
			gitRepos: []string{"repo-a", "repo-b"},
			inputs:   []string{"repo-b", "repo-a"},
			want:     map[string]string{"repo-a/deployment.yaml": "failed", "repo-b/deployment.yaml": "passed"},
		},
		{
			name: "multiple documents at the same index",
			files: map[string]string{
				"dev/all.yaml":  multiDocument(privilegedManifest),
				"prod/all.yaml": multiDocument(safeManifest),
			},
			inputs: []string{"prod", "dev"},
			want:   map[string]string{"dev/all.yaml": "failed", "prod/all.yaml": "passed"},
		},
		{
			name: "multiple documents at different indices",
			files: map[string]string{
				"dev/all.yaml":  privilegedManifest,
				"prod/all.yaml": multiDocument(safeManifest),
			},
			inputs: []string{"prod", "dev"},
			want:   map[string]string{"dev/all.yaml": "failed", "prod/all.yaml": "passed"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := tempDir(t)
			for name, contents := range tc.files {
				writeManifestSource(t, filepath.Join(root, filepath.FromSlash(name)), contents)
			}
			for _, repo := range tc.gitRepos {
				_, err := gitv5.PlainInit(filepath.Join(root, repo), false)
				require.NoError(t, err)
			}
			inputs := make([]string, len(tc.inputs))
			for i, input := range tc.inputs {
				inputs[i] = filepath.Join(root, filepath.FromSlash(input))
			}

			report, err := scanManifestSources(t, inputs...)

			assert.ErrorContains(t, err, "scan compliance-score is below permitted threshold")
			assert.Equal(t, tc.want, manifestSourceStatuses(t, report))
			compliance := tc.compliance
			if compliance == 0 {
				compliance = 50
			}
			assert.InDelta(t, compliance, report.SummaryDetails.ComplianceScore, 0.01)
			assertSourcesResolveToScannedFiles(t, report)
		})
	}
}

// Resource IDs feed baselines and diffs, so scans with a single root must keep
// them, and a scan of several roots gets the IDs its parent directory already had.
func TestScanKeepsResourceIDsOfSingleRootScans(t *testing.T) {
	root := tempDir(t)
	writeManifestSource(t, filepath.Join(root, "dev", "deployment.yaml"), privilegedManifest)
	writeManifestSource(t, filepath.Join(root, "prod", "deployment.yaml"), safeManifest)

	single, _ := scanManifestSources(t, filepath.Join(root, "dev"))
	assert.Equal(t, []string{workloadID("deployment.yaml:0")}, resourceIDs(single))
	assert.Equal(t, map[string]string{"deployment.yaml": "failed"}, manifestSourceStatuses(t, single))

	parent, _ := scanManifestSources(t, root)
	want := []string{workloadID("dev/deployment.yaml:0"), workloadID("prod/deployment.yaml:0")}
	sort.Strings(want)
	assert.Equal(t, want, resourceIDs(parent))

	twoRoots, _ := scanManifestSources(t, filepath.Join(root, "dev"), filepath.Join(root, "prod"))
	assert.Equal(t, want, resourceIDs(twoRoots))

	_, err := gitv5.PlainInit(root, false)
	require.NoError(t, err)
	inGit, _ := scanManifestSources(t, filepath.Join(root, "dev"), filepath.Join(root, "prod"))
	assert.Equal(t, want, resourceIDs(inGit))
	assert.Equal(t, map[string]string{
		"dev/deployment.yaml":  "failed",
		"prod/deployment.yaml": "passed",
	}, manifestSourceStatuses(t, inGit))
}

// tempDir resolves symlinks, as the git root is resolved (macOS /var is /private/var).
func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	return dir
}

func workloadID(path string) string {
	lw := localworkload.NewLocalWorkload(map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]interface{}{"name": "web", "namespace": "default"},
	})
	lw.SetPath(filepath.FromSlash(path))
	return lw.GetID()
}

func resourceIDs(report reporthandlingv2.PostureReport) []string {
	var ids []string
	for _, resource := range report.Resources {
		ids = append(ids, resource.ResourceID)
	}
	sort.Strings(ids)
	return ids
}

// assertSourcesResolveToScannedFiles checks provenance: each resource's source
// is the file it was read from, and a failing resource is the privileged one.
func assertSourcesResolveToScannedFiles(t *testing.T, report reporthandlingv2.PostureReport) {
	t.Helper()
	statuses := make(map[string]string)
	for _, result := range report.Results {
		statuses[result.ResourceID] = string(result.AssociatedControls[0].Status.InnerStatus)
	}
	for _, resource := range report.Resources {
		data, err := os.ReadFile(filepath.Join(resource.Source.Path, resource.Source.RelativePath))
		require.NoError(t, err)
		privileged := strings.Contains(string(data), "privileged: true")
		assert.Equal(t, privileged, statuses[resource.ResourceID] == "failed", resource.Source.RelativePath)
	}
}
