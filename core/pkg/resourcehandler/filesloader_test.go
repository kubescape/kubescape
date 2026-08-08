package resourcehandler

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gitv5 "github.com/go-git/go-git/v5"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Initializes a new instance of FileResourceHandler.
func TestNewFileResourceHandler_InitializesNewInstance(t *testing.T) {
	fileHandler := NewFileResourceHandler()
	assert.NotNil(t, fileHandler)
}

// This is deliberately a FileResourceHandler test rather than another parser
// count assertion: list items must survive manifest loading, offline resource
// resolution, and policy filtering before they become OPA input.
func TestFileResourceHandlerIndexesListEnvelopeItemsForPolicies(t *testing.T) {
	tests := []struct {
		name      string
		extension string
		manifest  string
		wantByGVR map[string]string
		wantNames map[string]string
	}{
		{
			name:      "JSON generic List",
			extension: "json",
			manifest: `{
  "apiVersion": "v1",
  "kind": "List",
  "items": [
    {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "listed-pod", "namespace": "default"}},
    {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "listed-service", "namespace": "default"}}
  ]
}`,
			wantByGVR: map[string]string{
				"/v1/pods":     "Pod",
				"/v1/services": "Service",
			},
			wantNames: map[string]string{
				"/v1/pods":     "listed-pod",
				"/v1/services": "listed-service",
			},
		},
		{
			name:      "JSON typed list",
			extension: "json",
			manifest: `{
  "apiVersion": "v1",
  "kind": "PodList",
  "items": [
    {"metadata": {"name": "json-typed-pod", "namespace": "default"}}
  ]
}`,
			wantByGVR: map[string]string{"/v1/pods": "Pod"},
			wantNames: map[string]string{"/v1/pods": "json-typed-pod"},
		},
		{
			name:      "YAML typed list",
			extension: "yaml",
			manifest: `apiVersion: v1
kind: PodList
items:
  - metadata:
      name: yaml-typed-pod
      namespace: default
`,
			wantByGVR: map[string]string{"/v1/pods": "Pod"},
			wantNames: map[string]string{"/v1/pods": "yaml-typed-pod"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifestPath := filepath.Join(t.TempDir(), "resources."+tt.extension)
			require.NoError(t, os.WriteFile(manifestPath, []byte(tt.manifest), 0o600))

			match := reporthandling.RuleMatchObjects{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"pods", "services"},
			}
			framework := *mockFramework("list-envelope-input", []reporthandling.Control{
				mockControl("list-envelope-input", []reporthandling.PolicyRule{
					mockRule("list-envelope-input", []reporthandling.RuleMatchObjects{match}, ""),
				}),
			})
			scanInfo := &cautils.ScanInfo{InputPatterns: []string{manifestPath}}
			session := cautils.NewOPASessionObj(
				context.Background(), []reporthandling.Framework{framework}, nil, scanInfo, nil,
			)

			resources, allResources, _, _, err := NewFileResourceHandler().GetResources(
				context.Background(), session, scanInfo,
			)
			require.NoError(t, err)
			require.Len(t, allResources, len(tt.wantByGVR))

			for gvr, wantKind := range tt.wantByGVR {
				require.Lenf(t, resources[gvr], 1, "expected %s in policy input %s", wantKind, gvr)
				resourceID := resources[gvr][0]
				resource, ok := allResources[resourceID]
				require.Truef(t, ok, "policy input %s referenced missing resource %s", gvr, resourceID)
				assert.Equal(t, wantKind, resource.GetKind())
				assert.Equal(t, "v1", resource.GetApiVersion())
				assert.Equal(t, tt.wantNames[gvr], resource.GetName())
			}
		})
	}
}

// A single-file scan must yield a repository-relative RelativePath: the SARIF and GitLab SAST printers build the finding's file location from it, and the GitLab printer drops findings whose path is empty, absolute, or escaping the repo root. See #2496.
func TestGetResourcesFromPath_SingleFileRelativePathIsRepositoryRelative(t *testing.T) {
	workloadIDToSource, workloads, err := getResourcesFromPath(context.TODO(), "../../cautils/testdata/mixed_extensions/pod.yaml", cautils.HelmValueOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, workloads, "the single-file scan must discover the pod")

	for _, w := range workloads {
		src, ok := workloadIDToSource[w.GetID()]
		require.True(t, ok, "every workload must have a source")

		rel := src.RelativePath
		assert.NotEmpty(t, rel, "RelativePath must be set or the finding has no file to anchor to")
		assert.False(t, filepath.IsAbs(rel), "RelativePath must be repository-relative, not absolute: %q", rel)
		cleaned := filepath.ToSlash(filepath.Clean(rel))
		assert.False(t, cleaned == ".." || strings.HasPrefix(cleaned, "../"),
			"RelativePath must not escape the repository root: %q", rel)
		assert.Equal(t, "pod.yaml", filepath.Base(rel))
	}
}

// newRepoWithUnusableGitMetadata builds a repository that go-git can locate but
// NewLocalGitRepository rejects (unborn HEAD, no remotes), as a CI checkout often is,
// and writes manifestPath inside it.
func newRepoWithUnusableGitMetadata(t *testing.T, manifestPath string) string {
	t.Helper()

	repoRoot, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	_, err = gitv5.PlainInit(repoRoot, false)
	require.NoError(t, err)

	_, err = cautils.NewLocalGitRepository(repoRoot)
	require.Error(t, err, "the repository's git metadata must be unusable for this test to mean anything")

	absManifest := filepath.Join(repoRoot, filepath.FromSlash(manifestPath))
	require.NoError(t, os.MkdirAll(filepath.Dir(absManifest), 0o750))
	require.NoError(t, os.WriteFile(absManifest, []byte(singlePodManifest), 0o600))

	return repoRoot
}

// TestGetResourcesFromPath_AnchorsOnRepositoryRootWithoutUsableGitMetadata verifies
// that a scan reports paths relative to the repository root even when the
// repository's branch and remote metadata is unusable. A CI checkout with a detached
// HEAD or no configured remote is still a repository, and anchoring on the scan path
// instead drops the prefix, leaving GitLab and GitHub with findings that point at
// paths the repository does not contain.
func TestGetResourcesFromPath_AnchorsOnRepositoryRootWithoutUsableGitMetadata(t *testing.T) {
	const manifest = "workloads/apps/base/app/cronjobs.yaml"

	tests := []struct {
		name     string
		scanPath string
	}{
		{name: "directory scan", scanPath: "workloads"},
		{name: "single file scan", scanPath: manifest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoRoot := newRepoWithUnusableGitMetadata(t, manifest)

			workloadIDToSource, workloads, err := getResourcesFromPath(context.TODO(), filepath.Join(repoRoot, filepath.FromSlash(tt.scanPath)), cautils.HelmValueOptions{})
			require.NoError(t, err)
			require.NotEmpty(t, workloads)

			for _, w := range workloads {
				src, ok := workloadIDToSource[w.GetID()]
				require.True(t, ok, "every workload must have a source")
				assert.Equal(t, manifest, filepath.ToSlash(src.RelativePath), "the path must be relative to the repository root, not the scan path")
				assert.Equal(t, repoRoot, src.Path, "Source.Path must be the root RelativePath resolves against")
			}
		})
	}
}

const singlePodManifest = `apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: nginx
    image: nginx:1.14.2
`

// A chart whose helm render fails must still have its static templates plain-scanned. The render is
// best-effort and drops the whole chart on any template error, so excluding templates/ unconditionally
// would make those resources reach neither loader and vanish silently. Regression guard for the #2501
// review: templates/ is excluded only for charts that rendered without errors.
func TestGetResourcesFromPath_ScansTemplatesOfChartThatFailedToRender(t *testing.T) {
	_, workloads, err := getResourcesFromPath(context.TODO(), "../../cautils/testdata/helm_chart_broken", cautils.HelmValueOptions{})
	require.NoError(t, err)

	var found bool
	for _, w := range workloads {
		if w.GetKind() == "ServiceAccount" && w.GetName() == "important-sa" {
			found = true
		}
	}
	assert.True(t, found, "a static template of a chart that failed to render must still be scanned")
}

func createMockGitRepo(t *testing.T, hasOrigin bool) string {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	require.NoError(t, os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/master\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "refs", "heads", "master"), []byte("0000000000000000000000000000000000000000\n"), 0o600))

	configContent := `[core]
	repositoryformatversion = 0
[remote "upstream"]
	url = https://example.com/upstream.git
`
	if hasOrigin {
		configContent += `[remote "origin"]
	url = https://example.com/origin.git
`
	}
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "config"), []byte(configContent), 0o600))
	return dir
}

func TestResolveHelmRemotePath(t *testing.T) {
	healthyRepo := createMockGitRepo(t, true)
	gitHealthy, err := cautils.NewLocalGitRepository(healthyRepo)
	require.NoError(t, err)

	brokenRepo := createMockGitRepo(t, false)
	gitBroken, err := cautils.NewLocalGitRepository(brokenRepo)
	require.NoError(t, err)

	tests := []struct {
		name       string
		clonedRepo string
		gitRepo    *cautils.LocalGitRepository
		want       string
	}{
		{
			name:       "empty clonedRepo",
			clonedRepo: "",
			gitRepo:    gitHealthy,
			want:       "",
		},
		{
			name:       "nil gitRepo",
			clonedRepo: "some-repo",
			gitRepo:    nil,
			want:       "",
		},
		{
			name:       "repo whose remote lookup fails",
			clonedRepo: "some-repo",
			gitRepo:    gitBroken,
			want:       "",
		},
		{
			name:       "healthy repo",
			clonedRepo: "some-repo",
			gitRepo:    gitHealthy,
			want:       "https://example.com/origin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveHelmRemotePath(tt.clonedRepo, tt.gitRepo)
			assert.Equal(t, tt.want, got)
		})
	}
}

// A chart that renders cleanly has its templates covered by the render, so the plain-YAML loader must
// not scan them again (no duplicate, no malformed-template warnings), while crds/ and files outside
// templates/ stay plainly scanned.
func TestGetResourcesFromPath_RenderedChartTemplatesLoadedOnce(t *testing.T) {
	_, workloads, err := getResourcesFromPath(context.TODO(), "../../cautils/testdata/helm_chart_layout", cautils.HelmValueOptions{})
	require.NoError(t, err)

	counts := map[string]int{}
	for _, w := range workloads {
		counts[w.GetKind()+"/"+w.GetName()]++
	}

	// rendered exactly once by helm, never re-scanned as a raw template
	assert.Equal(t, 1, counts["ServiceAccount/mychart-static"], "static template must be loaded once, by the render")
	assert.Equal(t, 1, counts["Deployment/-mychart"], "templated deployment must come from the render")
	assert.Equal(t, 1, counts["Service/-mysubchart"], "subchart template must come from the render")
	// not rendered by helm, so still plainly scanned
	assert.Equal(t, 1, counts["CustomResourceDefinition/widgets.example.com"], "crds/ must stay plainly scanned")
	assert.Equal(t, 1, counts["Pod/plain-outside-chart"], "files outside the chart must stay plainly scanned")
}

// Deduplicates resources discovered by both kustomize render and the plain-YAML glob.
func TestGetResourcesFromPath_DeduplicatesKustomizeAndPlainYaml(t *testing.T) {
	workloadIDToSource, workloads, err := getResourcesFromPath(context.TODO(), "../../cautils/testdata/kustomize/base", cautils.HelmValueOptions{})
	require.NoError(t, err)

	var deployments []string
	for _, w := range workloads {
		if w.GetKind() == "Deployment" {
			deployments = append(deployments, w.GetID())
		}
	}

	require.Len(t, deployments, 1)
	assert.Equal(t, reporthandling.SourceTypeKustomizeDirectory, workloadIDToSource[deployments[0]].FileType)
}

// Kustomize transformers mutate identity fields, so path-based exclusion (not identity dedup) must keep the result single.
func TestGetResourcesFromPath_KustomizeTransformersDoNotDuplicate(t *testing.T) {
	workloadIDToSource, workloads, err := getResourcesFromPath(context.TODO(), "../../cautils/testdata/kustomize/transformed", cautils.HelmValueOptions{})
	require.NoError(t, err)

	var deploymentIDs []string
	var deployment workloadinterface.IMetadata
	for _, w := range workloads {
		if w.GetKind() == "Deployment" {
			deploymentIDs = append(deploymentIDs, w.GetID())
			deployment = w
		}
	}

	require.Len(t, deploymentIDs, 1)
	assert.Equal(t, reporthandling.SourceTypeKustomizeDirectory, workloadIDToSource[deploymentIDs[0]].FileType)
	assert.Equal(t, "production", deployment.GetNamespace())
	assert.Equal(t, "prod-test-app", deployment.GetName())
}

func TestGetResourcesFromPathRejectsDirectoryWithoutKubernetesResources(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "values.yaml"), []byte("replicas: 3\n"), 0o600))

	sources, workloads, err := getResourcesFromPath(context.Background(), dir, cautils.HelmValueOptions{})

	require.Error(t, err)
	assert.Nil(t, sources)
	assert.Nil(t, workloads)
	assert.Contains(t, err.Error(), "no scannable Kubernetes resources")
}

func TestGetResourcesFromPathPropagatesKustomizeFailure(t *testing.T) {
	dir := t.TempDir()
	kustomization := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - missing.yaml
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(kustomization), 0o600))

	sources, workloads, err := getResourcesFromPath(context.Background(), dir, cautils.HelmValueOptions{})

	require.Error(t, err)
	assert.Nil(t, sources)
	assert.Nil(t, workloads)
	assert.Contains(t, err.Error(), "failed to render Kustomize resources")
}
