package resourcehandler

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func TestGetResourcesFromURL(t *testing.T) {
	t.Run("non-Git URL returns error", func(t *testing.T) {
		// Test with a non-Git URL
		url := "https://example.com/not-a-git-repo"

		sources, workloads, err := getResourcesFromURL(context.Background(), url)

		// Should return error for non-Git URLs or when resources can't be loaded
		assert.Error(t, err)
		assert.Nil(t, sources)
		assert.Nil(t, workloads)
	})

	t.Run("empty URL returns error", func(t *testing.T) {
		url := ""

		sources, workloads, err := getResourcesFromURL(context.Background(), url)

		assert.Error(t, err)
		assert.Nil(t, sources)
		assert.Nil(t, workloads)
	})
}

func TestIsGitURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{
			name:     "GitHub URL",
			url:      "https://github.com/kubescape/kubescape",
			expected: true,
		},
		{
			name:     "GitHub URL with .git",
			url:      "https://github.com/kubescape/kubescape.git",
			expected: true,
		},
		{
			name:     "GitLab URL",
			url:      "https://gitlab.com/group/project",
			expected: true,
		},
		{
			name:     "local path",
			url:      "/path/to/local/directory",
			expected: false,
		},
		{
			name:     "HTTP URL not Git",
			url:      "https://example.com/file.yaml",
			expected: false,
		},
		{
			name:     "empty string",
			url:      "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isGitURL(tt.url)
			assert.Equal(t, tt.expected, result)
		})
	}
}
