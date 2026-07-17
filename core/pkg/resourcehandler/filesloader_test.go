package resourcehandler

import (
	"context"
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
