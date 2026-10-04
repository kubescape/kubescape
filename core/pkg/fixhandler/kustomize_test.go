package fixhandler

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeResource builds a minimal reporthandling.Resource with the given kind and name.
func makeResource(kind, name string) *reporthandling.Resource {
	return &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       kind,
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": "default",
			},
		},
	}
}

// TestFixPathToJSONPointer verifies dot-notation → RFC 6901 JSON Pointer conversion.
func TestFixPathToJSONPointer(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			"spec.containers[0].securityContext.privileged",
			"/spec/containers/0/securityContext/privileged",
		},
		{
			"spec.securityContext.runAsNonRoot",
			"/spec/securityContext/runAsNonRoot",
		},
		{
			"spec.containers[*].image",
			"/spec/containers/*/image",
		},
		{
			"metadata.labels",
			"/metadata/labels",
		},
		{
			"spec.template.spec.containers[0].resources.limits.cpu",
			"/spec/template/spec/containers/0/resources/limits/cpu",
		},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, fixPathToJSONPointer(tt.input))
		})
	}
}

// TestEmitKustomizePatch_WritesCorrectFiles verifies that patch and kustomization
// files are written with the right content for a typical Helm finding.
func TestEmitKustomizePatch_WritesCorrectFiles(t *testing.T) {
	dir := t.TempDir()

	suggestions := []HelmFixSuggestion{
		{
			Resource:  makeResource("Deployment", "my-app"),
			ChartName: "my-chart",
			FixPaths: []armotypes.FixPath{
				{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"},
				{Path: "spec.template.spec.securityContext.runAsNonRoot", Value: "true"},
			},
		},
	}

	err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)

	// kustomization.yaml must exist and reference the patch file + target
	kustPath := filepath.Join(dir, "kustomization.yaml")
	require.FileExists(t, kustPath)
	kustContent, _ := os.ReadFile(kustPath)
	kustStr := string(kustContent)
	assert.Contains(t, kustStr, "Deployment-my-app.yaml")
	assert.Contains(t, kustStr, "my-app")
	assert.Contains(t, kustStr, "Deployment")
	assert.Contains(t, kustStr, "kustomize.config.k8s.io/v1beta1")

	// Patch file must exist with correct JSON 6902 ops
	patchPath := filepath.Join(dir, "Deployment-my-app.yaml")
	require.FileExists(t, patchPath)
	patchContent, _ := os.ReadFile(patchPath)
	patchStr := string(patchContent)
	assert.Contains(t, patchStr, "/spec/template/spec/containers/0/securityContext/privileged")
	assert.Contains(t, patchStr, "/spec/template/spec/securityContext/runAsNonRoot")
	assert.Contains(t, patchStr, "replace")
	// Boolean false must be emitted as false, not as string "false"
	assert.Contains(t, patchStr, "false")
}

// TestEmitKustomizePatch_MultipleResources verifies multiple resources each get
// their own patch file and all appear in kustomization.yaml.
func TestEmitKustomizePatch_MultipleResources(t *testing.T) {
	dir := t.TempDir()

	suggestions := []HelmFixSuggestion{
		{
			Resource:  makeResource("Deployment", "nginx"),
			ChartName: "my-chart",
			FixPaths:  []armotypes.FixPath{{Path: "spec.template.spec.securityContext.runAsNonRoot", Value: "true"}},
		},
		{
			Resource:  makeResource("DaemonSet", "fluentd"),
			ChartName: "my-chart",
			FixPaths:  []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
		},
	}

	require.NoError(t, EmitKustomizePatch(suggestions, dir))

	assert.FileExists(t, filepath.Join(dir, "kustomization.yaml"))
	assert.FileExists(t, filepath.Join(dir, "Deployment-nginx.yaml"))
	assert.FileExists(t, filepath.Join(dir, "DaemonSet-fluentd.yaml"))

	kustContent, _ := os.ReadFile(filepath.Join(dir, "kustomization.yaml"))
	kustStr := string(kustContent)
	assert.Contains(t, kustStr, "Deployment-nginx.yaml")
	assert.Contains(t, kustStr, "DaemonSet-fluentd.yaml")
}

// TestEmitKustomizePatch_EmptyInput verifies nothing is written for empty suggestions.
func TestEmitKustomizePatch_EmptyInput(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, EmitKustomizePatch(nil, dir))
	entries, _ := os.ReadDir(dir)
	assert.Empty(t, entries, "no files should be written for empty suggestions")
}

// TestEmitKustomizePatch_SkipsEmptyFixPaths verifies suggestions with no fix paths
// are silently skipped without writing any files.
func TestEmitKustomizePatch_SkipsEmptyFixPaths(t *testing.T) {
	dir := t.TempDir()
	suggestions := []HelmFixSuggestion{
		{
			Resource:  makeResource("Deployment", "empty-app"),
			ChartName: "my-chart",
			FixPaths:  []armotypes.FixPath{}, // no paths
		},
	}
	require.NoError(t, EmitKustomizePatch(suggestions, dir))
	entries, _ := os.ReadDir(dir)
	assert.Empty(t, entries, "no files should be written when fix paths are empty")
}

// TestEmitKustomizePatch_RemoveOpOnEmptyValue verifies that an empty Value
// produces a "remove" operation instead of "replace".
func TestEmitKustomizePatch_RemoveOpOnEmptyValue(t *testing.T) {
	dir := t.TempDir()
	suggestions := []HelmFixSuggestion{
		{
			Resource:  makeResource("Deployment", "my-app"),
			ChartName: "my-chart",
			FixPaths:  []armotypes.FixPath{{Path: "spec.template.spec.hostPID", Value: ""}},
		},
	}
	require.NoError(t, EmitKustomizePatch(suggestions, dir))
	patchContent, _ := os.ReadFile(filepath.Join(dir, "Deployment-my-app.yaml"))
	assert.Contains(t, string(patchContent), "remove")
}
