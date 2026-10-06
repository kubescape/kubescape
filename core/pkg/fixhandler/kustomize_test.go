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

// makeResourceWithNS builds a reporthandling.Resource with kind, name, and namespace.
func makeResourceWithNS(kind, namespace, name string) *reporthandling.Resource {
	return &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       kind,
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
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

// TestEmitKustomizePatch_WritesCorrectFiles verifies that patch, base, and kustomization
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

	// kustomization.yaml must exist and reference base.yaml + patch file + target
	kustPath := filepath.Join(dir, "kustomization.yaml")
	require.FileExists(t, kustPath)
	kustContent, _ := os.ReadFile(kustPath)
	kustStr := string(kustContent)
	assert.Contains(t, kustStr, "Deployment-default-my-app.yaml")
	assert.Contains(t, kustStr, "base.yaml")
	assert.Contains(t, kustStr, "my-app")
	assert.Contains(t, kustStr, "Deployment")
	assert.Contains(t, kustStr, "kustomize.config.k8s.io/v1beta1")

	// base.yaml must exist and contain rendered workload
	basePath := filepath.Join(dir, "base.yaml")
	require.FileExists(t, basePath)
	baseContent, _ := os.ReadFile(basePath)
	assert.Contains(t, string(baseContent), "kind: Deployment")
	assert.Contains(t, string(baseContent), "name: my-app")

	// Patch file must exist with correct JSON 6902 add ops
	patchPath := filepath.Join(dir, "Deployment-default-my-app.yaml")
	require.FileExists(t, patchPath)
	patchContent, _ := os.ReadFile(patchPath)
	patchStr := string(patchContent)
	assert.Contains(t, patchStr, "/spec/template/spec/containers/0/securityContext/privileged")
	assert.Contains(t, patchStr, "/spec/template/spec/securityContext/runAsNonRoot")
	assert.Contains(t, patchStr, "op: add")
	assert.Contains(t, patchStr, "false")
}

// TestEmitKustomizePatch_CombinesMultipleSuggestionsForSameResource verifies suggestions
// targeting the same workload are merged into a single patch file.
func TestEmitKustomizePatch_CombinesMultipleSuggestionsForSameResource(t *testing.T) {
	dir := t.TempDir()
	res := makeResource("Deployment", "my-app")

	suggestions := []HelmFixSuggestion{
		{
			Resource:  res,
			ChartName: "my-chart",
			FixPaths:  []armotypes.FixPath{{Path: "spec.template.spec.securityContext.runAsNonRoot", Value: "true"}},
		},
		{
			Resource:  res,
			ChartName: "my-chart",
			FixPaths:  []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
		},
	}

	require.NoError(t, EmitKustomizePatch(suggestions, dir))

	patchPath := filepath.Join(dir, "Deployment-default-my-app.yaml")
	require.FileExists(t, patchPath)
	patchContent, _ := os.ReadFile(patchPath)
	patchStr := string(patchContent)

	// Both operations must be in the single patch file
	assert.Contains(t, patchStr, "/spec/template/spec/securityContext/runAsNonRoot")
	assert.Contains(t, patchStr, "/spec/template/spec/containers/0/securityContext/privileged")
}

// TestEmitKustomizePatch_MultipleResources verifies multiple resources in different
// namespaces each get their own patch file and targets.
func TestEmitKustomizePatch_MultipleResources(t *testing.T) {
	dir := t.TempDir()

	suggestions := []HelmFixSuggestion{
		{
			Resource:  makeResourceWithNS("Deployment", "blue", "nginx"),
			ChartName: "my-chart",
			FixPaths:  []armotypes.FixPath{{Path: "spec.template.spec.securityContext.runAsNonRoot", Value: "true"}},
		},
		{
			Resource:  makeResourceWithNS("Deployment", "green", "nginx"),
			ChartName: "my-chart",
			FixPaths:  []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
		},
	}

	require.NoError(t, EmitKustomizePatch(suggestions, dir))

	assert.FileExists(t, filepath.Join(dir, "kustomization.yaml"))
	assert.FileExists(t, filepath.Join(dir, "Deployment-blue-nginx.yaml"))
	assert.FileExists(t, filepath.Join(dir, "Deployment-green-nginx.yaml"))

	kustContent, _ := os.ReadFile(filepath.Join(dir, "kustomization.yaml"))
	kustStr := string(kustContent)
	assert.Contains(t, kustStr, "Deployment-blue-nginx.yaml")
	assert.Contains(t, kustStr, "Deployment-green-nginx.yaml")
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

// TestEmitKustomizePatch_EmptyValueIsAssignment verifies that an empty Value
// produces an explicit empty string assignment with op: "add".
func TestEmitKustomizePatch_EmptyValueIsAssignment(t *testing.T) {
	dir := t.TempDir()
	suggestions := []HelmFixSuggestion{
		{
			Resource:  makeResource("Deployment", "my-app"),
			ChartName: "my-chart",
			FixPaths:  []armotypes.FixPath{{Path: "spec.storageClassName", Value: ""}},
		},
	}
	require.NoError(t, EmitKustomizePatch(suggestions, dir))
	patchContent, _ := os.ReadFile(filepath.Join(dir, "Deployment-default-my-app.yaml"))
	patchStr := string(patchContent)
	assert.Contains(t, patchStr, "op: add")
	assert.Contains(t, patchStr, `path: /spec/storageClassName`)
	assert.Contains(t, patchStr, `value: ""`)
}

// TestEmitKustomizePatch_ArrayAndComplexTypes verifies JSON array string values are
// parsed and emitted as YAML sequences.
func TestEmitKustomizePatch_ArrayAndComplexTypes(t *testing.T) {
	dir := t.TempDir()
	suggestions := []HelmFixSuggestion{
		{
			Resource:  makeResource("Deployment", "my-app"),
			ChartName: "my-chart",
			FixPaths:  []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.capabilities.drop", Value: `["ALL"]`}},
		},
	}
	require.NoError(t, EmitKustomizePatch(suggestions, dir))
	patchContent, _ := os.ReadFile(filepath.Join(dir, "Deployment-default-my-app.yaml"))
	patchStr := string(patchContent)
	assert.Contains(t, patchStr, "op: add")
	assert.Contains(t, patchStr, "- ALL")
}

// TestEmitKustomizePatch_PathTraversalProtection verifies path traversal characters in kind/name
// are sanitized and do not escape output directory.
func TestEmitKustomizePatch_PathTraversalProtection(t *testing.T) {
	dir := t.TempDir()
	suggestions := []HelmFixSuggestion{
		{
			Resource:  makeResource("../escaped", "../../badname"),
			ChartName: "my-chart",
			FixPaths:  []armotypes.FixPath{{Path: "spec.securityContext.runAsNonRoot", Value: "true"}},
		},
	}
	require.NoError(t, EmitKustomizePatch(suggestions, dir))

	// Escaped files outside dir must NOT be created
	escapedOutside := filepath.Join(dir, "..", "escaped-default-badname.yaml")
	assert.NoFileExists(t, escapedOutside)

	// Files inside dir must be sanitized
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), "..")
	}
}

// TestEmitKustomizePatch_NullValueEmitsValueNull verifies that a fix path with value "null"
// emits value: null without omitting the value field.
func TestEmitKustomizePatch_NullValueEmitsValueNull(t *testing.T) {
	dir := t.TempDir()
	suggestions := []HelmFixSuggestion{
		{
			Resource:  makeResource("Deployment", "my-app"),
			ChartName: "my-chart",
			FixPaths:  []armotypes.FixPath{{Path: "spec.storageClassName", Value: "null"}},
		},
	}
	require.NoError(t, EmitKustomizePatch(suggestions, dir))
	patchContent, _ := os.ReadFile(filepath.Join(dir, "Deployment-default-my-app.yaml"))
	patchStr := string(patchContent)
	assert.Contains(t, patchStr, "op: add")
	assert.Contains(t, patchStr, "path: /spec/storageClassName")
	assert.Contains(t, patchStr, "value: null")
}

// TestEmitKustomizePatch_ArrayElementTargetUsesReplace verifies that targeting an existing array element index
// uses "replace" rather than "add" so the element is updated instead of a new one being inserted.
func TestEmitKustomizePatch_ArrayElementTargetUsesReplace(t *testing.T) {
	dir := t.TempDir()
	suggestions := []HelmFixSuggestion{
		{
			Resource:  makeResource("Deployment", "my-app"),
			ChartName: "my-chart",
			FixPaths:  []armotypes.FixPath{{Path: "spec.template.spec.containers[0]", Value: `{"name":"demo","image":"nginx:1.28"}`}},
		},
	}
	require.NoError(t, EmitKustomizePatch(suggestions, dir))
	patchContent, _ := os.ReadFile(filepath.Join(dir, "Deployment-default-my-app.yaml"))
	patchStr := string(patchContent)
	assert.Contains(t, patchStr, "op: replace")
	assert.Contains(t, patchStr, "path: /spec/template/spec/containers/0")
}


