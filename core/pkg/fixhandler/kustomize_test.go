package fixhandler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

// copy of scanner container-redaction function from processorhandlerutils.go:811
func removeContainersData(containers []corev1.Container) {
	for i := range containers {
		container := &containers[i]
		for j := range container.Env {
			container.Env[j].Value = "XXXXXX"
			container.Env[j].ValueFrom = nil
		}
		container.EnvFrom = nil
	}
}

func ptrBool(b bool) *bool {
	return &b
}

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

// TestFixPathToJSONPointer verifies dot-notation and quoted-key → RFC 6901 JSON Pointer conversion.
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
			`metadata.labels."app.kubernetes.io/name"`,
			"/metadata/labels/app.kubernetes.io~1name",
		},
		{
			`metadata.annotations."example.com/tier"`,
			"/metadata/annotations/example.com~1tier",
		},
		{
			`metadata.labels."foo~bar"`,
			"/metadata/labels/foo~0bar",
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
			ptr, err := fixPathToJSONPointer(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, ptr)
		})
	}
}

// TestFixPathToJSONPointer_RejectsWildcards verifies that wildcard fix paths are rejected.
func TestFixPathToJSONPointer_RejectsWildcards(t *testing.T) {
	_, err := fixPathToJSONPointer("spec.containers[*].image")
	assert.Error(t, err, "wildcard path must not produce an unexpanded JSON Pointer")
}

// TestEmitKustomizePatch_WritesCorrectFiles verifies that patch, base, and kustomization
// files are written with the right content for a typical Helm finding.
func TestEmitKustomizePatch_WritesCorrectFiles(t *testing.T) {
	dir := t.TempDir()

	res := makeResource("Deployment", "my-app")
	res.GetObject()["spec"] = map[string]interface{}{
		"template": map[string]interface{}{
			"spec": map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name": "web",
					},
				},
			},
		},
	}

	suggestions := []HelmFixSuggestion{
		{
			Resource:           res,
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"},
				{Path: "spec.template.spec.securityContext.runAsNonRoot", Value: "true"},
			},
		},
	}

	emitRes, err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)
	require.NotNil(t, emitRes)
	require.Len(t, emitRes.EmittedResources, 1)

	// kustomization.yaml must exist and reference base.yaml + patch file + target
	kustPath := filepath.Join(dir, "kustomization.yaml")
	require.FileExists(t, kustPath)
	kustContent, _ := os.ReadFile(kustPath)
	kustStr := string(kustContent)
	assert.Contains(t, kustStr, "apps-Deployment-default-my-app-")
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
	patchFileName := resourcePatchFilename(resourceKey{
		Group:     "apps",
		Version:   "v1",
		Kind:      "Deployment",
		Namespace: "default",
		Name:      "my-app",
	})
	patchPath := filepath.Join(dir, patchFileName)
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
	res.GetObject()["spec"] = map[string]interface{}{
		"template": map[string]interface{}{
			"spec": map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "web"},
				},
			},
		},
	}

	suggestions := []HelmFixSuggestion{
		{
			Resource:           res,
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{{Path: "spec.template.spec.securityContext.runAsNonRoot", Value: "true"}},
		},
		{
			Resource:           res,
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
		},
	}

	_, err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)

	patchFileName := resourcePatchFilename(resourceKey{
		Group:     "apps",
		Version:   "v1",
		Kind:      "Deployment",
		Namespace: "default",
		Name:      "my-app",
	})
	patchPath := filepath.Join(dir, patchFileName)
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
			Resource:           makeResourceWithNS("Deployment", "blue", "nginx"),
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{{Path: "spec.template.spec.securityContext.runAsNonRoot", Value: "true"}},
		},
		{
			Resource:           makeResourceWithNS("Deployment", "green", "nginx"),
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{{Path: "spec.template.spec.securityContext.runAsNonRoot", Value: "true"}},
		},
	}

	_, err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)

	assert.FileExists(t, filepath.Join(dir, "kustomization.yaml"))
	kustContent, _ := os.ReadFile(filepath.Join(dir, "kustomization.yaml"))
	kustStr := string(kustContent)
	assert.Contains(t, kustStr, "apps-Deployment-blue-nginx-")
	assert.Contains(t, kustStr, "apps-Deployment-green-nginx-")
}

// TestEmitKustomizePatch_EmptyInput verifies nothing is written for empty suggestions.
func TestEmitKustomizePatch_EmptyInput(t *testing.T) {
	dir := t.TempDir()
	_, err := EmitKustomizePatch(nil, dir)
	require.NoError(t, err)
	entries, _ := os.ReadDir(dir)
	assert.Empty(t, entries, "no files should be written for empty suggestions")
}

// TestEmitKustomizePatch_SkipsEmptyFixPaths verifies suggestions with no fix paths
// are silently skipped without writing any files.
func TestEmitKustomizePatch_SkipsEmptyFixPaths(t *testing.T) {
	dir := t.TempDir()
	suggestions := []HelmFixSuggestion{
		{
			Resource:           makeResource("Deployment", "empty-app"),
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{},
		},
	}
	_, err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)
	entries, _ := os.ReadDir(dir)
	assert.Empty(t, entries, "no files should be written when fix paths are empty")
}

// TestEmitKustomizePatch_EmptyValueIsAssignment verifies that an empty Value
// produces an explicit empty string assignment with op: "add".
func TestEmitKustomizePatch_EmptyValueIsAssignment(t *testing.T) {
	dir := t.TempDir()
	suggestions := []HelmFixSuggestion{
		{
			Resource:           makeResource("Deployment", "my-app"),
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{{Path: "spec.storageClassName", Value: ""}},
		},
	}
	_, err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)
	patchFileName := resourcePatchFilename(resourceKey{
		Group:     "apps",
		Version:   "v1",
		Kind:      "Deployment",
		Namespace: "default",
		Name:      "my-app",
	})
	patchContent, _ := os.ReadFile(filepath.Join(dir, patchFileName))
	patchStr := string(patchContent)
	assert.Contains(t, patchStr, "op: add")
	assert.Contains(t, patchStr, `path: /spec/storageClassName`)
	assert.Contains(t, patchStr, `value: ""`)
}

// TestEmitKustomizePatch_ArrayAndComplexTypes verifies JSON array string values are
// parsed and emitted as YAML sequences.
func TestEmitKustomizePatch_ArrayAndComplexTypes(t *testing.T) {
	dir := t.TempDir()
	res := makeResource("Deployment", "my-app")
	res.GetObject()["spec"] = map[string]interface{}{
		"template": map[string]interface{}{
			"spec": map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "web"},
				},
			},
		},
	}
	suggestions := []HelmFixSuggestion{
		{
			Resource:           res,
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.capabilities.drop", Value: `["ALL"]`}},
		},
	}
	_, err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)
	patchFileName := resourcePatchFilename(resourceKey{
		Group:     "apps",
		Version:   "v1",
		Kind:      "Deployment",
		Namespace: "default",
		Name:      "my-app",
	})
	patchContent, _ := os.ReadFile(filepath.Join(dir, patchFileName))
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
			Resource:           makeResource("../escaped", "../../badname"),
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{{Path: "spec.securityContext.runAsNonRoot", Value: "true"}},
		},
	}
	_, err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)

	escapedOutside := filepath.Join(dir, "..", "escaped-default-badname.yaml")
	assert.NoFileExists(t, escapedOutside)

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
			Resource:           makeResource("Deployment", "my-app"),
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{{Path: "spec.storageClassName", Value: "null"}},
		},
	}
	_, err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)
	patchFileName := resourcePatchFilename(resourceKey{
		Group:     "apps",
		Version:   "v1",
		Kind:      "Deployment",
		Namespace: "default",
		Name:      "my-app",
	})
	patchContent, _ := os.ReadFile(filepath.Join(dir, patchFileName))
	patchStr := string(patchContent)
	assert.Contains(t, patchStr, "op: add")
	assert.Contains(t, patchStr, "path: /spec/storageClassName")
	assert.Contains(t, patchStr, "value: null")
}

// TestEmitKustomizePatch_ArrayElementTargetUsesReplace verifies that targeting an existing array element index
// uses "replace" rather than "add" so the element is updated instead of a new one being inserted.
func TestEmitKustomizePatch_ArrayElementTargetUsesReplace(t *testing.T) {
	dir := t.TempDir()
	res := makeResource("Deployment", "my-app")
	res.GetObject()["spec"] = map[string]interface{}{
		"template": map[string]interface{}{
			"spec": map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "demo", "image": "nginx:1.20"},
				},
			},
		},
	}
	suggestions := []HelmFixSuggestion{
		{
			Resource:           res,
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{{Path: "spec.template.spec.containers[0]", Value: `{"name":"demo","image":"nginx:1.28"}`}},
		},
	}
	_, err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)
	patchFileName := resourcePatchFilename(resourceKey{
		Group:     "apps",
		Version:   "v1",
		Kind:      "Deployment",
		Namespace: "default",
		Name:      "my-app",
	})
	patchContent, _ := os.ReadFile(filepath.Join(dir, patchFileName))
	patchStr := string(patchContent)
	assert.Contains(t, patchStr, "op: replace")
	assert.Contains(t, patchStr, "path: /spec/template/spec/containers/0")
}

// TestEmitKustomizePatch_ExpandsWildcard verifies that fix paths with [*] wildcards are expanded
// into concrete index paths for each existing container in the rendered resource.
func TestEmitKustomizePatch_ExpandsWildcard(t *testing.T) {
	dir := t.TempDir()
	res := makeResource("Deployment", "multi-container")
	res.GetObject()["spec"] = map[string]interface{}{
		"template": map[string]interface{}{
			"spec": map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "web"},
					map[string]interface{}{"name": "sidecar"},
				},
			},
		},
	}

	suggestions := []HelmFixSuggestion{
		{
			Resource:           res,
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "spec.template.spec.containers[*].securityContext.privileged", Value: "false"},
			},
		},
	}

	_, err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)

	patchFileName := resourcePatchFilename(resourceKey{
		Group:     "apps",
		Version:   "v1",
		Kind:      "Deployment",
		Namespace: "default",
		Name:      "multi-container",
	})
	patchContent, _ := os.ReadFile(filepath.Join(dir, patchFileName))
	patchStr := string(patchContent)

	// Must contain concrete indices 0 and 1, and no wildcard tokens
	assert.Contains(t, patchStr, "/spec/template/spec/containers/0/securityContext/privileged")
	assert.Contains(t, patchStr, "/spec/template/spec/containers/1/securityContext/privileged")
	assert.NotContains(t, patchStr, "/*/")
}

// TestEmitKustomizePatch_SiblingFixesSharingMissingParent_KustomizeBuild tests that sibling
// fixes sharing a missing parent (e.g. privileged=false and runAsNonRoot=true on a container
// with no initial securityContext) are both preserved in the final Kustomize build output.
func TestEmitKustomizePatch_SiblingFixesSharingMissingParent_KustomizeBuild(t *testing.T) {
	dir := t.TempDir()

	pod := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]interface{}{
				"name":      "test-pod",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name":  "app",
						"image": "busybox",
					},
				},
			},
		},
	}

	suggestions := []HelmFixSuggestion{
		{
			Resource:           pod,
			ChartName:          "test-chart",
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "spec.containers[0].securityContext.privileged", Value: "false"},
				{Path: "spec.containers[0].securityContext.runAsNonRoot", Value: "true"},
			},
		},
	}

	_, err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)

	// Verify patch file content
	patchFileName := resourcePatchFilename(resourceKey{
		Group:     "",
		Version:   "v1",
		Kind:      "Pod",
		Namespace: "default",
		Name:      "test-pod",
	})
	patchPath := filepath.Join(dir, patchFileName)
	require.FileExists(t, patchPath)
	patchBytes, err := os.ReadFile(patchPath)
	require.NoError(t, err)
	patchStr := string(patchBytes)
	assert.Contains(t, patchStr, "/spec/containers/0/securityContext")
	assert.Contains(t, patchStr, "/spec/containers/0/securityContext/privileged")
	assert.Contains(t, patchStr, "/spec/containers/0/securityContext/runAsNonRoot")

	// Execute actual Kustomize build using krusty
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	resMap, err := k.Run(filesys.MakeFsOnDisk(), dir)
	require.NoError(t, err, "kustomize build must succeed")

	outYaml, err := resMap.AsYaml()
	require.NoError(t, err)

	var builtPod struct {
		Spec struct {
			Containers []struct {
				Name            string `yaml:"name"`
				SecurityContext struct {
					Privileged   *bool `yaml:"privileged"`
					RunAsNonRoot *bool `yaml:"runAsNonRoot"`
				} `yaml:"securityContext"`
			} `yaml:"containers"`
		} `yaml:"spec"`
	}

	require.NoError(t, yaml.Unmarshal(outYaml, &builtPod))
	require.Len(t, builtPod.Spec.Containers, 1)
	sc := builtPod.Spec.Containers[0].SecurityContext
	require.NotNil(t, sc.Privileged, "privileged must be set in final object")
	assert.False(t, *sc.Privileged, "privileged must be false")
	require.NotNil(t, sc.RunAsNonRoot, "runAsNonRoot must be set in final object")
	assert.True(t, *sc.RunAsNonRoot, "runAsNonRoot must be true")
}

// TestEmitKustomizePatch_CollidingNamespaceName_KustomizeBuild tests that ambiguous
// namespace/name pairs (e.g. namespace=a-b,name=c and namespace=a,name=b-c) produce
// distinct patch files and correct target assignments when built with Kustomize.
func TestEmitKustomizePatch_CollidingNamespaceName_KustomizeBuild(t *testing.T) {
	dir := t.TempDir()

	dep1 := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":      "c",
				"namespace": "a-b",
			},
			"spec": map[string]interface{}{
				"replicas": 1,
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{"name": "c", "image": "nginx"},
						},
					},
				},
			},
		},
	}

	dep2 := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":      "b-c",
				"namespace": "a",
			},
			"spec": map[string]interface{}{
				"replicas": 1,
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{"name": "bc", "image": "nginx"},
						},
					},
				},
			},
		},
	}

	suggestions := []HelmFixSuggestion{
		{
			Resource:           dep1,
			ChartName:          "chart-1",
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{{Path: "spec.replicas", Value: "2"}},
		},
		{
			Resource:           dep2,
			ChartName:          "chart-2",
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{{Path: "spec.replicas", Value: "3"}},
		},
	}

	_, err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)

	// Verify two distinct patch files exist
	key1 := resourceKey{Group: "apps", Version: "v1", Kind: "Deployment", Namespace: "a-b", Name: "c"}
	key2 := resourceKey{Group: "apps", Version: "v1", Kind: "Deployment", Namespace: "a", Name: "b-c"}
	file1 := resourcePatchFilename(key1)
	file2 := resourcePatchFilename(key2)
	assert.NotEqual(t, file1, file2, "filenames must not collide for different namespace/name pairs")

	require.FileExists(t, filepath.Join(dir, file1))
	require.FileExists(t, filepath.Join(dir, file2))

	// Execute actual Kustomize build using krusty
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	resMap, err := k.Run(filesys.MakeFsOnDisk(), dir)
	require.NoError(t, err, "kustomize build must succeed")

	outYaml, err := resMap.AsYaml()
	require.NoError(t, err)

	decoder := yaml.NewDecoder(os.NewFile(0, "stdin"))
	_ = decoder

	var docs []struct {
		Metadata struct {
			Name      string `yaml:"name"`
			Namespace string `yaml:"namespace"`
		} `yaml:"metadata"`
		Spec struct {
			Replicas int `yaml:"replicas"`
		} `yaml:"spec"`
	}

	// Split and parse multi-document YAML
	rawDocs := splitYamlDocs(outYaml)
	for _, docBytes := range rawDocs {
		var doc struct {
			Metadata struct {
				Name      string `yaml:"name"`
				Namespace string `yaml:"namespace"`
			} `yaml:"metadata"`
			Spec struct {
				Replicas int `yaml:"replicas"`
			} `yaml:"spec"`
		}
		if err := yaml.Unmarshal(docBytes, &doc); err == nil && doc.Metadata.Name != "" {
			docs = append(docs, doc)
		}
	}

	require.Len(t, docs, 2, "both Deployments must be present in build output")
	var dep1Replicas, dep2Replicas int
	for _, d := range docs {
		if d.Metadata.Namespace == "a-b" && d.Metadata.Name == "c" {
			dep1Replicas = d.Spec.Replicas
		} else if d.Metadata.Namespace == "a" && d.Metadata.Name == "b-c" {
			dep2Replicas = d.Spec.Replicas
		}
	}

	assert.Equal(t, 2, dep1Replicas, "Deployment namespace=a-b,name=c must have replicas 2")
	assert.Equal(t, 3, dep2Replicas, "Deployment namespace=a,name=b-c must have replicas 3")
}

// splitYamlDocs splits multi-doc YAML bytes into individual documents.
func splitYamlDocs(data []byte) [][]byte {
	var docs [][]byte
	parts := splitBytes(data, []byte("\n---"))
	for _, p := range parts {
		trimmed := p
		if len(trimmed) > 0 {
			docs = append(docs, trimmed)
		}
	}
	return docs
}

func splitBytes(s, sep []byte) [][]byte {
	var res [][]byte
	for {
		idx := findSubslice(s, sep)
		if idx == -1 {
			res = append(res, s)
			break
		}
		res = append(res, s[:idx])
		s = s[idx+len(sep):]
	}
	return res
}

func findSubslice(s, sub []byte) int {
	if len(sub) == 0 {
		return 0
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if s[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// TestEmitKustomizePatch_Permissions verifies that directory is created with 0700 and files with 0600.
func TestEmitKustomizePatch_Permissions(t *testing.T) {
	parentDir := t.TempDir()
	outDir := filepath.Join(parentDir, "kust-out")

	suggestions := []HelmFixSuggestion{
		{
			Resource:           makeResource("Deployment", "perm-app"),
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{{Path: "spec.replicas", Value: "2"}},
		},
	}

	_, err := EmitKustomizePatch(suggestions, outDir)
	require.NoError(t, err)

	info, err := os.Stat(outDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), info.Mode().Perm(), "directory must have 0700 permissions")

	baseInfo, err := os.Stat(filepath.Join(outDir, "base.yaml"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), baseInfo.Mode().Perm(), "base.yaml must have 0600 permissions")

	kustInfo, err := os.Stat(filepath.Join(outDir, "kustomization.yaml"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), kustInfo.Mode().Perm(), "kustomization.yaml must have 0600 permissions")
}

// TestReview4034LiteralResourceNames verifies that regex special characters (like '.') in resource names
// are quoted in patch selectors so they do not inadvertently match other resources (e.g. api.svc matching api-svc).
func TestReview4034LiteralResourceNames(t *testing.T) {
	dir := t.TempDir()

	makeDep := func(name string) *reporthandling.Resource {
		return &reporthandling.Resource{
			Object: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]interface{}{
					"name": name,
				},
				"spec": map[string]interface{}{
					"replicas": 1,
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{"name": "app", "image": "nginx"},
							},
						},
					},
				},
			},
		}
	}

	suggestions := []HelmFixSuggestion{
		{
			Resource:           makeDep("api-svc"),
			ChartName:          "api-chart",
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{{Path: "spec.replicas", Value: "2"}},
		},
		{
			Resource:           makeDep("api.svc"),
			ChartName:          "api-chart",
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{{Path: "spec.replicas", Value: "3"}},
		},
	}

	_, err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)

	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	resMap, err := k.Run(filesys.MakeFsOnDisk(), dir)
	require.NoError(t, err)

	outYaml, err := resMap.AsYaml()
	require.NoError(t, err)

	actualReplicas := make(map[string]int)
	for _, docBytes := range splitYamlDocs(outYaml) {
		var doc struct {
			Metadata struct {
				Name string `yaml:"name"`
			} `yaml:"metadata"`
			Spec struct {
				Replicas int `yaml:"replicas"`
			} `yaml:"spec"`
		}
		if err := yaml.Unmarshal(docBytes, &doc); err == nil && doc.Metadata.Name != "" {
			actualReplicas[doc.Metadata.Name] = doc.Spec.Replicas
		}
	}

	expectedReplicas := map[string]int{
		"api-svc": 2,
		"api.svc": 3,
	}
	assert.Equal(t, expectedReplicas, actualReplicas, "patch target for api.svc must not overwrite api-svc")
}

// TestReview4034ExistingOutputPermissions verifies that regenerating output into a directory
// and files with pre-existing open permissions restricts both directory and files to 0700/0600.
func TestReview4034ExistingOutputPermissions(t *testing.T) {
	parentDir := t.TempDir()
	outDir := filepath.Join(parentDir, "existing-kust")

	// Pre-create directory with mode 0755
	require.NoError(t, os.MkdirAll(outDir, 0755))
	require.NoError(t, os.Chmod(outDir, 0755))

	// Pre-create base.yaml with mode 0644
	basePath := filepath.Join(outDir, "base.yaml")
	//nolint:gosec // G306: intentionally testing restriction of pre-existing 0644 file
	require.NoError(t, os.WriteFile(basePath, []byte("pre-existing: true\n"), 0644))
	require.NoError(t, os.Chmod(basePath, 0644))

	suggestions := []HelmFixSuggestion{
		{
			Resource:           makeResource("Deployment", "perm-app"),
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{{Path: "spec.replicas", Value: "2"}},
		},
	}

	_, err := EmitKustomizePatch(suggestions, outDir)
	require.NoError(t, err)

	dirInfo, err := os.Stat(outDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), dirInfo.Mode().Perm(), "existing directory must be restricted to 0700")

	baseInfo, err := os.Stat(basePath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), baseInfo.Mode().Perm(), "existing base.yaml must be restricted to 0600")
}

// TestReview4034HelmOverlayPreservesEnvironment verifies that:
//  1. Redacted report objects (e.g. from scanner's removeData replacing container environment values with XXXXXX)
//     are declined and not built into an applyable base that would overwrite live application configuration.
//  2. Redacted objects where the scanner cleared envFrom without leaving a placeholder (processorhandlerutils.go:826)
//     are visibly declined when fidelity provenance is unproven, rather than exported with missing configuration.
//  3. An unredacted rendered source preserves its real container environment values across EmitKustomizePatch
//     and a Kustomize build.
func TestReview4034HelmOverlayPreservesEnvironment(t *testing.T) {
	t.Run("declines redacted report object", func(t *testing.T) {
		dir := t.TempDir()

		redactedDep := &reporthandling.Resource{
			Object: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]interface{}{
					"name": "redacted-app",
				},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name": "app",
									"env": []interface{}{
										map[string]interface{}{"name": "APP_MODE", "value": "XXXXXX"},
									},
									"securityContext": map[string]interface{}{
										"privileged": true,
									},
								},
							},
						},
					},
				},
			},
		}

		suggestions := []HelmFixSuggestion{
			{
				Resource:  redactedDep,
				ChartName: "my-chart",
				FixPaths:  []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
			},
		}

		// Should decline redacted resource, producing no patch files or base.yaml
		res, err := EmitKustomizePatch(suggestions, dir)
		require.NoError(t, err)
		assert.Empty(t, res.EmittedResources)
		require.Len(t, res.SkippedResources, 1)

		_, err = os.Stat(filepath.Join(dir, "base.yaml"))
		assert.True(t, os.IsNotExist(err), "redacted report object must not be emitted to base.yaml")
	})

	t.Run("declines scanner-cleared envFrom without placeholder", func(t *testing.T) {
		dir := t.TempDir()

		// A chart Deployment starting with envFrom and no explicit env
		containers := []corev1.Container{
			{
				Name: "app",
				EnvFrom: []corev1.EnvFromSource{
					{
						ConfigMapRef: &corev1.ConfigMapEnvSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "app-config"},
						},
					},
				},
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptrBool(true),
				},
			},
		}

		// Run the actual scanner container-redaction function (processorhandlerutils.go:826)
		removeContainersData(containers)
		require.Nil(t, containers[0].EnvFrom, "actual scanner redactor must have cleared EnvFrom")
		require.Empty(t, containers[0].Env, "Env must remain empty")

		// Marshal containers via JSON round-trip to simulate report serialization
		containerBytes, err := json.Marshal(containers)
		require.NoError(t, err)
		var unmarshaledContainers []interface{}
		require.NoError(t, json.Unmarshal(containerBytes, &unmarshaledContainers))

		redactedDep := &reporthandling.Resource{
			Object: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]interface{}{
					"name": "envfrom-app",
				},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": unmarshaledContainers,
						},
					},
				},
			},
		}

		// Without verified unredacted base or explicit fidelity provenance, this must be declined visibly
		suggestions := []HelmFixSuggestion{
			{
				Resource:  redactedDep,
				ChartName: "my-chart",
				FixPaths:  []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
			},
		}

		res, err := EmitKustomizePatch(suggestions, dir)
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.Empty(t, res.EmittedResources, "must not emit unproven/redacted resource")
		require.Len(t, res.SkippedResources, 1, "must record declined resource")
		assert.Contains(t, res.SkippedResources[0].Reason, "unproven report fidelity")

		_, err = os.Stat(filepath.Join(dir, "base.yaml"))
		assert.True(t, os.IsNotExist(err), "base.yaml must not be written for declined resource")
	})

	t.Run("preserves environment from unredacted rendered source", func(t *testing.T) {
		dir := t.TempDir()

		unredactedDep := &reporthandling.Resource{
			Object: map[string]interface{}{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]interface{}{
					"name": "prod-app",
				},
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{
									"name": "app",
									"env": []interface{}{
										map[string]interface{}{"name": "APP_MODE", "value": "production"},
									},
									"securityContext": map[string]interface{}{
										"privileged": true,
									},
								},
							},
						},
					},
				},
			},
		}

		suggestions := []HelmFixSuggestion{
			{
				Resource:           unredactedDep,
				ChartName:          "my-chart",
				FidelityProvenance: true,
				FixPaths:           []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
			},
		}

		res, err := EmitKustomizePatch(suggestions, dir)
		require.NoError(t, err)
		require.Len(t, res.EmittedResources, 1)

		k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
		resMap, err := k.Run(filesys.MakeFsOnDisk(), dir)
		require.NoError(t, err)

		outYaml, err := resMap.AsYaml()
		require.NoError(t, err)

		var builtPod struct {
			Spec struct {
				Template struct {
					Spec struct {
						Containers []struct {
							Name string `yaml:"name"`
							Env  []struct {
								Name  string `yaml:"name"`
								Value string `yaml:"value"`
							} `yaml:"env"`
							SecurityContext struct {
								Privileged *bool `yaml:"privileged"`
							} `yaml:"securityContext"`
						} `yaml:"containers"`
					} `yaml:"spec"`
				} `yaml:"template"`
			} `yaml:"spec"`
		}

		require.NoError(t, yaml.Unmarshal(outYaml, &builtPod))
		require.Len(t, builtPod.Spec.Template.Spec.Containers, 1)
		c := builtPod.Spec.Template.Spec.Containers[0]
		require.Len(t, c.Env, 1)
		assert.Equal(t, "production", c.Env[0].Value, "environment value must be preserved as production")
		require.NotNil(t, c.SecurityContext.Privileged)
		assert.False(t, *c.SecurityContext.Privileged, "privileged must be patched to false")
	})
}

// TestReview4034StaleOutputDirectoryNotAdvertised verifies that running patch emission into a
// directory containing an older generated overlay does not advertise the old overlay when all
// suggestions in the current invocation are declined.
func TestReview4034StaleOutputDirectoryNotAdvertised(t *testing.T) {
	dir := t.TempDir()

	// 1. First invocation emits valid overlay for v1
	v1Dep := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name": "v1-app",
			},
			"spec": map[string]interface{}{
				"replicas": 1,
			},
		},
	}
	v1Suggestions := []HelmFixSuggestion{
		{
			Resource:           v1Dep,
			ChartName:          "v1-chart",
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{{Path: "spec.replicas", Value: "2"}},
		},
	}
	res1, err := EmitKustomizePatch(v1Suggestions, dir)
	require.NoError(t, err)
	require.Len(t, res1.EmittedResources, 1)
	require.FileExists(t, filepath.Join(dir, "base.yaml"))

	// 2. Second invocation into the same output directory with an unproven/redacted resource
	v2Dep := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name": "v2-app",
			},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name": "app",
								"env":  []interface{}{map[string]interface{}{"name": "SECRET", "value": "XXXXXX"}},
							},
						},
					},
				},
			},
		},
	}
	// Case 2a: Unproven fidelity from scan report
	v2Suggestions := []HelmFixSuggestion{
		{
			Resource:  v2Dep,
			ChartName: "v2-chart",
			FixPaths:  []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
		},
	}
	res2, err := EmitKustomizePatch(v2Suggestions, dir)
	require.NoError(t, err)
	assert.Empty(t, res2.EmittedResources, "declined generation must report 0 emitted resources for this invocation")
	require.Len(t, res2.SkippedResources, 1, "declined resource must be recorded in SkippedResources")
	assert.Contains(t, res2.SkippedResources[0].Reason, "unproven report fidelity")

	// Case 2b: Provenance asserted, but resource contains placeholder "XXXXXX"
	v2Suggestions[0].FidelityProvenance = true
	res3, err := EmitKustomizePatch(v2Suggestions, dir)
	require.NoError(t, err)
	assert.Empty(t, res3.EmittedResources, "declined generation with placeholder must report 0 emitted resources")
	require.Len(t, res3.SkippedResources, 1)
	assert.Contains(t, res3.SkippedResources[0].Reason, "XXXXXX")
}

// TestRereview4034PreservesHelmOverrides verifies that non-default Helm render overrides
// (replicas, image, envFrom) are preserved through to the Kustomize overlay when provided via
// HelmValueOptions, and that suggestions lacking matching value overrides are visibly declined
// rather than overwriting live application configuration with chart defaults.
func TestRereview4034PreservesHelmOverrides(t *testing.T) {
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: testchart\nversion: 0.1.0\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "values.yaml"), []byte("replicas: 1\nimage: example:v1\nenvFrom: dev-config\n"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "templates"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "templates", "deployment.yaml"), []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: {{ .Values.replicas }}
  template:
    spec:
      containers:
      - name: app
        image: {{ .Values.image }}
        envFrom:
        - configMapRef:
            name: {{ .Values.envFrom }}
        securityContext:
          privileged: true
`), 0600))

	// Scanned resource recorded at scan time with non-default overrides
	scannedResource := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name": "my-app",
			},
			"spec": map[string]interface{}{
				"replicas": 5,
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "app",
								"image": "example:v2",
								"envFrom": []interface{}{
									map[string]interface{}{
										"configMapRef": map[string]interface{}{"name": "prod-config"},
									},
								},
								"securityContext": map[string]interface{}{
									"privileged": true,
								},
							},
						},
					},
				},
			},
		},
	}

	t.Run("declines when overrides are omitted or mismatched", func(t *testing.T) {
		outDir := t.TempDir()
		// Missing HelmValueOptions: chart would render with default replicas=1, image=example:v1
		// which conflicts with scanned resource (replicas=5, image=example:v2)
		suggs := []HelmFixSuggestion{
			{
				Resource:  scannedResource,
				ChartPath: chartDir,
				FixPaths:  []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
			},
		}

		res, err := EmitKustomizePatch(suggs, outDir)
		require.NoError(t, err)
		assert.Empty(t, res.EmittedResources)
		require.Len(t, res.SkippedResources, 1)
		assert.True(t, strings.Contains(res.SkippedResources[0].Reason, "scan report redacts container environment configuration") ||
			strings.Contains(res.SkippedResources[0].Reason, "does not match scan-time resource configuration"))

		_, err = os.Stat(filepath.Join(outDir, "base.yaml"))
		assert.True(t, os.IsNotExist(err), "base.yaml must not be written when overrides mismatch")
	})

	t.Run("preserves non-default overrides with HelmValueOptions", func(t *testing.T) {
		outDir := t.TempDir()
		suggs := []HelmFixSuggestion{
			{
				Resource:  scannedResource,
				ChartPath: chartDir,
				HelmValueOptions: cautils.HelmValueOptions{
					Values: []string{"replicas=5", "image=example:v2", "envFrom=prod-config"},
				},
				FixPaths: []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
			},
		}

		res, err := EmitKustomizePatch(suggs, outDir)
		require.NoError(t, err)
		require.Len(t, res.EmittedResources, 1)

		k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
		resMap, err := k.Run(filesys.MakeFsOnDisk(), outDir)
		require.NoError(t, err)
		outYaml, err := resMap.AsYaml()
		require.NoError(t, err)

		var built struct {
			Spec struct {
				Replicas int `yaml:"replicas"`
				Template struct {
					Spec struct {
						Containers []struct {
							Name    string `yaml:"name"`
							Image   string `yaml:"image"`
							EnvFrom []struct {
								ConfigMapRef struct {
									Name string `yaml:"name"`
								} `yaml:"configMapRef"`
							} `yaml:"envFrom"`
							SecurityContext struct {
								Privileged *bool `yaml:"privileged"`
							} `yaml:"securityContext"`
						} `yaml:"containers"`
					} `yaml:"spec"`
				} `yaml:"template"`
			} `yaml:"spec"`
		}
		require.NoError(t, yaml.Unmarshal(outYaml, &built))
		assert.Equal(t, 5, built.Spec.Replicas, "replicas must be preserved as 5")
		require.Len(t, built.Spec.Template.Spec.Containers, 1)
		c := built.Spec.Template.Spec.Containers[0]
		assert.Equal(t, "example:v2", c.Image, "image must be preserved as example:v2")
		require.Len(t, c.EnvFrom, 1)
		assert.Equal(t, "prod-config", c.EnvFrom[0].ConfigMapRef.Name, "envFrom must be preserved as prod-config")
		require.NotNil(t, c.SecurityContext.Privileged)
		assert.False(t, *c.SecurityContext.Privileged, "privileged must be patched to false")
	})
}

// TestRereview4034MatchesFullAPIIdentity verifies that selecting a rendered base workload compares
// the complete API identity (group, version, kind, name, and resolved namespace), ensuring that
// resources of identical kind/name across different API groups are distinguished.
func TestRereview4034MatchesFullAPIIdentity(t *testing.T) {
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: widgetchart\nversion: 0.1.0\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "values.yaml"), []byte("\n"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "templates"), 0700))
	// Two Widget resources with identical names in different API groups
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "templates", "widgets.yaml"), []byte(`apiVersion: alpha.example.com/v1
kind: Widget
metadata:
  name: my-widget
spec:
  secure: false
---
apiVersion: beta.example.com/v1
kind: Widget
metadata:
  name: my-widget
spec:
  secure: false
`), 0600))

	outDir := t.TempDir()

	betaWidget := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "beta.example.com/v1",
			"kind":       "Widget",
			"metadata": map[string]interface{}{
				"name": "my-widget",
			},
			"spec": map[string]interface{}{
				"secure": false,
			},
		},
	}

	suggs := []HelmFixSuggestion{
		{
			Resource:  betaWidget,
			ChartPath: chartDir,
			FixPaths:  []armotypes.FixPath{{Path: "spec.secure", Value: "true"}},
		},
	}

	res, err := EmitKustomizePatch(suggs, outDir)
	require.NoError(t, err)
	require.Len(t, res.EmittedResources, 1)

	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	resMap, err := k.Run(filesys.MakeFsOnDisk(), outDir)
	require.NoError(t, err)
	outYaml, err := resMap.AsYaml()
	require.NoError(t, err)

	var built struct {
		APIVersion string `yaml:"apiVersion"`
		Kind       string `yaml:"kind"`
		Metadata   struct {
			Name string `yaml:"name"`
		} `yaml:"metadata"`
		Spec struct {
			Secure bool `yaml:"secure"`
		} `yaml:"spec"`
	}
	require.NoError(t, yaml.Unmarshal(outYaml, &built))
	assert.Equal(t, "beta.example.com/v1", built.APIVersion, "built widget must be beta.example.com/v1")
	assert.Equal(t, "Widget", built.Kind)
	assert.Equal(t, "my-widget", built.Metadata.Name)
	assert.True(t, built.Spec.Secure, "secure must be patched to true on beta widget")
}

// TestRereview4034HelmReadHonorsBasePath verifies that EmitKustomizePatch refuses to load
// a chart path outside AllowedBasePath.
func TestRereview4034HelmReadHonorsBasePath(t *testing.T) {
	allowedBase := t.TempDir()
	outsideDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(outsideDir, "Chart.yaml"), []byte("apiVersion: v2\nname: evilchart\nversion: 0.1.0\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(outsideDir, "values.yaml"), []byte("\n"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Join(outsideDir, "templates"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(outsideDir, "templates", "secret.yaml"), []byte(`apiVersion: v1
kind: Secret
metadata:
  name: outside-secret
stringData:
  SENTINEL: outside-secret-12345
`), 0600))

	outDir := t.TempDir()

	sugg := HelmFixSuggestion{
		Resource: &reporthandling.Resource{
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Secret",
				"metadata":   map[string]interface{}{"name": "outside-secret"},
				"stringData": map[string]interface{}{"SENTINEL": "outside-secret-12345"},
			},
		},
		ChartPath:       outsideDir,
		AllowedBasePath: allowedBase,
		FixPaths:        []armotypes.FixPath{{Path: "metadata.labels.patched", Value: "true"}},
	}

	res, err := EmitKustomizePatch([]HelmFixSuggestion{sugg}, outDir)
	require.NoError(t, err)
	assert.Empty(t, res.EmittedResources)
	require.Len(t, res.SkippedResources, 1)
	assert.Contains(t, res.SkippedResources[0].Reason, "outside allowed base path")

	_, err = os.Stat(filepath.Join(outDir, "base.yaml"))
	assert.True(t, os.IsNotExist(err), "base.yaml must not exist for outside chart")
}

// TestReview4034ActualScanRoundTrip tests the interaction between scanner container redaction,
// typed JSON serialization, and Kustomize base verification.
func TestReview4034ActualScanRoundTrip(t *testing.T) {
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: appchart\nversion: 0.1.0\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "values.yaml"), []byte(`envFrom: dev-config
appMode: development
`), 0600))
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "templates"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "templates", "deployment.yaml"), []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: example:v1
        envFrom:
        - configMapRef:
            name: {{ .Values.envFrom }}
        env:
        - name: APP_MODE
          value: {{ .Values.appMode }}
        securityContext:
          privileged: true
`), 0600))

	t.Run("redacted_only_override", func(t *testing.T) {
		// Scanned object where scan overrides were envFrom=prod-config, APP_MODE=production,
		// and scanner removeData redacted APP_MODE to XXXXXX and removed envFrom.
		containers := []corev1.Container{
			{
				Name:  "app",
				Image: "example:v1",
				Env: []corev1.EnvVar{
					{Name: "APP_MODE", Value: "production"},
				},
				EnvFrom: []corev1.EnvFromSource{
					{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "prod-config"}}},
				},
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptrBool(true),
				},
			},
		}
		// Run actual scanner redaction
		removeContainersData(containers)

		// Round-trip through JSON
		b, err := json.Marshal(map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]interface{}{"name": "my-app"},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": containers,
					},
				},
			},
		})
		require.NoError(t, err)

		var scannedObj map[string]interface{}
		require.NoError(t, json.Unmarshal(b, &scannedObj))

		scannedRes := &reporthandling.Resource{Object: scannedObj}

		outDir := t.TempDir()

		// Without verified HelmValueOptions, the emitter must decline rather than reverting to chart defaults
		suggsWithoutOpts := []HelmFixSuggestion{
			{
				Resource:  scannedRes,
				ChartPath: chartDir,
				FixPaths:  []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
			},
		}

		res, err := EmitKustomizePatch(suggsWithoutOpts, outDir)
		require.NoError(t, err)
		assert.Empty(t, res.EmittedResources, "must decline when missing render inputs prevent establishing fidelity")
		require.Len(t, res.SkippedResources, 1)
		assert.Contains(t, res.SkippedResources[0].Reason, "scan report redacts container environment configuration")

		_, err = os.Stat(filepath.Join(outDir, "base.yaml"))
		assert.True(t, os.IsNotExist(err), "base.yaml must not be written when declined")

		// With verified HelmValueOptions matching scan overrides, the emitter reproduces and preserves them
		outDir2 := t.TempDir()
		suggsWithOpts := []HelmFixSuggestion{
			{
				Resource:  scannedRes,
				ChartPath: chartDir,
				HelmValueOptions: cautils.HelmValueOptions{
					Values: []string{"envFrom=prod-config", "appMode=production"},
				},
				FixPaths: []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
			},
		}
		res2, err := EmitKustomizePatch(suggsWithOpts, outDir2)
		require.NoError(t, err)
		require.Len(t, res2.EmittedResources, 1)

		k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
		resMap, err := k.Run(filesys.MakeFsOnDisk(), outDir2)
		require.NoError(t, err)
		outYaml, err := resMap.AsYaml()
		require.NoError(t, err)
		assert.Contains(t, string(outYaml), "prod-config")
		assert.Contains(t, string(outYaml), "production")
		assert.Contains(t, string(outYaml), "privileged: false")
	})

	t.Run("unchanged_chart_without_resources", func(t *testing.T) {
		// Chart without resources in template
		chartDirNoRes := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(chartDirNoRes, "Chart.yaml"), []byte("apiVersion: v2\nname: noreschart\nversion: 0.1.0\n"), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(chartDirNoRes, "values.yaml"), []byte("\n"), 0600))
		require.NoError(t, os.MkdirAll(filepath.Join(chartDirNoRes, "templates"), 0700))
		require.NoError(t, os.WriteFile(filepath.Join(chartDirNoRes, "templates", "deployment.yaml"), []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: no-res-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: example:v1
        securityContext:
          privileged: true
`), 0600))

		// Scanner round-trip introduces resources: {} via corev1.Container
		containers := []corev1.Container{
			{
				Name:  "app",
				Image: "example:v1",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptrBool(true),
				},
			},
		}
		b, err := json.Marshal(map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]interface{}{"name": "no-res-app"},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": containers,
					},
				},
			},
		})
		require.NoError(t, err)

		var scannedObj map[string]interface{}
		require.NoError(t, json.Unmarshal(b, &scannedObj))

		outDir := t.TempDir()
		suggs := []HelmFixSuggestion{
			{
				Resource:  &reporthandling.Resource{Object: scannedObj},
				ChartPath: chartDirNoRes,
				HelmValueOptions: cautils.HelmValueOptions{
					ValueFiles: []string{filepath.Join(chartDirNoRes, "values.yaml")},
				},
				FixPaths: []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
			},
		}

		res, err := EmitKustomizePatch(suggs, outDir)
		require.NoError(t, err)
		assert.Len(t, res.EmittedResources, 1, "unchanged chart with scanner-added empty resources must be emitted")
		assert.Empty(t, res.SkippedResources)

		k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
		resMap, err := k.Run(filesys.MakeFsOnDisk(), outDir)
		require.NoError(t, err)
		outYaml, err := resMap.AsYaml()
		require.NoError(t, err)
		assert.Contains(t, string(outYaml), "privileged: false")
	})
}

// TestReview4034ContainedChartExternalValues verifies that symlinks inside an allowed chart
// pointing to external files outside AllowedBasePath are detected and rejected.
func TestReview4034ContainedChartExternalValues(t *testing.T) {
	allowedBase := t.TempDir()
	outsideDir := t.TempDir()

	// External values file with sentinel
	externalValuesFile := filepath.Join(outsideDir, "external-values.yaml")
	require.NoError(t, os.WriteFile(externalValuesFile, []byte("sentinel: OUTSIDE_ROOT_SENTINEL\n"), 0600))

	// Chart root is inside allowedBase
	chartDir := filepath.Join(allowedBase, "symlink-chart")
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "templates"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: symlinkchart\nversion: 0.1.0\n"), 0600))

	// values.yaml inside chart is a symlink pointing outside allowedBase
	require.NoError(t, os.Symlink(externalValuesFile, filepath.Join(chartDir, "values.yaml")))

	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "templates", "secret.yaml"), []byte(`apiVersion: v1
kind: Secret
metadata:
  name: symlink-secret
stringData:
  KEY: {{ .Values.sentinel }}
`), 0600))

	outDir := t.TempDir()

	sugg := HelmFixSuggestion{
		Resource: &reporthandling.Resource{
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Secret",
				"metadata":   map[string]interface{}{"name": "symlink-secret"},
				"stringData": map[string]interface{}{"KEY": "OUTSIDE_ROOT_SENTINEL"},
			},
		},
		ChartPath:       chartDir,
		AllowedBasePath: allowedBase,
		FixPaths:        []armotypes.FixPath{{Path: "metadata.labels.patched", Value: "true"}},
	}

	res, err := EmitKustomizePatch([]HelmFixSuggestion{sugg}, outDir)
	require.NoError(t, err)
	assert.Empty(t, res.EmittedResources)
	require.Len(t, res.SkippedResources, 1)
	assert.Contains(t, res.SkippedResources[0].Reason, "outside allowed base path")

	baseFile := filepath.Join(outDir, "base.yaml")
	if data, err := os.ReadFile(baseFile); err == nil {
		assert.NotContains(t, string(data), "OUTSIDE_ROOT_SENTINEL", "external sentinel must not be copied into base.yaml")
	}
}

// TestReview4034ScanOnlyEnvFromEmptyChartDefault verifies [P1]:
// When a chart's default has empty extraEnvFrom=[] (or lacks envFrom), and a scan-time override
// added envFrom (e.g. configMapRef=prod-config) without explicit env, scanner removeContainersData
// deletes envFrom without leaving XXXXXX. Both default candidate and scan report lack envFrom.
//  1. Without value overrides (missing render provenance), the emitter must visibly decline rather than
//     silently dropping prod-config.
//  2. Passing --release-name alone does NOT satisfy render provenance, and must still be visibly declined.
//  3. When verified Helm value overrides are supplied, the emitter preserves prod-config in base.yaml.
func TestReview4034ScanOnlyEnvFromEmptyChartDefault(t *testing.T) {
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: emptyenvchart\nversion: 0.1.0\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "values.yaml"), []byte("extraEnvFrom: []\n"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "templates"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "templates", "deployment.yaml"), []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: example:v1
        {{- with .Values.extraEnvFrom }}
        envFrom:
          {{- toYaml . | nindent 8 }}
        {{- end }}
        securityContext:
          privileged: true
`), 0600))

	// Scanned object at scan time had --set extraEnvFrom[0].configMapRef.name=prod-config,
	// and scanner removeContainersData deleted envFrom without leaving XXXXXX.
	containers := []corev1.Container{
		{
			Name:  "app",
			Image: "example:v1",
			EnvFrom: []corev1.EnvFromSource{
				{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "prod-config"}}},
			},
			SecurityContext: &corev1.SecurityContext{
				Privileged: ptrBool(true),
			},
		},
	}
	removeContainersData(containers)
	require.Nil(t, containers[0].EnvFrom, "scanner must have cleared envFrom")
	require.Empty(t, containers[0].Env, "env must remain empty")

	b, err := json.Marshal(map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]interface{}{"name": "my-app"},
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": containers,
				},
			},
		},
	})
	require.NoError(t, err)

	var scannedObj map[string]interface{}
	require.NoError(t, json.Unmarshal(b, &scannedObj))
	scannedRes := &reporthandling.Resource{Object: scannedObj}

	t.Run("declines without value overrides", func(t *testing.T) {
		outDir := t.TempDir()
		suggs := []HelmFixSuggestion{
			{
				Resource:  scannedRes,
				ChartPath: chartDir,
				FixPaths:  []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
			},
		}

		res, err := EmitKustomizePatch(suggs, outDir)
		require.NoError(t, err)
		assert.Empty(t, res.EmittedResources)
		require.Len(t, res.SkippedResources, 1)
		assert.Contains(t, res.SkippedResources[0].Reason, "scan report redacts container environment configuration and no verified Helm render inputs were provided")
	})

	t.Run("declines when only release-name is provided without value overrides", func(t *testing.T) {
		outDir := t.TempDir()
		suggs := []HelmFixSuggestion{
			{
				Resource:  scannedRes,
				ChartPath: chartDir,
				HelmValueOptions: cautils.HelmValueOptions{
					ReleaseName: "my-release",
				},
				FixPaths: []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
			},
		}

		res, err := EmitKustomizePatch(suggs, outDir)
		require.NoError(t, err)
		assert.Empty(t, res.EmittedResources)
		require.Len(t, res.SkippedResources, 1)
		assert.Contains(t, res.SkippedResources[0].Reason, "scan report redacts container environment configuration and no verified Helm render inputs were provided")
	})

	t.Run("preserves scan-time envFrom when complete render provenance is supplied", func(t *testing.T) {
		outDir := t.TempDir()
		suggs := []HelmFixSuggestion{
			{
				Resource:  scannedRes,
				ChartPath: chartDir,
				HelmValueOptions: cautils.HelmValueOptions{
					Values: []string{"extraEnvFrom[0].configMapRef.name=prod-config"},
				},
				FixPaths: []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
			},
		}

		res, err := EmitKustomizePatch(suggs, outDir)
		require.NoError(t, err)
		require.Len(t, res.EmittedResources, 1)

		k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
		resMap, err := k.Run(filesys.MakeFsOnDisk(), outDir)
		require.NoError(t, err)
		outYaml, err := resMap.AsYaml()
		require.NoError(t, err)
		assert.Contains(t, string(outYaml), "prod-config")
		assert.Contains(t, string(outYaml), "privileged: false")
	})
}

// TestReview4034DirectorySymlinkDescendantContainment verifies [P1]:
// When a chart directory contains a directory symlink whose resolved target is within AllowedBasePath,
// but that target contains a nested symlink pointing outside AllowedBasePath (e.g.
// chart/files -> allowed/shared and allowed/shared/sentinel -> outside/sentinel),
// traversal detects the external descendant and rejects the chart before Helm reads it.
// Also verifies that symlinked chart roots are resolved and traversed with cycle protection.
func TestReview4034DirectorySymlinkDescendantContainment(t *testing.T) {
	allowedBase := t.TempDir()
	outsideDir := t.TempDir()

	// External secret sentinel
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	require.NoError(t, os.WriteFile(outsideFile, []byte("SUPER_SECRET_LEAK\n"), 0600))

	// Shared folder inside allowedBase
	sharedDir := filepath.Join(allowedBase, "shared")
	require.NoError(t, os.MkdirAll(sharedDir, 0700))
	// Nested symlink inside shared pointing outside allowedBase
	require.NoError(t, os.Symlink(outsideFile, filepath.Join(sharedDir, "sentinel")))

	// Chart inside allowedBase
	chartDir := filepath.Join(allowedBase, "chart")
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "templates"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: dirsymlinkchart\nversion: 0.1.0\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "values.yaml"), []byte("dummy: val\n"), 0600))

	// Directory symlink: chart/files -> allowed/shared
	require.NoError(t, os.Symlink(sharedDir, filepath.Join(chartDir, "files")))

	// Template reading files/sentinel via Helm's .Files.Get
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "templates", "secret.yaml"), []byte(`apiVersion: v1
kind: Secret
metadata:
  name: leak-secret
stringData:
  CONTENT: {{ .Files.Get "files/sentinel" }}
`), 0600))

	outDir := t.TempDir()
	sugg := HelmFixSuggestion{
		Resource: &reporthandling.Resource{
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Secret",
				"metadata":   map[string]interface{}{"name": "leak-secret"},
				"stringData": map[string]interface{}{"CONTENT": "SUPER_SECRET_LEAK"},
			},
		},
		ChartPath:       chartDir,
		AllowedBasePath: allowedBase,
		HelmValueOptions: cautils.HelmValueOptions{
			Values: []string{"dummy=val"},
		},
		FixPaths: []armotypes.FixPath{{Path: "metadata.labels.patched", Value: "true"}},
	}

	res, err := EmitKustomizePatch([]HelmFixSuggestion{sugg}, outDir)
	require.NoError(t, err)
	assert.Empty(t, res.EmittedResources)
	require.Len(t, res.SkippedResources, 1)
	assert.Contains(t, res.SkippedResources[0].Reason, "outside allowed base path")

	baseFile := filepath.Join(outDir, "base.yaml")
	if data, err := os.ReadFile(baseFile); err == nil {
		assert.NotContains(t, string(data), "SUPER_SECRET_LEAK")
	}

	// Also verify symlinked chart root (chart root is itself a symlink)
	chartLink := filepath.Join(allowedBase, "chart-symlink")
	require.NoError(t, os.Symlink(chartDir, chartLink))
	suggLink := sugg
	suggLink.ChartPath = chartLink
	outDir2 := t.TempDir()
	res2, err := EmitKustomizePatch([]HelmFixSuggestion{suggLink}, outDir2)
	require.NoError(t, err)
	assert.Empty(t, res2.EmittedResources)
	require.Len(t, res2.SkippedResources, 1)
	assert.Contains(t, res2.SkippedResources[0].Reason, "outside allowed base path")
}

// TestReview4034FileValuesContainment verifies that FileValues (--set-file) operands
// pointing to files outside AllowedBasePath are constrained and rejected.
func TestReview4034FileValuesContainment(t *testing.T) {
	allowedBase := t.TempDir()
	outsideDir := t.TempDir()

	outsideFile := filepath.Join(outsideDir, "outside-secret.txt")
	require.NoError(t, os.WriteFile(outsideFile, []byte("OUTSIDE_FILE_VAL\n"), 0600))

	insideFile := filepath.Join(allowedBase, "inside-secret.txt")
	require.NoError(t, os.WriteFile(insideFile, []byte("INSIDE_FILE_VAL\n"), 0600))

	chartDir := filepath.Join(allowedBase, "chart")
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "templates"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: filevalchart\nversion: 0.1.0\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "values.yaml"), []byte("myval: default\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "templates", "service.yaml"), []byte(`apiVersion: v1
kind: Service
metadata:
  name: my-service
  labels:
    content: {{ .Values.myval }}
spec:
  ports:
  - port: 80
`), 0600))

	t.Run("rejects external FileValues", func(t *testing.T) {
		outDir := t.TempDir()
		sugg := HelmFixSuggestion{
			Resource: &reporthandling.Resource{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Service",
					"metadata": map[string]interface{}{
						"name":   "my-service",
						"labels": map[string]interface{}{"content": "OUTSIDE_FILE_VAL"},
					},
					"spec": map[string]interface{}{
						"ports": []interface{}{
							map[string]interface{}{"port": 80},
						},
					},
				},
			},
			ChartPath:       chartDir,
			AllowedBasePath: allowedBase,
			HelmValueOptions: cautils.HelmValueOptions{
				FileValues: []string{fmt.Sprintf("myval=%s", outsideFile)},
			},
			FixPaths: []armotypes.FixPath{{Path: "metadata.labels.patched", Value: "true"}},
		}

		res, err := EmitKustomizePatch([]HelmFixSuggestion{sugg}, outDir)
		require.NoError(t, err)
		assert.Empty(t, res.EmittedResources)
		require.Len(t, res.SkippedResources, 1)
		assert.Contains(t, res.SkippedResources[0].Reason, "file-values file")
		assert.Contains(t, res.SkippedResources[0].Reason, "outside allowed base path")
	})

	t.Run("accepts internal FileValues", func(t *testing.T) {
		outDir := t.TempDir()
		sugg := HelmFixSuggestion{
			Resource: &reporthandling.Resource{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Service",
					"metadata": map[string]interface{}{
						"name":   "my-service",
						"labels": map[string]interface{}{"content": "INSIDE_FILE_VAL"},
					},
					"spec": map[string]interface{}{
						"ports": []interface{}{
							map[string]interface{}{"port": 80},
						},
					},
				},
			},
			ChartPath:       chartDir,
			AllowedBasePath: allowedBase,
			HelmValueOptions: cautils.HelmValueOptions{
				FileValues: []string{fmt.Sprintf("myval=%s", insideFile)},
			},
			FixPaths: []armotypes.FixPath{{Path: "metadata.labels.patched", Value: "true"}},
		}

		res, err := EmitKustomizePatch([]HelmFixSuggestion{sugg}, outDir)
		require.NoError(t, err)
		require.Len(t, res.EmittedResources, 1)

		k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
		resMap, err := k.Run(filesys.MakeFsOnDisk(), outDir)
		require.NoError(t, err)
		outYaml, err := resMap.AsYaml()
		require.NoError(t, err)
		assert.Contains(t, string(outYaml), "INSIDE_FILE_VAL")
	})
}
