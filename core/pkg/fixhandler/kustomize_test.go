package fixhandler

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"
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
			Resource:  res,
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
			Resource:  makeResourceWithNS("Deployment", "blue", "nginx"),
			ChartName: "my-chart",
			FixPaths:  []armotypes.FixPath{{Path: "spec.template.spec.securityContext.runAsNonRoot", Value: "true"}},
		},
		{
			Resource:  makeResourceWithNS("Deployment", "green", "nginx"),
			ChartName: "my-chart",
			FixPaths:  []armotypes.FixPath{{Path: "spec.template.spec.securityContext.runAsNonRoot", Value: "true"}},
		},
	}

	require.NoError(t, EmitKustomizePatch(suggestions, dir))

	assert.FileExists(t, filepath.Join(dir, "kustomization.yaml"))
	kustContent, _ := os.ReadFile(filepath.Join(dir, "kustomization.yaml"))
	kustStr := string(kustContent)
	assert.Contains(t, kustStr, "apps-Deployment-blue-nginx-")
	assert.Contains(t, kustStr, "apps-Deployment-green-nginx-")
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
			FixPaths:  []armotypes.FixPath{},
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
			Resource:  res,
			ChartName: "my-chart",
			FixPaths:  []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.capabilities.drop", Value: `["ALL"]`}},
		},
	}
	require.NoError(t, EmitKustomizePatch(suggestions, dir))
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
			Resource:  makeResource("../escaped", "../../badname"),
			ChartName: "my-chart",
			FixPaths:  []armotypes.FixPath{{Path: "spec.securityContext.runAsNonRoot", Value: "true"}},
		},
	}
	require.NoError(t, EmitKustomizePatch(suggestions, dir))

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
			Resource:  makeResource("Deployment", "my-app"),
			ChartName: "my-chart",
			FixPaths:  []armotypes.FixPath{{Path: "spec.storageClassName", Value: "null"}},
		},
	}
	require.NoError(t, EmitKustomizePatch(suggestions, dir))
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
			Resource:  res,
			ChartName: "my-chart",
			FixPaths:  []armotypes.FixPath{{Path: "spec.template.spec.containers[0]", Value: `{"name":"demo","image":"nginx:1.28"}`}},
		},
	}
	require.NoError(t, EmitKustomizePatch(suggestions, dir))
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
			Resource:  res,
			ChartName: "my-chart",
			FixPaths: []armotypes.FixPath{
				{Path: "spec.template.spec.containers[*].securityContext.privileged", Value: "false"},
			},
		},
	}

	require.NoError(t, EmitKustomizePatch(suggestions, dir))

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
			Resource:  pod,
			ChartName: "test-chart",
			FixPaths: []armotypes.FixPath{
				{Path: "spec.containers[0].securityContext.privileged", Value: "false"},
				{Path: "spec.containers[0].securityContext.runAsNonRoot", Value: "true"},
			},
		},
	}

	require.NoError(t, EmitKustomizePatch(suggestions, dir))

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
			Resource:  dep1,
			ChartName: "chart-1",
			FixPaths:  []armotypes.FixPath{{Path: "spec.replicas", Value: "2"}},
		},
		{
			Resource:  dep2,
			ChartName: "chart-2",
			FixPaths:  []armotypes.FixPath{{Path: "spec.replicas", Value: "3"}},
		},
	}

	require.NoError(t, EmitKustomizePatch(suggestions, dir))

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
			Resource:  makeResource("Deployment", "perm-app"),
			ChartName: "my-chart",
			FixPaths:  []armotypes.FixPath{{Path: "spec.replicas", Value: "2"}},
		},
	}

	require.NoError(t, EmitKustomizePatch(suggestions, outDir))

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
