package fixhandler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/gofrs/flock"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"
	"sigs.k8s.io/kustomize/kyaml/resid"
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

// makeResource builds a minimal reporthandling.Resource with the given kind and name,
// using valid Kubernetes apiVersions for standard resources.
func makeResource(kind, name string) *reporthandling.Resource {
	apiVersion := "apps/v1"
	switch kind {
	case "Service", "ConfigMap", "Secret", "Pod", "ServiceAccount", "PersistentVolumeClaim", "Endpoints", "LimitRange", "ResourceQuota", "Namespace", "Node", "PersistentVolume":
		apiVersion = "v1"
	case "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding":
		apiVersion = "rbac.authorization.k8s.io/v1"
	case "Job", "CronJob":
		apiVersion = "batch/v1"
	case "Ingress", "NetworkPolicy":
		apiVersion = "networking.k8s.io/v1"
	case "CustomResourceDefinition":
		apiVersion = "apiextensions.k8s.io/v1"
	}
	return &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": apiVersion,
			"kind":       kind,
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": "default",
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
	assert.Contains(t, patchStr, "value: \"null\"")
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

	_, err := EmitKustomizePatch(suggestions, outDir, WithOverwrite(true))
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
		unredactedContainers := []corev1.Container{
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

		bUnredacted, err := json.Marshal(map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]interface{}{"name": "my-app"},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": unredactedContainers,
					},
				},
			},
		})
		require.NoError(t, err)
		var unredactedObj map[string]interface{}
		require.NoError(t, json.Unmarshal(bUnredacted, &unredactedObj))

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

		// Even with HelmValueOptions matching scan overrides, supplying value overrides alone does not
		// verify scan-time render contents against redacted scan reports; generation must decline.
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
		assert.Empty(t, res2.EmittedResources, "must decline redacted report even with HelmValueOptions")
		require.Len(t, res2.SkippedResources, 1)
		assert.Contains(t, res2.SkippedResources[0].Reason, "scan report redacts container environment configuration")

		_, err = os.Stat(filepath.Join(outDir2, "base.yaml"))
		assert.True(t, os.IsNotExist(err), "base.yaml must not be written when declined")

		// When a verified unredacted base is provided, generation succeeds and preserves live configuration
		outDir3 := t.TempDir()
		suggsWithUnredactedBase := []HelmFixSuggestion{
			{
				Resource:       scannedRes,
				UnredactedBase: unredactedObj,
				ChartPath:      chartDir,
				HelmValueOptions: cautils.HelmValueOptions{
					Values: []string{"envFrom=prod-config", "appMode=production"},
				},
				FixPaths: []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
			},
		}
		res3, err := EmitKustomizePatch(suggsWithUnredactedBase, outDir3)
		require.NoError(t, err)
		require.Len(t, res3.EmittedResources, 1)

		k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
		resMap, err := k.Run(filesys.MakeFsOnDisk(), outDir3)
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
				Resource:           &reporthandling.Resource{Object: scannedObj},
				ChartPath:          chartDirNoRes,
				FidelityProvenance: true,
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
	unredactedContainers := []corev1.Container{
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
	bUnredacted, err := json.Marshal(map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]interface{}{"name": "my-app"},
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": unredactedContainers,
				},
			},
		},
	})
	require.NoError(t, err)
	var unredactedObj map[string]interface{}
	require.NoError(t, json.Unmarshal(bUnredacted, &unredactedObj))

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

	t.Run("declines with value overrides alone, but preserves when verified unredacted base is supplied", func(t *testing.T) {
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
		assert.Empty(t, res.EmittedResources, "must decline redacted report even with HelmValueOptions")
		require.Len(t, res.SkippedResources, 1)
		assert.Contains(t, res.SkippedResources[0].Reason, "scan report redacts container environment configuration")

		// With verified unredacted base, generation succeeds and preserves envFrom
		outDirPreserved := t.TempDir()
		suggsPreserved := []HelmFixSuggestion{
			{
				Resource:       scannedRes,
				UnredactedBase: unredactedObj,
				ChartPath:      chartDir,
				HelmValueOptions: cautils.HelmValueOptions{
					Values: []string{"extraEnvFrom[0].configMapRef.name=prod-config"},
				},
				FixPaths: []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
			},
		}

		resPreserved, err := EmitKustomizePatch(suggsPreserved, outDirPreserved)
		require.NoError(t, err)
		require.Len(t, resPreserved.EmittedResources, 1)

		k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
		resMap, err := k.Run(filesys.MakeFsOnDisk(), outDirPreserved)
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

// TestReview4034HelmOverlayDeclinesWhenValuesFileChangedRedactedSetting verifies that
// when a values file path is supplied but its content changed a redacted setting (such as envFrom)
// after scan time — including changing the reference or removing envFrom entirely — the overlay
// generator declines the resource rather than silently overwriting or omitting the application's
// configuration with the changed values.
func TestReview4034HelmOverlayDeclinesWhenValuesFileChangedRedactedSetting(t *testing.T) {
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: appchart\nversion: 0.1.0\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "values.yaml"), []byte("configMapName: default-config\n"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "templates"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "templates", "deployment.yaml"), []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: prod-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: example:v1
        {{- if .Values.configMapName }}
        envFrom:
        - configMapRef:
            name: {{ .Values.configMapName }}
        {{- end }}
        securityContext:
          privileged: true
`), 0600))

	// 1. Write production.yaml setting envFrom ConfigMap to prod-config
	valuesFile := filepath.Join(chartDir, "production.yaml")
	require.NoError(t, os.WriteFile(valuesFile, []byte("configMapName: prod-config\n"), 0600))

	// 2. Render Deployment using the real Helm renderer
	sourceToWorkloads, _, _, err := cautils.LoadResourcesFromHelmCharts(context.Background(), chartDir, cautils.HelmValueOptions{
		ValueFiles: []string{valuesFile},
	})
	require.NoError(t, err)

	var renderedObj map[string]interface{}
	for _, workloads := range sourceToWorkloads {
		for _, w := range workloads {
			if w.GetKind() == "Deployment" && w.GetName() == "prod-app" {
				renderedObj = deepCopyMap(w.GetObject())
				break
			}
		}
	}
	require.NotNil(t, renderedObj)

	// Save an unredacted base copy for later preservation verification
	unredactedBase := deepCopyMap(renderedObj)

	// 3. Redact using the actual scanner removeContainersData (clears envFrom without leaving placeholder)
	containers := getContainersFromObj(renderedObj)
	require.NotEmpty(t, containers)
	var coreContainers []corev1.Container
	containerBytes, err := json.Marshal(containers)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(containerBytes, &coreContainers))
	removeContainersData(coreContainers)
	require.Nil(t, coreContainers[0].EnvFrom, "scanner redactor must have cleared envFrom")

	// 4. JSON serialization roundtrip to simulate scan report persistence
	redactedContainerBytes, err := json.Marshal(coreContainers)
	require.NoError(t, err)
	var unmarshaledContainers []interface{}
	require.NoError(t, json.Unmarshal(redactedContainerBytes, &unmarshaledContainers))

	scannedObj := deepCopyMap(renderedObj)
	spec := scannedObj["spec"].(map[string]interface{})
	tmpl := spec["template"].(map[string]interface{})
	tmplSpec := tmpl["spec"].(map[string]interface{})
	tmplSpec["containers"] = unmarshaledContainers

	scannedRes := &reporthandling.Resource{
		Object: scannedObj,
		Source: &reporthandling.Source{
			FileType:         reporthandling.SourceTypeHelmChart,
			HelmPath:         chartDir,
			HelmChartName:    "appchart",
			HelmTemplateFile: "templates/deployment.yaml",
		},
	}

	// 5. Case A: Changed values file removes envFrom entirely (configMapName: "")
	// Both scanned report and new render candidate lack envFrom (ambiguous both-absent case).
	// Without verified scan-time provenance, generation must decline.
	require.NoError(t, os.WriteFile(valuesFile, []byte("configMapName: \"\"\n"), 0600))

	outDirRemoved := t.TempDir()
	suggsRemoved := []HelmFixSuggestion{
		{
			Resource:  scannedRes,
			ChartPath: chartDir,
			HelmValueOptions: cautils.HelmValueOptions{
				ValueFiles: []string{valuesFile},
			},
			FixPaths: []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
		},
	}
	resRemoved, err := EmitKustomizePatch(suggsRemoved, outDirRemoved)
	require.NoError(t, err)
	assert.Empty(t, resRemoved.EmittedResources, "must decline generation when values file removed envFrom entirely")
	require.Len(t, resRemoved.SkippedResources, 1, "must record declined resource")
	assert.Contains(t, resRemoved.SkippedResources[0].Reason, "scan report redacts container environment configuration")

	_, err = os.Stat(filepath.Join(outDirRemoved, "base.yaml"))
	assert.True(t, os.IsNotExist(err), "base.yaml must not be written when declined for removed envFrom")

	// 6. Case B: Changed values file modifies envFrom reference (prod-config -> dev-config)
	require.NoError(t, os.WriteFile(valuesFile, []byte("configMapName: dev-config\n"), 0600))

	outDirModified := t.TempDir()
	suggsModified := []HelmFixSuggestion{
		{
			Resource:  scannedRes,
			ChartPath: chartDir,
			HelmValueOptions: cautils.HelmValueOptions{
				ValueFiles: []string{valuesFile},
			},
			FixPaths: []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
		},
	}
	resModified, err := EmitKustomizePatch(suggsModified, outDirModified)
	require.NoError(t, err)
	assert.Empty(t, resModified.EmittedResources, "must decline generation when values file changed envFrom to dev-config")
	require.Len(t, resModified.SkippedResources, 1, "must record declined resource")
	assert.Contains(t, resModified.SkippedResources[0].Reason, "scan report redacts container environment configuration")

	_, err = os.Stat(filepath.Join(outDirModified, "base.yaml"))
	assert.True(t, os.IsNotExist(err), "base.yaml must not be written when declined")

	// 7. Case C: When a verified unredacted base is preserved, generation succeeds and preserves prod-config
	outDirPreserved := t.TempDir()
	suggsPreserved := []HelmFixSuggestion{
		{
			Resource:       scannedRes,
			UnredactedBase: unredactedBase,
			ChartPath:      chartDir,
			HelmValueOptions: cautils.HelmValueOptions{
				ValueFiles: []string{valuesFile},
			},
			FixPaths: []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
		},
	}
	resPreserved, err := EmitKustomizePatch(suggsPreserved, outDirPreserved)
	require.NoError(t, err)
	require.Len(t, resPreserved.EmittedResources, 1)

	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	resMap, err := k.Run(filesys.MakeFsOnDisk(), outDirPreserved)
	require.NoError(t, err)
	outYaml, err := resMap.AsYaml()
	require.NoError(t, err)
	assert.Contains(t, string(outYaml), "prod-config", "verified unredacted base must preserve prod-config")
	assert.NotContains(t, string(outYaml), "dev-config", "must not contain dev-config from changed values file")
	assert.Contains(t, string(outYaml), "privileged: false")
}

// TestReview4034AmbiguousBothAbsentGuard verifies the guard logic
// directly for the ambiguous both-absent envFrom case: when a scanned object has containers
// and the candidate object lacks envFrom with no explicit env entries or placeholders,
// resolveBaseObject must decline unless verified scan-time provenance or an unredacted base is provided.
func TestReview4034AmbiguousBothAbsentGuard(t *testing.T) {
	scannedObj := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]interface{}{"name": "prod-app"},
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"name":  "app",
							"image": "example:v1",
							"securityContext": map[string]interface{}{
								"privileged": true,
							},
						},
					},
				},
			},
		},
	}

	candidateObj := deepCopyMap(scannedObj)

	// Surviving non-redacted fields match
	assert.NoError(t, verifyScannedFieldsMatch(scannedObj, candidateObj, ""))

	// Without verified scan-time provenance (no UnredactedBase or FidelityProvenance),
	// the ambiguous both-absent case is declined because scanner removes envFrom without placeholder.
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: app\nversion: 0.1.0\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "values.yaml"), []byte("configMapName: \"\"\n"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "templates"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "templates", "deployment.yaml"), []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: prod-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: example:v1
        {{- if .Values.configMapName }}
        envFrom:
        - configMapRef:
            name: {{ .Values.configMapName }}
        {{- end }}
        securityContext:
          privileged: true
`), 0600))

	sugg := HelmFixSuggestion{
		Resource:     &reporthandling.Resource{Object: scannedObj},
		ChartPath:    chartDir,
		TemplateFile: "templates/deployment.yaml",
		HelmValueOptions: cautils.HelmValueOptions{
			ValueFiles: []string{filepath.Join(chartDir, "values.yaml")},
		},
	}

	resolved, reason := resolveBaseObject(sugg, nil)
	assert.Nil(t, resolved, "must decline ambiguous both-absent case without verified scan-time provenance")
	assert.Contains(t, reason, "scan report redacts container environment configuration")
}

// TestReview4034ValuesDrivenTemplateAmbiguousEnvFromDeclined verifies that when a Deployment template
// renders its container list dynamically from values (e.g. {{- toYaml .Values.containers | nindent 8 }})
// and never names envFrom literally:
//  1. At scan time, production.yaml supplies a container with envFrom: [{configMapRef: {name: prod-config}}],
//     and the scanner redacts envFrom from the report without leaving a placeholder.
//  2. After scanning, envFrom is removed from that same values file.
//  3. The rendered candidate also lacks envFrom, and the template never names it.
//  4. Searching source text cannot prove fidelity; resolveBaseObject / EmitKustomizePatch must visibly decline
//     to prevent dropping application configuration while applying an unrelated security fix.
//  5. When verified scan-time provenance or an unredacted base is provided, generation succeeds and preserves
//     the original application configuration (prod-config).
func TestReview4034ValuesDrivenTemplateAmbiguousEnvFromDeclined(t *testing.T) {
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: valuesdrivenchart\nversion: 0.1.0\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "values.yaml"), []byte("containers: []\n"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "templates"), 0700))

	// Template renders container list via toYaml from .Values.containers; never mentions envFrom literally
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "templates", "deployment.yaml"), []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: prod-app
spec:
  template:
    spec:
      containers:
        {{- toYaml .Values.containers | nindent 8 }}
`), 0600))

	// 1. Write production.yaml initially supplying container with envFrom (prod-config)
	valuesFile := filepath.Join(chartDir, "production.yaml")
	require.NoError(t, os.WriteFile(valuesFile, []byte(`containers:
- name: app
  image: example:v1
  envFrom:
  - configMapRef:
      name: prod-config
  securityContext:
    privileged: true
`), 0600))

	// 2. Render Deployment using the real Helm renderer to obtain the scan-time object
	sourceToWorkloads, _, _, err := cautils.LoadResourcesFromHelmCharts(context.Background(), chartDir, cautils.HelmValueOptions{
		ValueFiles: []string{valuesFile},
	})
	require.NoError(t, err)

	var renderedObj map[string]interface{}
	for _, workloads := range sourceToWorkloads {
		for _, w := range workloads {
			if w.GetKind() == "Deployment" && w.GetName() == "prod-app" {
				renderedObj = deepCopyMap(w.GetObject())
				break
			}
		}
	}
	require.NotNil(t, renderedObj, "must find rendered prod-app deployment")

	// Save an unredacted base copy for later provenance verification
	unredactedObj := deepCopyMap(renderedObj)

	// 3. Redact using the actual scanner removeContainersData (clears envFrom without leaving placeholder)
	renderedContainers := getContainersFromObj(renderedObj)
	require.Len(t, renderedContainers, 1)
	coreContainers := []corev1.Container{
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
	removeContainersData(coreContainers)
	require.Nil(t, coreContainers[0].EnvFrom, "actual scanner redactor must have cleared envFrom")
	require.Empty(t, coreContainers[0].Env, "env must remain empty")

	bContainers, err := json.Marshal(coreContainers)
	require.NoError(t, err)
	var redactedContainers []interface{}
	require.NoError(t, json.Unmarshal(bContainers, &redactedContainers))

	scannedObj := deepCopyMap(renderedObj)
	scannedObj["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})["containers"] = redactedContainers
	scannedRes := &reporthandling.Resource{Object: scannedObj}

	// 4. Update production.yaml to remove envFrom entirely
	require.NoError(t, os.WriteFile(valuesFile, []byte(`containers:
- name: app
  image: example:v1
  securityContext:
    privileged: true
`), 0600))

	// 5. Case A: Overlay generation without verified scan-time provenance must be declined
	outDir := t.TempDir()
	suggs := []HelmFixSuggestion{
		{
			Resource:     scannedRes,
			ChartPath:    chartDir,
			TemplateFile: "templates/deployment.yaml",
			HelmValueOptions: cautils.HelmValueOptions{
				ValueFiles: []string{valuesFile},
			},
			FixPaths: []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
		},
	}

	res, err := EmitKustomizePatch(suggs, outDir)
	require.NoError(t, err)
	assert.Empty(t, res.EmittedResources, "must decline generation when values-driven template removed envFrom")
	require.Len(t, res.SkippedResources, 1, "must record declined resource")
	assert.Contains(t, res.SkippedResources[0].Reason, "scan report redacts container environment configuration")

	_, err = os.Stat(filepath.Join(outDir, "base.yaml"))
	assert.True(t, os.IsNotExist(err), "base.yaml must not be written when declined for ambiguous envFrom")

	// Verify standard-library helper guard behavior directly (matching maintainer probe)
	candidateWorkloads, _, _, err := cautils.LoadResourcesFromHelmCharts(context.Background(), chartDir, cautils.HelmValueOptions{
		ValueFiles: []string{valuesFile},
	})
	require.NoError(t, err)
	var candidateObj map[string]interface{}
	for _, workloads := range candidateWorkloads {
		for _, w := range workloads {
			if w.GetKind() == "Deployment" && w.GetName() == "prod-app" {
				candidateObj = deepCopyMap(w.GetObject())
				break
			}
		}
	}
	require.NotNil(t, candidateObj)
	assert.False(t, hasRedactedEnvironment(scannedObj, candidateObj), "hasRedactedEnvironment is false when both lack envFrom")
	assert.NoError(t, verifyScannedFieldsMatch(scannedObj, candidateObj, ""), "comparison is nil because surviving fields match")
	resolved, reason := resolveBaseObject(suggs[0], nil)
	assert.Nil(t, resolved, "resolveBaseObject must decline ambiguous values-driven template")
	assert.Contains(t, reason, "scan report redacts container environment configuration")

	// 6. Case B: When a verified unredacted base is preserved, generation succeeds and preserves prod-config
	outDirPreserved := t.TempDir()
	suggsPreserved := []HelmFixSuggestion{
		{
			Resource:       scannedRes,
			UnredactedBase: unredactedObj,
			ChartPath:      chartDir,
			TemplateFile:   "templates/deployment.yaml",
			HelmValueOptions: cautils.HelmValueOptions{
				ValueFiles: []string{valuesFile},
			},
			FixPaths: []armotypes.FixPath{{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
		},
	}

	resPreserved, err := EmitKustomizePatch(suggsPreserved, outDirPreserved)
	require.NoError(t, err)
	t.Logf("Skipped: %+v", resPreserved.SkippedResources)
	require.Len(t, resPreserved.EmittedResources, 1, "must emit patch when unredacted base is provided")
	assert.Empty(t, resPreserved.SkippedResources)

	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	resMap, err := k.Run(filesys.MakeFsOnDisk(), outDirPreserved)
	require.NoError(t, err)
	outYaml, err := resMap.AsYaml()
	require.NoError(t, err)
	assert.Contains(t, string(outYaml), "prod-config", "verified unredacted base must preserve prod-config")
	assert.Contains(t, string(outYaml), "privileged: false", "must apply requested security fix")
}

func TestReview4034SourcePathNormalizedOnRenderedResource(t *testing.T) {
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: test-svc\nversion: 0.1.0\n"), 0600))
	templatesDir := filepath.Join(chartDir, "templates")
	require.NoError(t, os.MkdirAll(templatesDir, 0755))

	svcYaml := `apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  ports:
  - port: 80
  externalTrafficPolicy: Cluster
`
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, "service.yaml"), []byte(svcYaml), 0600))

	// The scan report retains sourcePath and path, while the re-rendered base removes them.
	scannedSvc := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Service",
			"path":       "templates/service.yaml",
			"sourcePath": filepath.Join(chartDir, "templates/service.yaml"),
			"metadata": map[string]interface{}{
				"name": "my-service",
			},
			"spec": map[string]interface{}{
				"ports": []interface{}{
					map[string]interface{}{"port": 80},
				},
				"externalTrafficPolicy": "Cluster",
			},
		},
	}

	outDir := t.TempDir()
	suggs := []HelmFixSuggestion{
		{
			Resource:     scannedSvc,
			ChartPath:    chartDir,
			TemplateFile: "templates/service.yaml",
			FixPaths:     []armotypes.FixPath{{Path: "spec.externalTrafficPolicy", Value: "Local"}},
		},
	}

	res, err := EmitKustomizePatch(suggs, outDir)
	require.NoError(t, err)
	require.Len(t, res.EmittedResources, 1, "unchanged rendered Service must not be declined due to sourcePath")
	assert.Empty(t, res.SkippedResources)

	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	resMap, err := k.Run(filesys.MakeFsOnDisk(), outDir)
	require.NoError(t, err)
	outYaml, err := resMap.AsYaml()
	require.NoError(t, err)
	assert.Contains(t, string(outYaml), "externalTrafficPolicy: Local")
}

func TestReview4034NamespaceScopedTargetsDoNotOverwriteProdFix(t *testing.T) {
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: test-svc\nversion: 0.1.0\n"), 0600))
	templatesDir := filepath.Join(chartDir, "templates")
	require.NoError(t, os.MkdirAll(templatesDir, 0755))

	svcProdYaml := `apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: prod
spec:
  externalTrafficPolicy: Cluster
`
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, "svc-prod.yaml"), []byte(svcProdYaml), 0600))

	svcNoNsYaml := `apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  externalTrafficPolicy: Cluster
`
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, "svc-nons.yaml"), []byte(svcNoNsYaml), 0600))

	prodSvc := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Service",
			"metadata": map[string]interface{}{
				"name":      "web",
				"namespace": "prod",
			},
			"spec": map[string]interface{}{
				"externalTrafficPolicy": "Cluster",
			},
		},
	}
	noNsSvc := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Service",
			"metadata": map[string]interface{}{
				"name": "web",
			},
			"spec": map[string]interface{}{
				"externalTrafficPolicy": "Cluster",
			},
		},
	}

	outDir := t.TempDir()
	suggs := []HelmFixSuggestion{
		{
			Resource:     prodSvc,
			ChartPath:    chartDir,
			TemplateFile: "templates/svc-prod.yaml",
			FixPaths:     []armotypes.FixPath{{Path: "spec.externalTrafficPolicy", Value: "Local"}},
		},
		{
			Resource:     noNsSvc,
			ChartPath:    chartDir,
			TemplateFile: "templates/svc-nons.yaml",
			FixPaths:     []armotypes.FixPath{{Path: "spec.externalTrafficPolicy", Value: "Cluster"}},
		},
	}

	res, err := EmitKustomizePatch(suggs, outDir)
	require.NoError(t, err)
	require.Len(t, res.EmittedResources, 2)
	assert.Empty(t, res.SkippedResources)

	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	resMap, err := k.Run(filesys.MakeFsOnDisk(), outDir)
	require.NoError(t, err)
	outYaml, err := resMap.AsYaml()
	require.NoError(t, err)

	docs := splitYamlDocs(outYaml)
	require.Len(t, docs, 2)

	var foundProd, foundNoNs bool
	for _, docBytes := range docs {
		var s struct {
			Metadata struct {
				Name      string `yaml:"name"`
				Namespace string `yaml:"namespace"`
			} `yaml:"metadata"`
			Spec struct {
				ExternalTrafficPolicy string `yaml:"externalTrafficPolicy"`
			} `yaml:"spec"`
		}
		require.NoError(t, yaml.Unmarshal(docBytes, &s))
		if s.Metadata.Namespace == "prod" {
			foundProd = true
			assert.Equal(t, "Local", s.Spec.ExternalTrafficPolicy, "prod fix must not be overwritten by namespace-less patch")
		} else {
			foundNoNs = true
			assert.Equal(t, "Cluster", s.Spec.ExternalTrafficPolicy)
		}
	}
	assert.True(t, foundProd, "prod service must be present in build output")
	assert.True(t, foundNoNs, "namespaceless service must be present in build output")

	// Verify ambiguous target collision is rejected
	svcDefaultYaml := `apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: default
spec:
  externalTrafficPolicy: Cluster
`
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, "svc-default.yaml"), []byte(svcDefaultYaml), 0600))

	explicitDefaultSvc := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Service",
			"metadata": map[string]interface{}{
				"name":      "web",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"externalTrafficPolicy": "Cluster",
			},
		},
	}
	ambiguousSuggs := []HelmFixSuggestion{
		{
			Resource:     noNsSvc,
			ChartPath:    chartDir,
			TemplateFile: "templates/svc-nons.yaml",
			FixPaths:     []armotypes.FixPath{{Path: "spec.externalTrafficPolicy", Value: "Cluster"}},
		},
		{
			Resource:     explicitDefaultSvc,
			ChartPath:    chartDir,
			TemplateFile: "templates/svc-default.yaml",
			FixPaths:     []armotypes.FixPath{{Path: "spec.externalTrafficPolicy", Value: "Local"}},
		},
	}
	_, err = EmitKustomizePatch(ambiguousSuggs, t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ambiguous patch target detected")
}

func TestReview4034RejectsAdditionalNonRedactedFieldsFromChartDrift(t *testing.T) {
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: test-svc\nversion: 0.1.0\n"), 0600))
	templatesDir := filepath.Join(chartDir, "templates")
	require.NoError(t, os.MkdirAll(templatesDir, 0755))

	// Chart was modified after scan to add a new externalIPs field
	svcDriftedYaml := `apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  ports:
  - port: 80
  externalIPs:
  - 198.51.100.1
  externalTrafficPolicy: Cluster
`
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, "service.yaml"), []byte(svcDriftedYaml), 0600))

	// Scanned resource did NOT have externalIPs
	scannedSvc := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Service",
			"sourcePath": filepath.Join(chartDir, "templates/service.yaml"),
			"metadata": map[string]interface{}{
				"name": "web",
			},
			"spec": map[string]interface{}{
				"ports": []interface{}{
					map[string]interface{}{"port": 80},
				},
				"externalTrafficPolicy": "Cluster",
			},
		},
	}

	outDir := t.TempDir()
	suggs := []HelmFixSuggestion{
		{
			Resource:     scannedSvc,
			ChartPath:    chartDir,
			TemplateFile: "templates/service.yaml",
			FixPaths:     []armotypes.FixPath{{Path: "spec.externalTrafficPolicy", Value: "Local"}},
		},
	}

	res, err := EmitKustomizePatch(suggs, outDir)
	require.NoError(t, err)
	assert.Empty(t, res.EmittedResources, "must decline when newly added non-redacted field is present in rendered chart")
	require.Len(t, res.SkippedResources, 1)
	assert.Contains(t, res.SkippedResources[0].Reason, "externalIPs")

	_, err = os.Stat(filepath.Join(outDir, "base.yaml"))
	assert.True(t, os.IsNotExist(err), "base.yaml must not be written when declined")
}

func TestReview4034ClusterScopedCSIDriverKustomizeBuild(t *testing.T) {
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: test-csi\nversion: 0.1.0\n"), 0600))
	templatesDir := filepath.Join(chartDir, "templates")
	require.NoError(t, os.MkdirAll(templatesDir, 0755))

	csiYaml := `apiVersion: storage.k8s.io/v1
kind: CSIDriver
metadata:
  name: my-csi-driver
spec:
  attachRequired: true
`
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, "csidriver.yaml"), []byte(csiYaml), 0600))

	scannedCSI := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "storage.k8s.io/v1",
			"kind":       "CSIDriver",
			"sourcePath": filepath.Join(chartDir, "templates/csidriver.yaml"),
			"metadata": map[string]interface{}{
				"name": "my-csi-driver",
			},
			"spec": map[string]interface{}{
				"attachRequired": true,
			},
		},
	}

	// Verify Kustomize's full GVK OpenAPI scope knowledge recognizes CSIDriver as cluster-scoped
	assert.True(t, resid.NewGvk("storage.k8s.io", "v1", "CSIDriver").IsClusterScoped())

	outDir := t.TempDir()
	suggs := []HelmFixSuggestion{
		{
			Resource:     scannedCSI,
			ChartPath:    chartDir,
			TemplateFile: "templates/csidriver.yaml",
			FixPaths:     []armotypes.FixPath{{Path: "spec.attachRequired", Value: "false"}},
		},
	}

	res, err := EmitKustomizePatch(suggs, outDir)
	require.NoError(t, err)
	require.Len(t, res.EmittedResources, 1)
	assert.Empty(t, res.SkippedResources)

	// Read generated kustomization.yaml to verify target.Namespace is omitted (not set to "default")
	kustBytes, err := os.ReadFile(filepath.Join(outDir, "kustomization.yaml"))
	require.NoError(t, err)
	var kd kustomizationDoc
	require.NoError(t, yaml.Unmarshal(kustBytes, &kd))
	require.Len(t, kd.Patches, 1)
	assert.Empty(t, kd.Patches[0].Target.Namespace, "cluster-scoped CSIDriver must not have target namespace default")

	// Execute actual kustomize build and assert attachRequired changed to false
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	resMap, err := k.Run(filesys.MakeFsOnDisk(), outDir)
	require.NoError(t, err)
	outYaml, err := resMap.AsYaml()
	require.NoError(t, err)

	assert.Contains(t, string(outYaml), "attachRequired: false", "kustomize build must apply patch modifying attachRequired to false")
	assert.NotContains(t, string(outYaml), "attachRequired: true", "kustomize build must not leave attachRequired: true")
}

func TestReview4034RejectsAddedServiceSelectorWithEmptyLeaf(t *testing.T) {
	// 1. Direct helper test: verifyScannedFieldsMatch rejects added selector with empty leaf {app: ""}
	scannedMap := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]interface{}{
			"name": "web",
		},
		"spec": map[string]interface{}{
			"externalTrafficPolicy": "Cluster",
		},
	}
	driftedMap := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]interface{}{
			"name": "web",
		},
		"spec": map[string]interface{}{
			"selector": map[string]interface{}{
				"app": "",
			},
			"externalTrafficPolicy": "Cluster",
		},
	}
	err := verifyScannedFieldsMatch(scannedMap, driftedMap, "")
	require.Error(t, err, "verifyScannedFieldsMatch must reject added selector even when leaf value is empty string")
	assert.Contains(t, err.Error(), "spec.selector")

	// Also verify when scanned resource had empty selector map {}
	scannedWithEmptySelector := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]interface{}{
			"name": "web",
		},
		"spec": map[string]interface{}{
			"selector":              map[string]interface{}{},
			"externalTrafficPolicy": "Cluster",
		},
	}
	errEmpty := verifyScannedFieldsMatch(scannedWithEmptySelector, driftedMap, "")
	require.Error(t, errEmpty, "verifyScannedFieldsMatch must reject {app: \"\"} when scanned was empty map")

	// 2. Full EmitKustomizePatch integration test: Service chart drift with {app: ""} is declined
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: test-svc\nversion: 0.1.0\n"), 0600))
	templatesDir := filepath.Join(chartDir, "templates")
	require.NoError(t, os.MkdirAll(templatesDir, 0755))

	svcDriftedYaml := `apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  selector:
    app: ""
  externalTrafficPolicy: Cluster
`
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, "service.yaml"), []byte(svcDriftedYaml), 0600))

	scannedSvc := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Service",
			"sourcePath": filepath.Join(chartDir, "templates/service.yaml"),
			"metadata": map[string]interface{}{
				"name": "web",
			},
			"spec": map[string]interface{}{
				"externalTrafficPolicy": "Cluster",
			},
		},
	}

	outDir := t.TempDir()
	suggs := []HelmFixSuggestion{
		{
			Resource:     scannedSvc,
			ChartPath:    chartDir,
			TemplateFile: "templates/service.yaml",
			FixPaths:     []armotypes.FixPath{{Path: "spec.externalTrafficPolicy", Value: "Local"}},
		},
	}

	res, err := EmitKustomizePatch(suggs, outDir)
	require.NoError(t, err)
	assert.Empty(t, res.EmittedResources, "must decline when chart drifted with selector {app: \"\"}")
	require.Len(t, res.SkippedResources, 1)
	assert.Contains(t, res.SkippedResources[0].Reason, "spec.selector")
}

func TestReview4034RejectsNullExternalIPsBecomingNonEmptyList(t *testing.T) {
	// 1. Direct helper test: null externalIPs in scanned resource cannot match nonempty list
	scannedMap := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]interface{}{
			"name": "web",
		},
		"spec": map[string]interface{}{
			"externalIPs":           nil,
			"externalTrafficPolicy": "Cluster",
		},
	}
	driftedMap := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]interface{}{
			"name": "web",
		},
		"spec": map[string]interface{}{
			"externalIPs": []interface{}{
				"198.51.100.1",
			},
			"externalTrafficPolicy": "Cluster",
		},
	}
	err := verifyScannedFieldsMatch(scannedMap, driftedMap, "")
	require.Error(t, err, "null externalIPs in scanned resource must not match nonempty rendered list")
	assert.Contains(t, err.Error(), "spec.externalIPs")

	// 2. Full EmitKustomizePatch test: declined when null externalIPs became nonempty list
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: test-svc\nversion: 0.1.0\n"), 0600))
	templatesDir := filepath.Join(chartDir, "templates")
	require.NoError(t, os.MkdirAll(templatesDir, 0755))

	svcDriftedYaml := `apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  externalIPs:
  - 198.51.100.1
  externalTrafficPolicy: Cluster
`
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, "service.yaml"), []byte(svcDriftedYaml), 0600))

	scannedSvc := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Service",
			"sourcePath": filepath.Join(chartDir, "templates/service.yaml"),
			"metadata": map[string]interface{}{
				"name": "web",
			},
			"spec": map[string]interface{}{
				"externalIPs":           nil,
				"externalTrafficPolicy": "Cluster",
			},
		},
	}

	outDir := t.TempDir()
	suggs := []HelmFixSuggestion{
		{
			Resource:     scannedSvc,
			ChartPath:    chartDir,
			TemplateFile: "templates/service.yaml",
			FixPaths:     []armotypes.FixPath{{Path: "spec.externalTrafficPolicy", Value: "Local"}},
		},
	}

	res, err := EmitKustomizePatch(suggs, outDir)
	require.NoError(t, err)
	assert.Empty(t, res.EmittedResources, "must decline when null externalIPs became nonempty list")
	require.Len(t, res.SkippedResources, 1)
	assert.Contains(t, res.SkippedResources[0].Reason, "externalIPs")
}

func TestReview4034SelectorRemovalAndConflationRegressions(t *testing.T) {
	// 1. Direct helper: scanned PDB spec.selector: {} rejected against rendered selector: null
	scannedPDB := map[string]interface{}{
		"apiVersion": "policy/v1",
		"kind":       "PodDisruptionBudget",
		"metadata": map[string]interface{}{
			"name": "app-pdb",
		},
		"spec": map[string]interface{}{
			"selector": map[string]interface{}{},
		},
	}
	renderedNullSelector := map[string]interface{}{
		"apiVersion": "policy/v1",
		"kind":       "PodDisruptionBudget",
		"metadata": map[string]interface{}{
			"name": "app-pdb",
		},
		"spec": map[string]interface{}{
			"selector": nil,
		},
	}
	errNull := verifyScannedFieldsMatch(scannedPDB, renderedNullSelector, "")
	require.Error(t, errNull, "empty selector {} in scanned PDB must not match rendered selector: null")
	assert.Contains(t, errNull.Error(), "spec.selector")

	// 2. Direct helper: scanned PDB spec.selector: {} rejected against rendered missing selector
	renderedMissingSelector := map[string]interface{}{
		"apiVersion": "policy/v1",
		"kind":       "PodDisruptionBudget",
		"metadata": map[string]interface{}{
			"name": "app-pdb",
		},
		"spec": map[string]interface{}{},
	}
	errMissing := verifyScannedFieldsMatch(scannedPDB, renderedMissingSelector, "")
	require.Error(t, errMissing, "empty selector {} in scanned PDB must not match omitted selector")
	assert.Contains(t, errMissing.Error(), "spec.selector")

	// 3. Direct helper: scanned Service selector with empty leaf {app: "web", canary: ""} rejected when canary is missing
	scannedSvc := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]interface{}{
			"name": "web",
		},
		"spec": map[string]interface{}{
			"selector": map[string]interface{}{
				"app":    "web",
				"canary": "",
			},
		},
	}
	renderedSvcMissingLeaf := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]interface{}{
			"name": "web",
		},
		"spec": map[string]interface{}{
			"selector": map[string]interface{}{
				"app": "web",
			},
		},
	}
	errLeaf := verifyScannedFieldsMatch(scannedSvc, renderedSvcMissingLeaf, "")
	require.Error(t, errLeaf, "missing empty-string leaf canary: \"\" must be rejected")
	assert.Contains(t, errLeaf.Error(), "spec.selector.canary")

	// 4. Direct helper: documented scanner-added container resources: {} accepted when omitted in rendered base
	scannedContainer := map[string]interface{}{
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":      "app",
					"resources": map[string]interface{}{},
				},
			},
		},
	}
	renderedContainerNoRes := map[string]interface{}{
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name": "app",
				},
			},
		},
	}
	errContainer := verifyScannedFieldsMatch(scannedContainer, renderedContainerNoRes, "")
	require.NoError(t, errContainer, "scanner-added empty resources: {} must match omitted container resources")

	// 5. Full EmitKustomizePatch integration test: PDB with empty selector {} declined when chart has null selector
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: test-pdb\nversion: 0.1.0\n"), 0600))
	templatesDir := filepath.Join(chartDir, "templates")
	require.NoError(t, os.MkdirAll(templatesDir, 0755))

	pdbChartYaml := `apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: my-pdb
spec:
  minAvailable: 1
  selector: null
`
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, "pdb.yaml"), []byte(pdbChartYaml), 0600))

	scannedPDBRes := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "policy/v1",
			"kind":       "PodDisruptionBudget",
			"sourcePath": filepath.Join(chartDir, "templates/pdb.yaml"),
			"metadata": map[string]interface{}{
				"name": "my-pdb",
			},
			"spec": map[string]interface{}{
				"minAvailable": 1,
				"selector":     map[string]interface{}{},
			},
		},
	}

	outDir := t.TempDir()
	suggs := []HelmFixSuggestion{
		{
			Resource:     scannedPDBRes,
			ChartPath:    chartDir,
			TemplateFile: "templates/pdb.yaml",
			FixPaths:     []armotypes.FixPath{{Path: "spec.minAvailable", Value: "2"}},
		},
	}

	res, err := EmitKustomizePatch(suggs, outDir)
	require.NoError(t, err)
	assert.Empty(t, res.EmittedResources, "must decline when scanned selector {} matches rendered selector: null")
	require.Len(t, res.SkippedResources, 1)
	assert.Contains(t, res.SkippedResources[0].Reason, "spec.selector")
}

func TestReview4034CrossNamespaceCustomResourceScopeRegression(t *testing.T) {
	// 1. Direct helper: custom resource example.com/v1 Node is NOT cluster-scoped
	customNodeKey := resourceKey{
		Group:     "example.com",
		Version:   "v1",
		Kind:      "Node",
		Namespace: "",
		Name:      "my-node",
	}
	assert.False(t, isClusterScopedResource(customNodeKey), "custom resource example.com/v1 Node must not be classified as cluster-scoped")

	// Standard Kubernetes core /v1 Node IS cluster-scoped
	standardNodeKey := resourceKey{
		Group:     "",
		Version:   "v1",
		Kind:      "Node",
		Namespace: "",
		Name:      "standard-node",
	}
	assert.True(t, isClusterScopedResource(standardNodeKey), "standard Kubernetes core /v1 Node must be classified as cluster-scoped")

	// 2. Full EmitKustomizePatch + Kustomize build test:
	// Two example.com/v1 Node resources named "my-node":
	// - One in namespace "prod" with spec.secure: true (fixed from false)
	// - One without a namespace (scoped to default) with spec.secure: false
	// The namespace-less patch must NOT target wildcard and must NOT overwrite prod's secure: true fix.
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: test-custom\nversion: 0.1.0\n"), 0600))
	templatesDir := filepath.Join(chartDir, "templates")
	require.NoError(t, os.MkdirAll(templatesDir, 0755))

	prodNodeYaml := `apiVersion: example.com/v1
kind: Node
metadata:
  name: my-node
  namespace: prod
spec:
  secure: false
`
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, "prod-node.yaml"), []byte(prodNodeYaml), 0600))

	clusterNodeYaml := `apiVersion: example.com/v1
kind: Node
metadata:
  name: my-node
spec:
  secure: false
`
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, "cluster-node.yaml"), []byte(clusterNodeYaml), 0600))

	scannedProdNode := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "example.com/v1",
			"kind":       "Node",
			"sourcePath": filepath.Join(chartDir, "templates/prod-node.yaml"),
			"metadata": map[string]interface{}{
				"name":      "my-node",
				"namespace": "prod",
			},
			"spec": map[string]interface{}{
				"secure": false,
			},
		},
	}

	scannedDefaultNode := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "example.com/v1",
			"kind":       "Node",
			"sourcePath": filepath.Join(chartDir, "templates/cluster-node.yaml"),
			"metadata": map[string]interface{}{
				"name": "my-node",
			},
			"spec": map[string]interface{}{
				"secure": false,
			},
		},
	}

	outDir := t.TempDir()
	suggs := []HelmFixSuggestion{
		{
			Resource:     scannedProdNode,
			ChartPath:    chartDir,
			TemplateFile: "templates/prod-node.yaml",
			FixPaths:     []armotypes.FixPath{{Path: "spec.secure", Value: "true"}},
		},
		{
			Resource:     scannedDefaultNode,
			ChartPath:    chartDir,
			TemplateFile: "templates/cluster-node.yaml",
			FixPaths:     []armotypes.FixPath{{Path: "spec.secure", Value: "false"}},
		},
	}

	res, err := EmitKustomizePatch(suggs, outDir)
	require.NoError(t, err)
	require.Len(t, res.EmittedResources, 2)
	assert.Empty(t, res.SkippedResources)

	// Read kustomization.yaml: verify namespace-less custom resource has target.Namespace = "default"
	kustBytes, err := os.ReadFile(filepath.Join(outDir, "kustomization.yaml"))
	require.NoError(t, err)
	var kd kustomizationDoc
	require.NoError(t, yaml.Unmarshal(kustBytes, &kd))
	require.Len(t, kd.Patches, 2)

	namespaces := []string{kd.Patches[0].Target.Namespace, kd.Patches[1].Target.Namespace}
	assert.Contains(t, namespaces, "prod")
	assert.Contains(t, namespaces, "default", "namespaceless custom resource must have target namespace defaulted to 'default', not empty wildcard")

	// Execute actual pinned Kustomize build
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	resMap, err := k.Run(filesys.MakeFsOnDisk(), outDir)
	require.NoError(t, err)
	outYaml, err := resMap.AsYaml()
	require.NoError(t, err)

	// Verify prod resource retained secure: true and was NOT reset to false by the other patch
	assert.Contains(t, string(outYaml), "namespace: prod")
	assert.Contains(t, string(outYaml), "secure: true")
}

// TestReview4034_APIGroupExactMatching verifies that target selector uses exact group matching (^$ for empty group,
// and escaped group names for non-empty groups) so that a Service patch in core group does not overwrite
// or patch a Service in a custom API group when kustomize build runs.
func TestReview4034_APIGroupExactMatching(t *testing.T) {
	dir := t.TempDir()

	coreSvc := makeResource("Service", "my-svc")
	coreSvc.SetApiVersion("v1")
	coreSvc.GetObject()["spec"] = map[string]interface{}{
		"ports": []interface{}{map[string]interface{}{"port": 80}},
	}

	customSvc := makeResource("Service", "my-svc")
	customSvc.SetApiVersion("custom.example.com/v1")
	customSvc.GetObject()["spec"] = map[string]interface{}{
		"ports": []interface{}{map[string]interface{}{"port": 8080}},
	}

	suggestions := []HelmFixSuggestion{
		{
			Resource:           coreSvc,
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{{Path: "metadata.labels.coreOnly", Value: "true"}},
		},
		{
			Resource:           customSvc,
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{{Path: "metadata.labels.customOnly", Value: "true"}},
		},
	}

	res, err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)
	require.Len(t, res.EmittedResources, 2)

	// Check kustomization.yaml
	kustContent, err := os.ReadFile(filepath.Join(dir, "kustomization.yaml"))
	require.NoError(t, err)
	kustStr := string(kustContent)
	assert.Contains(t, kustStr, "group: ^$")
	assert.Contains(t, kustStr, `group: ^custom\.example\.com$`)

	// Run kustomize build to verify patches apply strictly to their own groups without collision
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	fSys := filesys.MakeFsOnDisk()
	m, err := k.Run(fSys, dir)
	require.NoError(t, err)
	yamlOut, err := m.AsYaml()
	require.NoError(t, err)

	rawDocs := splitYamlDocs(yamlOut)
	require.Len(t, rawDocs, 2)

	for _, docBytes := range rawDocs {
		var doc struct {
			APIVersion string `yaml:"apiVersion"`
			Metadata   struct {
				Labels map[string]interface{} `yaml:"labels"`
			} `yaml:"metadata"`
		}
		require.NoError(t, yaml.Unmarshal(docBytes, &doc))
		switch doc.APIVersion {
		case "v1":
			assert.Equal(t, true, doc.Metadata.Labels["coreOnly"])
			assert.Nil(t, doc.Metadata.Labels["customOnly"])
		case "custom.example.com/v1":
			assert.Equal(t, true, doc.Metadata.Labels["customOnly"])
			assert.Nil(t, doc.Metadata.Labels["coreOnly"])
		}
	}
}

// TestReview4034_SliceIndexingCreatesList verifies that addressing an array index in a missing
// field (like spec.externalIPs[0]) initializes a list rather than a map, producing a valid
// Kubernetes list in the output.
func TestReview4034_SliceIndexingCreatesList(t *testing.T) {
	dir := t.TempDir()

	svc := makeResource("Service", "test-svc")
	svc.SetApiVersion("v1")
	svc.GetObject()["spec"] = map[string]interface{}{
		"ports": []interface{}{map[string]interface{}{"port": 80}},
	}

	suggestions := []HelmFixSuggestion{
		{
			Resource:           svc,
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "spec.externalIPs[0]", Value: "192.0.2.1"},
			},
		},
	}

	_, err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)

	// Verify patch content creates empty list and adds index 0
	patchFileName := resourcePatchFilename(resourceKey{
		Group:     "",
		Version:   "v1",
		Kind:      "Service",
		Namespace: "default",
		Name:      "test-svc",
	})
	patchContent, err := os.ReadFile(filepath.Join(dir, patchFileName))
	require.NoError(t, err)
	var ops []kustomizePatchOp
	err = yaml.Unmarshal(patchContent, &ops)
	require.NoError(t, err)
	require.Len(t, ops, 2)
	assert.Equal(t, "add", ops[0].Op)
	assert.Equal(t, "/spec/externalIPs", ops[0].Path)
	assert.Equal(t, []interface{}{}, ops[0].Value)
	assert.Equal(t, "add", ops[1].Op)
	assert.Equal(t, "/spec/externalIPs/0", ops[1].Path)
	assert.Equal(t, "192.0.2.1", ops[1].Value)

	// Run kustomize build to ensure Kubernetes type is a list
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	fSys := filesys.MakeFsOnDisk()
	m, err := k.Run(fSys, dir)
	require.NoError(t, err)
	yamlOut, err := m.AsYaml()
	require.NoError(t, err)

	rawDocs := splitYamlDocs(yamlOut)
	require.Len(t, rawDocs, 1)

	var builtSvc struct {
		Spec struct {
			ExternalIPs []string `yaml:"externalIPs"`
		} `yaml:"spec"`
	}
	require.NoError(t, yaml.Unmarshal(rawDocs[0], &builtSvc))
	require.Len(t, builtSvc.Spec.ExternalIPs, 1)
	assert.Equal(t, "192.0.2.1", builtSvc.Spec.ExternalIPs[0])
}

// TestReview4034_FixValueParsingRulesParity verifies that fix value parsing rules match the standard fixer:
// "null" becomes string "null" (not nil), ""quoted"" retains quotes, and safe sequences parse as lists.
func TestReview4034_FixValueParsingRulesParity(t *testing.T) {
	dir := t.TempDir()

	deploy := makeResource("Deployment", "val-app")
	deploy.GetObject()["spec"] = map[string]interface{}{
		"template": map[string]interface{}{
			"spec": map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "app"},
				},
			},
		},
	}

	suggestions := []HelmFixSuggestion{
		{
			Resource:           deploy,
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "spec.nullString", Value: "null"},
				{Path: "spec.quotedString", Value: `"quoted"`},
				{Path: "spec.boolVal", Value: "true"},
				{Path: "spec.intVal", Value: "123"},
				{Path: "spec.zeroVal", Value: "0"},
				{Path: "spec.oneVal", Value: "1"},
				{Path: "spec.seqVal", Value: `["drop1", "drop2"]`},
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
		Name:      "val-app",
	})
	patchContent, err := os.ReadFile(filepath.Join(dir, patchFileName))
	require.NoError(t, err)
	var ops []kustomizePatchOp
	err = yaml.Unmarshal(patchContent, &ops)
	require.NoError(t, err)

	opMap := make(map[string]interface{})
	for _, op := range ops {
		opMap[op.Path] = op.Value
	}

	// null should be string "null"
	assert.Equal(t, "null", opMap["/spec/nullString"])
	// "quoted" should retain literal quotes
	assert.Equal(t, `"quoted"`, opMap["/spec/quotedString"])
	// true should be bool true
	assert.Equal(t, true, opMap["/spec/boolVal"])
	// 123 should be int(123)
	assert.Equal(t, 123, opMap["/spec/intVal"])
	// 0 and 1 must be preserved as integers rather than boolean false/true
	assert.Equal(t, 0, opMap["/spec/zeroVal"])
	assert.NotEqual(t, false, opMap["/spec/zeroVal"])
	assert.Equal(t, 1, opMap["/spec/oneVal"])
	assert.NotEqual(t, true, opMap["/spec/oneVal"])
	// sequence should be []interface{}
	assert.Equal(t, []interface{}{"drop1", "drop2"}, opMap["/spec/seqVal"])
}

// TestReview4034_RedactedPlaceholderExemptionRestricted verifies that fields not actually redacted by the
// scanner (such as Service selector app: XXXXXX changing to other-app) are NOT exempted and result in
// declining the resource, while actual redacted fields (container env vars) are exempted.
func TestReview4034_RedactedPlaceholderExemptionRestricted(t *testing.T) {
	dir := t.TempDir()

	// Scenario 1: Non-redacted field (Service selector) has drift from XXXXXX to other-app.
	// Must be declined!
	scannedSvc := makeResource("Service", "drift-svc")
	scannedSvc.GetObject()["spec"] = map[string]interface{}{
		"selector": map[string]interface{}{"app": "XXXXXX"},
	}

	candSvc := makeResource("Service", "drift-svc")
	candSvc.GetObject()["spec"] = map[string]interface{}{
		"selector": map[string]interface{}{"app": "other-app"},
	}

	// Direct verification check
	err := verifyScannedFieldsMatch(scannedSvc.GetObject()["spec"], candSvc.GetObject()["spec"], "spec")
	require.Error(t, err, "non-redacted field containing XXXXXX must not match different rendered value")
	assert.Contains(t, err.Error(), "spec.selector.app")

	// Verify via EmitKustomizePatch with UnredactedBase
	sug1 := []HelmFixSuggestion{
		{
			Resource:       scannedSvc,
			UnredactedBase: candSvc.GetObject(),
			ChartName:      "my-chart",
			FixPaths:       []armotypes.FixPath{{Path: "metadata.labels.fix", Value: "applied"}},
		},
	}
	res1, err := EmitKustomizePatch(sug1, dir)
	require.NoError(t, err)
	require.Len(t, res1.SkippedResources, 1)
	assert.Contains(t, res1.SkippedResources[0].Reason, "spec.selector.app")

	// Scenario 2: Actually redacted field (container env value XXXXXX) IS exempted.
	scannedDeploy := makeResource("Deployment", "env-app")
	scannedDeploy.GetObject()["spec"] = map[string]interface{}{
		"template": map[string]interface{}{
			"spec": map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name": "web",
						"env": []interface{}{
							map[string]interface{}{"name": "SECRET_KEY", "value": "XXXXXX"},
						},
					},
				},
			},
		},
	}
	candDeploy := makeResource("Deployment", "env-app")
	candDeploy.GetObject()["spec"] = map[string]interface{}{
		"template": map[string]interface{}{
			"spec": map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name": "web",
						"env": []interface{}{
							map[string]interface{}{"name": "SECRET_KEY", "value": "real-secret-123"},
						},
					},
				},
			},
		},
	}
	err = verifyScannedFieldsMatch(scannedDeploy.GetObject()["spec"], candDeploy.GetObject()["spec"], "spec")
	assert.NoError(t, err, "actually redacted container env value must be exempted from drift check")
}

// TestReview4034_RootContainmentBlocksSymlinkEscape verifies that EmitKustomizePatch does not follow
// existing symlinks pointing outside the output directory (e.g. base.yaml -> outside file).
func TestReview4034_RootContainmentBlocksSymlinkEscape(t *testing.T) {
	tmpDir := t.TempDir()
	outDir := filepath.Join(tmpDir, "out")
	outsideDir := filepath.Join(tmpDir, "outside")
	require.NoError(t, os.MkdirAll(outDir, 0700))
	require.NoError(t, os.MkdirAll(outsideDir, 0700))

	outsideFile := filepath.Join(outsideDir, "target.txt")
	require.NoError(t, os.WriteFile(outsideFile, []byte("sensitive-original-content"), 0600))

	// Create symlink base.yaml inside outDir pointing outside to target.txt
	linkPath := filepath.Join(outDir, "base.yaml")
	require.NoError(t, os.Symlink(outsideFile, linkPath))

	deploy := makeResource("Deployment", "my-app")
	suggestions := []HelmFixSuggestion{
		{
			Resource:           deploy,
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{{Path: "metadata.labels.fix", Value: "applied"}},
		},
	}

	_, err := EmitKustomizePatch(suggestions, outDir)
	require.Error(t, err, "EmitKustomizePatch must fail when base.yaml symlink escapes output directory")

	// Ensure outside file was not overwritten
	outsideContent, err := os.ReadFile(outsideFile)
	require.NoError(t, err)
	assert.Equal(t, "sensitive-original-content", string(outsideContent))
}

// TestReview4034_ServiceSelectorEnvFromNotExempted verifies that an added field named "envFrom"
// in non-container objects (such as Service spec.selector.envFrom) is NOT exempted from drift
// detection, declining the candidate base to avoid redirecting pod traffic.
func TestReview4034_ServiceSelectorEnvFromNotExempted(t *testing.T) {
	dir := t.TempDir()

	scannedSvc := makeResource("Service", "web-svc")
	scannedSvc.GetObject()["spec"] = map[string]interface{}{
		"selector": map[string]interface{}{"app": "web"},
	}

	candSvc := makeResource("Service", "web-svc")
	candSvc.GetObject()["spec"] = map[string]interface{}{
		"selector": map[string]interface{}{
			"app":     "web",
			"envFrom": "production",
		},
	}

	// Direct verification check: should fail with missing field error
	err := verifyScannedFieldsMatch(scannedSvc.GetObject()["spec"], candSvc.GetObject()["spec"], "spec")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec.selector.envFrom")

	// EmitKustomizePatch with UnredactedBase must decline the resource
	sug := []HelmFixSuggestion{
		{
			Resource:       scannedSvc,
			UnredactedBase: candSvc.GetObject(),
			ChartName:      "my-chart",
			FixPaths:       []armotypes.FixPath{{Path: "metadata.labels.fix", Value: "applied"}},
		},
	}
	res, err := EmitKustomizePatch(sug, dir)
	require.NoError(t, err)
	require.Len(t, res.SkippedResources, 1)
	assert.Contains(t, res.SkippedResources[0].Reason, "spec.selector.envFrom")
}

// TestReview4034_NumericZeroAndOnePreservedAsIntegers verifies that raw fix values "0" and "1"
// are preserved as integer types (rather than boolean false/true from strconv.ParseBool),
// matching the standard fixer and preserving fields like PodDisruptionBudget minAvailable: 0.
func TestReview4034_NumericZeroAndOnePreservedAsIntegers(t *testing.T) {
	dir := t.TempDir()

	pdb := makeResource("PodDisruptionBudget", "app-pdb")
	pdb.SetApiVersion("policy/v1")
	pdb.GetObject()["spec"] = map[string]interface{}{
		"selector": map[string]interface{}{"matchLabels": map[string]interface{}{"app": "demo"}},
	}

	suggestions := []HelmFixSuggestion{
		{
			Resource:           pdb,
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "spec.minAvailable", Value: "0"},
				{Path: "spec.maxUnavailable", Value: "1"},
			},
		},
	}

	_, err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)

	patchFileName := resourcePatchFilename(resourceKey{
		Group:     "policy",
		Version:   "v1",
		Kind:      "PodDisruptionBudget",
		Namespace: "default",
		Name:      "app-pdb",
	})
	patchContent, err := os.ReadFile(filepath.Join(dir, patchFileName))
	require.NoError(t, err)

	var ops []kustomizePatchOp
	require.NoError(t, yaml.Unmarshal(patchContent, &ops))
	require.Len(t, ops, 2)

	assert.Equal(t, "/spec/minAvailable", ops[0].Path)
	assert.Equal(t, 0, ops[0].Value)
	assert.NotEqual(t, false, ops[0].Value, "minAvailable 0 must not be boolean false")

	assert.Equal(t, "/spec/maxUnavailable", ops[1].Path)
	assert.Equal(t, 1, ops[1].Value)
	assert.NotEqual(t, true, ops[1].Value, "maxUnavailable 1 must not be boolean true")

	// Verify with kustomize build
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	fSys := filesys.MakeFsOnDisk()
	m, err := k.Run(fSys, dir)
	require.NoError(t, err)
	yamlOut, err := m.AsYaml()
	require.NoError(t, err)

	rawDocs := splitYamlDocs(yamlOut)
	require.Len(t, rawDocs, 1)

	var builtPDB struct {
		Spec struct {
			MinAvailable   int `yaml:"minAvailable"`
			MaxUnavailable int `yaml:"maxUnavailable"`
		} `yaml:"spec"`
	}
	require.NoError(t, yaml.Unmarshal(rawDocs[0], &builtPDB))
	assert.Equal(t, 0, builtPDB.Spec.MinAvailable)
	assert.Equal(t, 1, builtPDB.Spec.MaxUnavailable)
}

// TestReview4034_MissingIntermediateArrayElementCreated verifies that fixing a path with a missing
// intermediate array element (such as spec.ingress[0].from[0].namespaceSelector.matchLabels.team on
// a NetworkPolicy where from does not exist) creates the missing element and applies the restriction,
// rather than silently dropping the fix.
func TestReview4034_MissingIntermediateArrayElementCreated(t *testing.T) {
	dir := t.TempDir()

	np := makeResource("NetworkPolicy", "restrict-ingress")
	np.SetApiVersion("networking.k8s.io/v1")
	np.GetObject()["spec"] = map[string]interface{}{
		"ingress": []interface{}{
			map[string]interface{}{
				"ports": []interface{}{
					map[string]interface{}{"port": 80},
				},
			},
		},
	}

	suggestions := []HelmFixSuggestion{
		{
			Resource:           np,
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "metadata.labels.applied", Value: "true"},
				{Path: "spec.ingress[0].from[0].namespaceSelector.matchLabels.team", Value: "security"},
			},
		},
	}

	res, err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)
	require.Len(t, res.EmittedResources, 1)
	require.Empty(t, res.SkippedResources)

	// Run kustomize build to verify the restriction is actually present in the rendered manifest
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	fSys := filesys.MakeFsOnDisk()
	m, err := k.Run(fSys, dir)
	require.NoError(t, err)
	yamlOut, err := m.AsYaml()
	require.NoError(t, err)

	rawDocs := splitYamlDocs(yamlOut)
	require.Len(t, rawDocs, 1)

	var builtNP struct {
		Metadata struct {
			Labels map[string]string `yaml:"labels"`
		} `yaml:"metadata"`
		Spec struct {
			Ingress []struct {
				From []struct {
					NamespaceSelector struct {
						MatchLabels map[string]string `yaml:"matchLabels"`
					} `yaml:"namespaceSelector"`
				} `yaml:"from"`
				Ports []struct {
					Port int `yaml:"port"`
				} `yaml:"ports"`
			} `yaml:"ingress"`
		} `yaml:"spec"`
	}
	require.NoError(t, yaml.Unmarshal(rawDocs[0], &builtNP))
	assert.Equal(t, "true", builtNP.Metadata.Labels["applied"])
	require.Len(t, builtNP.Spec.Ingress, 1)
	require.Len(t, builtNP.Spec.Ingress[0].From, 1)
	assert.Equal(t, "security", builtNP.Spec.Ingress[0].From[0].NamespaceSelector.MatchLabels["team"])
	require.Len(t, builtNP.Spec.Ingress[0].Ports, 1)
	assert.Equal(t, 80, builtNP.Spec.Ingress[0].Ports[0].Port)
}

// TestReview4034_ArrayGapsRejected verifies that array gaps are rejected instead of filling
// preceding elements with empty objects or emitting out-of-bounds array patches.
func TestReview4034_ArrayGapsRejected(t *testing.T) {
	dir := t.TempDir()

	// 1. Intermediate array gap: NetworkPolicy with no ingress list, targeting index 1
	np := makeResource("NetworkPolicy", "np-gap")
	np.SetApiVersion("networking.k8s.io/v1")
	np.GetObject()["spec"] = map[string]interface{}{}

	suggestions := []HelmFixSuggestion{
		{
			Resource:           np,
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "spec.ingress[1].from[0].namespaceSelector.matchLabels.team", Value: "security"},
			},
		},
	}

	res, err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)
	require.Empty(t, res.EmittedResources)
	require.Len(t, res.SkippedResources, 1)
	assert.Contains(t, res.SkippedResources[0].Reason, "array gap detected")

	// 2. Terminal array gap: Service with empty externalIPs, targeting index 2
	svc := makeResource("Service", "svc-gap")
	svc.GetObject()["spec"] = map[string]interface{}{
		"externalIPs": []interface{}{},
	}

	suggestions2 := []HelmFixSuggestion{
		{
			Resource:           svc,
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "spec.externalIPs[2]", Value: "1.2.3.4"},
			},
		},
	}

	dir2 := t.TempDir()
	res2, err := EmitKustomizePatch(suggestions2, dir2)
	require.NoError(t, err)
	require.Empty(t, res2.EmittedResources)
	require.Len(t, res2.SkippedResources, 1)
	assert.Contains(t, res2.SkippedResources[0].Reason, "array gap detected")
}

// TestReview4034_DeclinedResourcesExcludedFromBaseAndStalePatchesPurged verifies that
// fixes are resolved before writing output files, so declined resources do not appear
// in base.yaml, and reruns where fixes are declined do not produce mismatched overlays.
func TestReview4034_DeclinedResourcesExcludedFromBaseAndStalePatchesPurged(t *testing.T) {
	dir := t.TempDir()

	validDeploy := makeResource("Deployment", "valid-app")
	validDeploy.GetObject()["spec"] = map[string]interface{}{
		"template": map[string]interface{}{
			"spec": map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "web"},
				},
			},
		},
	}

	invalidNP := makeResource("NetworkPolicy", "invalid-np")
	invalidNP.SetApiVersion("networking.k8s.io/v1")
	invalidNP.GetObject()["spec"] = map[string]interface{}{}

	suggestions := []HelmFixSuggestion{
		{
			Resource:           validDeploy,
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"},
			},
		},
		{
			Resource:           invalidNP,
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "spec.ingress[5].from[0].namespaceSelector.matchLabels.team", Value: "security"},
			},
		},
	}

	res, err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)
	require.Len(t, res.EmittedResources, 1)
	assert.Equal(t, "Deployment/default/valid-app", res.EmittedResources[0])
	require.Len(t, res.SkippedResources, 1)
	assert.Equal(t, "NetworkPolicy/invalid-np", res.SkippedResources[0].ResourceKey)

	// Verify base.yaml only contains the valid Deployment, NOT the declined NetworkPolicy
	baseContent, err := os.ReadFile(filepath.Join(dir, "base.yaml"))
	require.NoError(t, err)
	docs := splitYamlDocs(baseContent)
	require.Len(t, docs, 1, "declined resource must not appear in base.yaml")
	assert.Contains(t, string(docs[0]), "kind: Deployment")
	assert.NotContains(t, string(baseContent), "NetworkPolicy")

	// Verify kustomize build succeeds and only contains the Deployment
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	fSys := filesys.MakeFsOnDisk()
	m, err := k.Run(fSys, dir)
	require.NoError(t, err)
	builtYaml, err := m.AsYaml()
	require.NoError(t, err)
	assert.Contains(t, string(builtYaml), "kind: Deployment")
	assert.NotContains(t, string(builtYaml), "NetworkPolicy")

	// Rerun where all fixes are declined: must emit 0 resources and not overwrite with inconsistent state
	emptyDir := t.TempDir()
	allDeclined := []HelmFixSuggestion{
		{
			Resource:           invalidNP,
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "spec.ingress[5].from[0].namespaceSelector.matchLabels.team", Value: "security"},
			},
		},
	}
	res2, err := EmitKustomizePatch(allDeclined, emptyDir)
	require.NoError(t, err)
	require.Empty(t, res2.EmittedResources)
	require.Len(t, res2.SkippedResources, 1)
	// No base.yaml should be created in emptyDir
	_, err = os.Stat(filepath.Join(emptyDir, "base.yaml"))
	assert.True(t, os.IsNotExist(err), "base.yaml must not be written when all resources are declined")
}

// TestReview4034_ExistingDirectoryPreservesUnrelatedFiles verifies that EmitKustomizePatch
// does not delete user-authored files (such as patch-custom.yaml or custom notes)
// when outputting to an existing directory.
func TestReview4034_ExistingDirectoryPreservesUnrelatedFiles(t *testing.T) {
	dir := t.TempDir()

	// Pre-populate existing output directory with user-authored files
	customPatchPath := filepath.Join(dir, "patch-custom.yaml")
	customPatchContent := []byte("# User-authored custom patch\n- op: add\n  path: /metadata/labels/custom\n  value: user-label\n")
	require.NoError(t, os.WriteFile(customPatchPath, customPatchContent, 0600))

	unrelatedTxtPath := filepath.Join(dir, "custom-notes.txt")
	require.NoError(t, os.WriteFile(unrelatedTxtPath, []byte("custom notes"), 0600))

	deploy := makeResource("Deployment", "my-app")
	deploy.GetObject()["spec"] = map[string]interface{}{
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
			Resource:           deploy,
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"},
			},
		},
	}

	res, err := EmitKustomizePatch(suggestions, dir, WithOverwrite(true))
	require.NoError(t, err)
	require.Len(t, res.EmittedResources, 1)

	// Verify user-authored files were NOT deleted
	savedCustomPatch, err := os.ReadFile(customPatchPath)
	require.NoError(t, err, "user-authored patch-custom.yaml must not be deleted")
	assert.Equal(t, string(customPatchContent), string(savedCustomPatch))

	savedNotes, err := os.ReadFile(unrelatedTxtPath)
	require.NoError(t, err, "unrelated files must not be deleted")
	assert.Equal(t, "custom notes", string(savedNotes))

	// Verify Kubescape own files were written properly
	assert.FileExists(t, filepath.Join(dir, "base.yaml"))
	assert.FileExists(t, filepath.Join(dir, "kustomization.yaml"))
}

// TestReview4034_OctalLeadingZeroNumericParsing verifies that YAML octal values like 0777
// are parsed to decimal integers (511) matching the standard fixer.
func TestReview4034_OctalLeadingZeroNumericParsing(t *testing.T) {
	dir := t.TempDir()

	deploy := makeResource("Deployment", "mode-app")
	deploy.GetObject()["spec"] = map[string]interface{}{
		"template": map[string]interface{}{
			"spec": map[string]interface{}{
				"volumes": []interface{}{
					map[string]interface{}{
						"name": "vol",
						"configMap": map[string]interface{}{
							"name": "cfg",
						},
					},
				},
			},
		},
	}

	suggestions := []HelmFixSuggestion{
		{
			Resource:           deploy,
			ChartName:          "my-chart",
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "spec.template.spec.volumes[0].configMap.defaultMode", Value: "0777"},
				{Path: "spec.octal644", Value: "0644"},
			},
		},
	}

	res, err := EmitKustomizePatch(suggestions, dir)
	require.NoError(t, err)
	require.Len(t, res.EmittedResources, 1)

	patchFileName := resourcePatchFilename(resourceKey{
		Group:     "apps",
		Version:   "v1",
		Kind:      "Deployment",
		Namespace: "default",
		Name:      "mode-app",
	})
	patchContent, err := os.ReadFile(filepath.Join(dir, patchFileName))
	require.NoError(t, err)

	var ops []kustomizePatchOp
	require.NoError(t, yaml.Unmarshal(patchContent, &ops))
	require.Len(t, ops, 2)

	assert.Equal(t, "/spec/template/spec/volumes/0/configMap/defaultMode", ops[0].Path)
	assert.Equal(t, 511, ops[0].Value, "0777 must be parsed as octal integer 511")

	assert.Equal(t, "/spec/octal644", ops[1].Path)
	assert.Equal(t, 420, ops[1].Value, "0644 must be parsed as octal integer 420")

	// Verify build output
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	fSys := filesys.MakeFsOnDisk()
	m, err := k.Run(fSys, dir)
	require.NoError(t, err)
	yamlOut, err := m.AsYaml()
	require.NoError(t, err)

	var built struct {
		Spec struct {
			Template struct {
				Spec struct {
					Volumes []struct {
						ConfigMap struct {
							DefaultMode int `yaml:"defaultMode"`
						} `yaml:"configMap"`
					} `yaml:"volumes"`
				} `yaml:"spec"`
			} `yaml:"template"`
			Octal644 int `yaml:"octal644"`
		} `yaml:"spec"`
	}
	require.NoError(t, yaml.Unmarshal(yamlOut, &built))
	assert.Equal(t, 511, built.Spec.Template.Spec.Volumes[0].ConfigMap.DefaultMode)
	assert.Equal(t, 420, built.Spec.Octal644)
}

// TestReview4034_CustomResourceDriftRejectedAndRedactionRestricted verifies that:
// 1. String "123" changing to numeric 123 is rejected as a type mismatch.
// 2. Literal data.setting: XXXXXX changing in a custom resource is rejected.
// 3. Added envFrom under spec.rules.containers[0] in a custom resource is rejected.
func TestReview4034_CustomResourceDriftRejectedAndRedactionRestricted(t *testing.T) {
	// Case 1: spec.setting string "123" vs numeric 123
	scannedStr := map[string]interface{}{
		"apiVersion": "example.com/v1",
		"kind":       "MyCustomResource",
		"metadata":   map[string]interface{}{"name": "cr-1"},
		"spec": map[string]interface{}{
			"setting": "123",
		},
	}
	candNum := map[string]interface{}{
		"apiVersion": "example.com/v1",
		"kind":       "MyCustomResource",
		"metadata":   map[string]interface{}{"name": "cr-1"},
		"spec": map[string]interface{}{
			"setting": 123,
		},
	}
	err1 := verifyScannedFieldsMatch(scannedStr, candNum, "")
	require.Error(t, err1, "string '123' becoming numeric 123 must be rejected")
	assert.Contains(t, err1.Error(), "type mismatch at spec.setting")

	// Case 2: Custom resource with data.setting: XXXXXX changing to changed
	scannedCR := map[string]interface{}{
		"apiVersion": "example.com/v1",
		"kind":       "MyCustomResource",
		"metadata":   map[string]interface{}{"name": "cr-2"},
		"data": map[string]interface{}{
			"setting": "XXXXXX",
		},
	}
	candCRChanged := map[string]interface{}{
		"apiVersion": "example.com/v1",
		"kind":       "MyCustomResource",
		"metadata":   map[string]interface{}{"name": "cr-2"},
		"data": map[string]interface{}{
			"setting": "changed",
		},
	}
	err2 := verifyScannedFieldsMatch(scannedCR, candCRChanged, "")
	require.Error(t, err2, "literal data.setting: XXXXXX in custom resource must not be exempted from drift")
	assert.Contains(t, err2.Error(), "value mismatch at data.setting")

	// Case 3: Added envFrom under spec.rules.containers[0] on custom resource
	scannedRules := map[string]interface{}{
		"apiVersion": "example.com/v1",
		"kind":       "MyCustomResource",
		"metadata":   map[string]interface{}{"name": "cr-3"},
		"spec": map[string]interface{}{
			"rules": map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "custom-box"},
				},
			},
		},
	}
	candRulesWithEnvFrom := map[string]interface{}{
		"apiVersion": "example.com/v1",
		"kind":       "MyCustomResource",
		"metadata":   map[string]interface{}{"name": "cr-3"},
		"spec": map[string]interface{}{
			"rules": map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name":    "custom-box",
						"envFrom": []interface{}{map[string]interface{}{"configMapRef": map[string]interface{}{"name": "cm"}}},
					},
				},
			},
		},
	}
	err3 := verifyScannedFieldsMatch(scannedRules, candRulesWithEnvFrom, "")
	require.Error(t, err3, "added envFrom under non-pod container path spec.rules.containers[0] must be rejected")
	assert.Contains(t, err3.Error(), "spec.rules.containers[0].envFrom")
}

// TestKustomize_AtomicStagingRollbackOnFailure verifies that if writing any patch file
// fails during overlay generation, the staging directory is cleaned up and no partial
// base.yaml or corrupted files are left in the destination directory.
func TestKustomize_AtomicStagingRollbackOnFailure(t *testing.T) {
	outDir := t.TempDir()

	deploy := makeResource("Deployment", "app1")
	deploy.GetObject()["spec"] = map[string]interface{}{
		"template": map[string]interface{}{
			"spec": map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "c1"},
				},
			},
		},
	}

	// Two suggestions: first valid, second has an invalid path that fails ensureSubpath traversal check
	suggestions := []HelmFixSuggestion{
		{
			Resource:           deploy,
			ChartName:          "chart1",
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"},
			},
		},
	}

	// Verify that if pre-existing files were not present, a clean run writes base.yaml
	res, err := EmitKustomizePatch(suggestions, outDir)
	require.NoError(t, err)
	require.Len(t, res.EmittedResources, 1)
	require.FileExists(t, filepath.Join(outDir, "base.yaml"))

	// Force promotion failure by creating a directory where a staged file would be promoted
	failDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(failDir, "kustomization.yaml"), 0700))
	origBaseContent := "ORIGINAL_BASE_CONTENT_PRESERVED"
	require.NoError(t, os.WriteFile(filepath.Join(failDir, "base.yaml"), []byte(origBaseContent), 0600))

	// Calling EmitKustomizePatch into failDir must fail when promoting kustomization.yaml
	_, err = EmitKustomizePatch(suggestions, failDir)
	require.Error(t, err)

	// Verify that destination pre-existing base.yaml was restored and not overwritten
	currentBase, err := os.ReadFile(filepath.Join(failDir, "base.yaml"))
	require.NoError(t, err)
	assert.Equal(t, origBaseContent, string(currentBase), "original base.yaml must be preserved on promotion failure")

	// Verify that staging directory was cleaned up and no .kust-staging-* remains, and no partial patches left
	entries, readErr := os.ReadDir(failDir)
	require.NoError(t, readErr)
	for _, e := range entries {
		assert.False(t, strings.HasPrefix(e.Name(), ".kust-staging-"), "staging directory must be removed on failure")
		assert.False(t, strings.HasPrefix(e.Name(), "apps-") || strings.HasPrefix(e.Name(), "patch-"), "partially promoted patch files must be rolled back on failure")
	}
}

// TestKustomize_VendoredChartWithOutsideOrMissingFileRepositoryAllowed verifies that
// a chart declaring a dependency with repository: file://../child is not declined
// when that original source was removed or lives outside allowedBase, provided the
// chart dependency is vendored inside charts/ and all chart files are contained.
func TestKustomize_VendoredChartWithOutsideOrMissingFileRepositoryAllowed(t *testing.T) {
	allowedBase := t.TempDir()
	outsideBase := t.TempDir()

	chartDir := filepath.Join(allowedBase, "parent-chart")
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "templates"), 0700))
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "charts", "child", "templates"), 0700))

	// Outside dependency path that does not exist in allowedBase
	outsideDep := filepath.Join(outsideBase, "missing-child-source")
	relOutside, err := filepath.Rel(chartDir, outsideDep)
	require.NoError(t, err)

	parentChartYaml := fmt.Sprintf(`apiVersion: v2
name: parent-chart
version: 0.1.0
dependencies:
  - name: child
    version: 0.1.0
    repository: "file://%s"
`, relOutside)
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte(parentChartYaml), 0600))

	childChartYaml := `apiVersion: v2
name: child
version: 0.1.0
`
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "charts", "child", "Chart.yaml"), []byte(childChartYaml), 0600))

	childDeploymentYaml := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: child-workload
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.21
          securityContext:
            allowPrivilegeEscalation: true
`
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "charts", "child", "templates", "deployment.yaml"), []byte(childDeploymentYaml), 0600))

	// Containment validation of the actual chart files passes
	require.NoError(t, validateChartFilesContainment(chartDir, allowedBase))

	// EmitKustomizePatch must succeed loading and fixing the vendored child chart workload
	res := makeResource("Deployment", "child-workload")
	res.SetApiVersion("apps/v1")
	res.SetNamespace("default")

	sug := []HelmFixSuggestion{
		{
			Resource:           res,
			ChartName:          "parent-chart",
			ChartPath:          chartDir,
			AllowedBasePath:    allowedBase,
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation", Value: "false"},
			},
		},
	}

	outDir := filepath.Join(t.TempDir(), "kustomize-out")
	emitRes, err := EmitKustomizePatch(sug, outDir)
	require.NoError(t, err, "vendored chart with outside/missing file:// metadata must not be rejected")
	require.Len(t, emitRes.EmittedResources, 1)
	require.Empty(t, emitRes.SkippedResources)

	// Verify kustomize build renders the fixed patch
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	fSys := filesys.MakeFsOnDisk()
	m, err := k.Run(fSys, outDir)
	require.NoError(t, err)
	yamlOut, err := m.AsYaml()
	require.NoError(t, err)
	assert.Contains(t, string(yamlOut), "allowPrivilegeEscalation: false")
}

// TestKustomize_ClusterRoleAndNamespacelessServiceMatching verifies that cluster-scoped
// resources (ClusterRole) and namespace-less services are matched correctly against candidates
// without namespace mismatch rejections.
func TestKustomize_ClusterRoleAndNamespacelessServiceMatching(t *testing.T) {
	outDir := t.TempDir()

	// 1. ClusterRole (cluster-scoped, group rbac.authorization.k8s.io, no namespace)
	clusterRoleObj := map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata": map[string]interface{}{
			"name": "secret-reader",
		},
		"rules": []interface{}{
			map[string]interface{}{
				"apiGroups": []interface{}{""},
				"resources": []interface{}{"secrets"},
				"verbs":     []interface{}{"get", "watch", "list"},
			},
		},
	}
	crRes := reporthandling.Resource{
		Object: clusterRoleObj,
		Source: &reporthandling.Source{FileType: reporthandling.SourceTypeHelmChart},
	}

	// 2. Namespace-less Service (namespaced kind, but metadata has no namespace)
	svcObj := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]interface{}{
			"name": "my-service",
		},
		"spec": map[string]interface{}{
			"selector": map[string]interface{}{"app": "frontend"},
			"ports": []interface{}{
				map[string]interface{}{"port": 80},
			},
		},
	}
	svcRes := reporthandling.Resource{
		Object: svcObj,
		Source: &reporthandling.Source{FileType: reporthandling.SourceTypeHelmChart},
	}

	suggestions := []HelmFixSuggestion{
		{
			Resource:           &crRes,
			ChartName:          "auth-chart",
			FidelityProvenance: true,
			UnredactedBase:     deepCopyMap(clusterRoleObj),
			FixPaths: []armotypes.FixPath{
				{Path: "metadata.labels.hardened", Value: "true"},
			},
		},
		{
			Resource:           &svcRes,
			ChartName:          "auth-chart",
			FidelityProvenance: true,
			UnredactedBase:     deepCopyMap(svcObj),
			FixPaths: []armotypes.FixPath{
				{Path: "metadata.labels.hardened", Value: "true"},
			},
		},
	}

	res, err := EmitKustomizePatch(suggestions, outDir)
	require.NoError(t, err)
	require.Len(t, res.EmittedResources, 2)
	assert.Contains(t, res.EmittedResources, "ClusterRole/secret-reader")
	assert.Contains(t, res.EmittedResources, "Service/my-service")

	// Read generated kustomization.yaml to verify target selector rules
	kustData, err := os.ReadFile(filepath.Join(outDir, "kustomization.yaml"))
	require.NoError(t, err)

	var kust kustomizationDoc
	require.NoError(t, yaml.Unmarshal(kustData, &kust))
	require.Len(t, kust.Patches, 2)

	seen := map[string]bool{}
	for _, p := range kust.Patches {
		seen[p.Target.Kind] = true
		switch p.Target.Kind {
		case "ClusterRole":
			assert.Empty(t, p.Target.Namespace, "ClusterRole target must have empty namespace")
		case "Service":
			assert.Equal(t, "default", p.Target.Namespace, "Namespaceless Service target must default to default namespace")
		}
	}
	assert.True(t, seen["ClusterRole"] && seen["Service"], "both targets must be present")
}

// TestKustomize_LoadUnredactedFromChart_ReleaseNamespaceMatching tests that loadUnredactedFromChart
// correctly matches when target is in ReleaseNamespace and candidate omits metadata.namespace.
func TestKustomize_LoadUnredactedFromChart_ReleaseNamespaceMatching(t *testing.T) {
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: testchart\nversion: 0.1.0\n"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "templates"), 0700))

	// Template omits metadata.namespace
	depYaml := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: namespaceless-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:latest
`
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "templates", "deployment.yaml"), []byte(depYaml), 0600))

	// Target resource has namespace "staging"
	targetObj := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      "namespaceless-app",
			"namespace": "staging",
		},
	}
	targetRes := reporthandling.Resource{
		Object: targetObj,
		Source: &reporthandling.Source{FileType: reporthandling.SourceTypeHelmChart},
	}

	// 1. ReleaseNamespace matches target namespace ("staging") -> candidate matches
	s1 := HelmFixSuggestion{
		Resource:        &targetRes,
		ChartPath:       chartDir,
		AllowedBasePath: chartDir,
		HelmValueOptions: cautils.HelmValueOptions{
			ReleaseNamespace: "staging",
		},
	}
	chartCache := make(map[string]map[string][]workloadinterface.IMetadata)
	matched, err := loadUnredactedFromChart(s1, chartCache)
	require.NoError(t, err, "candidate with omitted namespace must match target in ReleaseNamespace")
	require.NotNil(t, matched)
	assert.Equal(t, "namespaceless-app", matched["metadata"].(map[string]interface{})["name"])

	// 2. ReleaseNamespace does not match target namespace ("production" != "staging") -> match fails
	s2 := HelmFixSuggestion{
		Resource:        &targetRes,
		ChartPath:       chartDir,
		AllowedBasePath: chartDir,
		HelmValueOptions: cautils.HelmValueOptions{
			ReleaseNamespace: "production",
		},
	}
	_, err = loadUnredactedFromChart(s2, chartCache)
	require.Error(t, err, "candidate must not match when ReleaseNamespace differs from target namespace")
	assert.Contains(t, err.Error(), "not found in rendered chart")
}

// TestKustomize_HasEmittableKustomizePatches verifies that HasEmittableKustomizePatches
// correctly differentiates emittable suggestions from declined or empty ones.
func TestKustomize_HasEmittableKustomizePatches(t *testing.T) {
	assert.False(t, HasEmittableKustomizePatches(nil), "nil suggestions must return false")
	assert.False(t, HasEmittableKustomizePatches([]HelmFixSuggestion{}), "empty suggestions must return false")

	// Nil resource or no fix paths
	assert.False(t, HasEmittableKustomizePatches([]HelmFixSuggestion{
		{Resource: nil},
	}))

	deploy := makeResource("Deployment", "app1")
	assert.False(t, HasEmittableKustomizePatches([]HelmFixSuggestion{
		{Resource: deploy, FixPaths: nil},
	}))

	// Resource declined (no provenance or unredacted base)
	assert.False(t, HasEmittableKustomizePatches([]HelmFixSuggestion{
		{
			Resource: deploy,
			FixPaths: []armotypes.FixPath{{Path: "spec.replicas", Value: "2"}},
		},
	}))

	// Resource with fidelity provenance is emittable
	assert.True(t, HasEmittableKustomizePatches([]HelmFixSuggestion{
		{
			Resource:           deploy,
			FidelityProvenance: true,
			UnredactedBase:     deepCopyMap(deploy.GetObject()),
			FixPaths:           []armotypes.FixPath{{Path: "spec.replicas", Value: "2"}},
		},
	}))
}

// TestKustomize_RestoreBackups verifies that restoreBackups correctly restores files
// under held root and returns errors when destination files already exist.
func TestKustomize_RestoreBackups(t *testing.T) {
	dstDir := t.TempDir()
	backupRelDir := ".backup"
	require.NoError(t, os.Mkdir(filepath.Join(dstDir, backupRelDir), 0700))

	require.NoError(t, os.WriteFile(filepath.Join(dstDir, backupRelDir, "base.yaml"), []byte("BACKUP_BASE"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dstDir, backupRelDir, "kustomization.yaml"), []byte("BACKUP_KUST"), 0600))

	root, err := os.OpenRoot(dstDir)
	require.NoError(t, err)
	defer root.Close()

	// Clean destination: both files restored
	err = restoreBackups(root, backupRelDir)
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dstDir, "base.yaml"))
	require.NoError(t, err)
	assert.Equal(t, "BACKUP_BASE", string(data))

	// Destination already has base.yaml: returns error
	require.NoError(t, os.WriteFile(filepath.Join(dstDir, backupRelDir, "base.yaml"), []byte("NEW_BACKUP"), 0600))
	err = restoreBackups(root, backupRelDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "destination exists")
}

// TestFollowup_OutputDirProtection verifies that EmitKustomizePatch refuses a non-empty
// destination directory unless noConfirm is set to true.
func TestFollowup_OutputDirProtection(t *testing.T) {
	dir := t.TempDir()

	// Place an existing file in dir
	existingFile := filepath.Join(dir, "my-existing-note.txt")
	require.NoError(t, os.WriteFile(existingFile, []byte("preserve me"), 0600))

	svc := makeResource("Service", "web-svc")
	svc.GetObject()["spec"] = map[string]interface{}{"type": "ClusterIP"}

	suggestions := []HelmFixSuggestion{
		{
			Resource:           svc,
			ChartName:          "web-chart",
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "metadata.labels.patched", Value: "\"true\""},
			},
		},
	}

	// 1. With WithOverwrite(false), generation must be refused
	res, err := EmitKustomizePatch(suggestions, dir, WithOverwrite(false))
	require.Error(t, err, "non-empty directory must be refused when overwrite is false")
	assert.Contains(t, err.Error(), "is not empty; pass --no-confirm to write into it anyway")
	assert.Nil(t, res)

	// Ensure no kustomize files were written and existing file preserved
	assert.NoFileExists(t, filepath.Join(dir, "kustomization.yaml"))
	assert.NoFileExists(t, filepath.Join(dir, "base.yaml"))
	assert.FileExists(t, existingFile)

	// 1b. Two-argument call without options must default to refusing non-empty directories and preserve existing output
	resTwoArg, errTwoArg := EmitKustomizePatch(suggestions, dir)
	require.Error(t, errTwoArg, "two-argument call on non-empty directory must be refused")
	assert.Contains(t, errTwoArg.Error(), "is not empty; pass --no-confirm to write into it anyway")
	assert.Nil(t, resTwoArg)
	assert.FileExists(t, existingFile)

	// 2. With WithOverwrite(true), generation succeeds into the non-empty directory
	res2, err2 := EmitKustomizePatch(suggestions, dir, WithOverwrite(true))
	require.NoError(t, err2)
	require.NotNil(t, res2)
	assert.Len(t, res2.EmittedResources, 1)

	assert.FileExists(t, filepath.Join(dir, "kustomization.yaml"))
	assert.FileExists(t, filepath.Join(dir, "base.yaml"))
	assert.FileExists(t, existingFile)
}

// TestFollowup_CoherentPublicationStagingAndRollback verifies that EmitKustomizePatch
// stages generation and coherently publishes to the destination directory, completely
// restoring the previous overlay if an injected write error occurs during publication.
func TestFollowup_CoherentPublicationStagingAndRollback(t *testing.T) {
	dir := t.TempDir()

	// 1. Create an initial valid overlay in dir
	initialBase := "apiVersion: v1\nkind: Service\nmetadata:\n  name: initial-svc\n"
	initialKust := "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - base.yaml\n"
	initialPatch := "[{\"op\": \"add\", \"path\": \"/metadata/labels/test\", \"value\": \"initial\"}]\n"
	patchFileName := resourcePatchFilename(resourceKey{Kind: "Service", Name: "new-svc"})
	require.NoError(t, os.WriteFile(filepath.Join(dir, "base.yaml"), []byte(initialBase), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(initialKust), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, patchFileName), []byte(initialPatch), 0600))

	// 2. Plan new patches to update the overlay
	svc := makeResource("Service", "new-svc")
	svc.GetObject()["spec"] = map[string]interface{}{"type": "ClusterIP"}

	suggestions := []HelmFixSuggestion{
		{
			Resource:           svc,
			ChartName:          "new-chart",
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "metadata.labels.patched", Value: "\"true\""},
			},
		},
	}

	// 3. Inject write failure during publication of kustomization.yaml
	defer func() { failKustomizeWriteDuringPublication = nil }()
	failKustomizeWriteDuringPublication = func(filename string) error {
		if filename == "publish:kustomization.yaml" {
			return errors.New("simulated disk full during kustomization.yaml publish")
		}
		return nil
	}

	res, err := EmitKustomizePatch(suggestions, dir, WithOverwrite(true))
	require.Error(t, err, "injected publication failure must return an error")
	assert.Contains(t, err.Error(), "simulated disk full")
	assert.Nil(t, res)

	// 4. Verify rollback preserved the previous overlay exactly as it was
	baseAfter, err := os.ReadFile(filepath.Join(dir, "base.yaml"))
	require.NoError(t, err)
	assert.Equal(t, initialBase, string(baseAfter), "base.yaml must remain the previous version after write failure")

	kustAfter, err := os.ReadFile(filepath.Join(dir, "kustomization.yaml"))
	require.NoError(t, err)
	assert.Equal(t, initialKust, string(kustAfter), "kustomization.yaml must remain the previous version after write failure")

	patchAfter, err := os.ReadFile(filepath.Join(dir, patchFileName))
	require.NoError(t, err)
	assert.Equal(t, initialPatch, string(patchAfter), "patch file must remain the previous version after write failure")

	// Verify no stray patch files or staging directories remained
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		if e.Name() != ".kust.lock" {
			names = append(names, e.Name())
		}
	}
	assert.ElementsMatch(t, []string{"base.yaml", "kustomization.yaml", patchFileName}, names, "pre-existing files must be restored and no uncommitted files left")

	parentEntries, err := os.ReadDir(filepath.Dir(dir))
	require.NoError(t, err)
	for _, e := range parentEntries {
		assert.False(t, strings.HasPrefix(e.Name(), ".kustomize-staging"), "staging directory must not leak")
	}

	// 5. Clear failure injection and verify generation succeeds
	failKustomizeWriteDuringPublication = nil
	res2, err2 := EmitKustomizePatch(suggestions, dir, WithOverwrite(true))
	require.NoError(t, err2)
	assert.Len(t, res2.EmittedResources, 1)

	baseSuccess, err := os.ReadFile(filepath.Join(dir, "base.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(baseSuccess), "new-svc")
}

// TestFollowup_ReleaseNamespaceMatching verifies that loadUnredactedFromChart and EmitKustomizePatch
// symmetrically normalize release namespaces for namespaced resources while keeping cluster-scoped
// resources strictly namespace-free.
func TestFollowup_ReleaseNamespaceMatching(t *testing.T) {
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: test-chart\nversion: 0.1.0\n"), 0600))
	templatesDir := filepath.Join(chartDir, "templates")
	require.NoError(t, os.MkdirAll(templatesDir, 0700))

	// Namespaceless Service template
	svcYaml := "apiVersion: v1\nkind: Service\nmetadata:\n  name: my-service\nspec:\n  type: ClusterIP\n"
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, "service.yaml"), []byte(svcYaml), 0600))

	// Cluster-scoped ClusterRole template
	crYaml := "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: my-cluster-role\nrules: []\n"
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, "clusterrole.yaml"), []byte(crYaml), 0600))

	// CustomResourceDefinition placed in standard Helm crds/ directory with spec.scope: Cluster
	crdsDir := filepath.Join(chartDir, "crds")
	require.NoError(t, os.MkdirAll(crdsDir, 0700))
	crdYaml := `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: widgets.example.com
spec:
  group: example.com
  scope: Cluster
  names:
    kind: Widget
`
	require.NoError(t, os.WriteFile(filepath.Join(crdsDir, "crd.yaml"), []byte(crdYaml), 0600))

	// Namespaceless cluster-scoped custom resource Widget template
	widgetYaml := `apiVersion: example.com/v1
kind: Widget
metadata:
  name: my-widget
spec:
  color: blue
`
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, "widget.yaml"), []byte(widgetYaml), 0600))

	chartCache := make(map[string]map[string][]workloadinterface.IMetadata)

	// 1. Namespaceless scanned Service matching rendered chart with ReleaseNamespace set
	scannedSvc := makeResource("Service", "my-service")
	scannedSvc.GetObject()["apiVersion"] = "v1"
	delete(scannedSvc.GetObject()["metadata"].(map[string]interface{}), "namespace")
	scannedSvc.GetObject()["spec"] = map[string]interface{}{"type": "ClusterIP"}

	svcSuggestion := HelmFixSuggestion{
		Resource:  scannedSvc,
		ChartPath: chartDir,
		ChartName: "test-chart",
		HelmValueOptions: cautils.HelmValueOptions{
			ReleaseNamespace: "prod-namespace",
		},
		FixPaths: []armotypes.FixPath{{Path: "metadata.labels.patched", Value: "applied"}},
	}

	candObj, err := loadUnredactedFromChart(svcSuggestion, chartCache)
	require.NoError(t, err, "namespaceless Service must match candidate when ReleaseNamespace is specified")
	assert.NotNil(t, candObj)

	// 2. ClusterRole matching rendered chart with ReleaseNamespace set
	scannedCR := makeResource("ClusterRole", "my-cluster-role")
	scannedCR.GetObject()["apiVersion"] = "rbac.authorization.k8s.io/v1"
	delete(scannedCR.GetObject()["metadata"].(map[string]interface{}), "namespace")
	scannedCR.GetObject()["rules"] = []interface{}{}

	crSuggestion := HelmFixSuggestion{
		Resource:  scannedCR,
		ChartPath: chartDir,
		ChartName: "test-chart",
		HelmValueOptions: cautils.HelmValueOptions{
			ReleaseNamespace: "prod-namespace",
		},
		FixPaths: []armotypes.FixPath{{Path: "metadata.labels.patched", Value: "applied"}},
	}

	candCRObj, err := loadUnredactedFromChart(crSuggestion, chartCache)
	require.NoError(t, err, "ClusterRole must match candidate without substituting ReleaseNamespace")
	assert.NotNil(t, candCRObj)

	// 3. Cluster-scoped custom resource Widget matching rendered chart with ReleaseNamespace set
	scannedWidget := makeResource("Widget", "my-widget")
	scannedWidget.GetObject()["apiVersion"] = "example.com/v1"
	delete(scannedWidget.GetObject()["metadata"].(map[string]interface{}), "namespace")
	scannedWidget.GetObject()["spec"] = map[string]interface{}{"color": "blue"}

	widgetSuggestion := HelmFixSuggestion{
		Resource:  scannedWidget,
		ChartPath: chartDir,
		ChartName: "test-chart",
		HelmValueOptions: cautils.HelmValueOptions{
			ReleaseNamespace: "prod-namespace",
		},
		FixPaths: []armotypes.FixPath{{Path: "metadata.labels.patched", Value: "applied"}},
	}

	candWidgetObj, err := loadUnredactedFromChart(widgetSuggestion, chartCache)
	require.NoError(t, err, "cluster-scoped Widget from crds/ must match candidate without substituting ReleaseNamespace")
	assert.NotNil(t, candWidgetObj)

	// 4. Verify EmitKustomizePatch scopes Service target to ReleaseNamespace and leaves ClusterRole and Widget unscoped
	outDir := t.TempDir()
	emitRes, err := EmitKustomizePatch([]HelmFixSuggestion{svcSuggestion, crSuggestion, widgetSuggestion}, outDir, WithOverwrite(true))
	require.NoError(t, err)
	assert.Len(t, emitRes.EmittedResources, 3)

	kustContent, err := os.ReadFile(filepath.Join(outDir, "kustomization.yaml"))
	require.NoError(t, err)
	var kDoc kustomizationDoc
	require.NoError(t, yaml.Unmarshal(kustContent, &kDoc))

	foundSvc := false
	foundCR := false
	foundWidget := false
	for _, p := range kDoc.Patches {
		if strings.Contains(p.Target.Kind, "Service") {
			foundSvc = true
			assert.Equal(t, "^($|default|prod-namespace$)", p.Target.Namespace, "Service target must be scoped to ReleaseNamespace and namespaceless input")
		}
		if strings.Contains(p.Target.Kind, "ClusterRole") {
			foundCR = true
			assert.Empty(t, p.Target.Namespace, "ClusterRole target must remain namespace-free")
		}
		if strings.Contains(p.Target.Kind, "Widget") {
			foundWidget = true
			assert.Empty(t, p.Target.Namespace, "cluster-scoped Widget target must remain namespace-free")
		}
	}
	assert.True(t, foundSvc)
	assert.True(t, foundCR)
	assert.True(t, foundWidget)

	// 5. Verify base.yaml keeps cluster-scoped custom resource Widget namespace-free
	baseContent, err := os.ReadFile(filepath.Join(outDir, "base.yaml"))
	require.NoError(t, err)
	var docs []map[string]interface{}
	decoder := yaml.NewDecoder(strings.NewReader(string(baseContent)))
	for {
		var doc map[string]interface{}
		if dErr := decoder.Decode(&doc); dErr != nil {
			break
		}
		if doc != nil {
			docs = append(docs, doc)
		}
	}
	foundBaseWidget := false
	for _, doc := range docs {
		if doc["kind"] == "Widget" {
			foundBaseWidget = true
			meta, _ := doc["metadata"].(map[string]interface{})
			assert.Empty(t, meta["namespace"], "base document for cluster-scoped custom resource Widget must remain namespace-free")
		}
	}
	assert.True(t, foundBaseWidget, "base.yaml must contain Widget")

	// 6. Verify krusty build successfully applies patches while keeping cluster-scoped resources namespace-free
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	resMap, err := k.Run(filesys.MakeFsOnDisk(), outDir)
	require.NoError(t, err, "kustomize build must succeed")
	outYaml, err := resMap.AsYaml()
	require.NoError(t, err)
	assert.Contains(t, string(outYaml), "patched: applied")

	foundBuiltSvc := false
	foundBuiltWidget := false
	for _, r := range resMap.Resources() {
		if r.GetKind() == "Service" {
			foundBuiltSvc = true
			assert.Equal(t, "prod-namespace", r.GetNamespace(), "base Service must carry the release namespace")
			svcYAML, yErr := r.AsYAML()
			require.NoError(t, yErr)
			assert.Contains(t, string(svcYAML), "patched: applied", "Service patch must be applied")
		}
		if r.GetKind() == "Widget" {
			foundBuiltWidget = true
			assert.Empty(t, r.GetNamespace(), "cluster-scoped Widget must remain namespace-free in built output")
			widgetYAML, yErr := r.AsYAML()
			require.NoError(t, yErr)
			assert.Contains(t, string(widgetYAML), "patched: applied", "Widget patch must be applied")
		}
	}
	assert.True(t, foundBuiltSvc, "built output must contain the Service")
	assert.True(t, foundBuiltWidget, "built output must contain the Widget")
}

// TestFollowup_ValueConversionParity verifies that parseFixValue retains sequence whitelisting
// and unsigned 64-bit integer handling identical to the standard fixer contract.
func TestFollowup_ValueConversionParity(t *testing.T) {
	// Nested sequence [[1]] must remain a string scalar
	nestedSeq := parseFixValue("[[1]]")
	assert.Equal(t, "[[1]]", nestedSeq, "nested sequence [[1]] must remain a string scalar")

	// Sequence of objects [{"key":"value"}] must remain a string scalar
	mapSeq := parseFixValue(`[{"key":"value"}]`)
	assert.Equal(t, `[{"key":"value"}]`, mapSeq, "map sequence must remain a string scalar")

	// Scientific notation sequence [1e3] must remain a string scalar
	expSeq := parseFixValue("[1e3]")
	assert.Equal(t, "[1e3]", expSeq, "scientific notation sequence must remain a string scalar")

	// MaxUint64 (18446744073709551615) must be parsed as a uint64 integer
	maxUint := parseFixValue("18446744073709551615")
	assert.Equal(t, uint64(18446744073709551615), maxUint, "18446744073709551615 must parse as uint64")

	// Valid 1-D flow sequence of plain scalars must decode to []interface{}
	validSeq := parseFixValue(`["a", "b"]`)
	assert.Equal(t, []interface{}{"a", "b"}, validSeq, "valid flow sequence must parse to slice")

	// Booleans, standard integers, floats, and octal integers
	assert.Equal(t, true, parseFixValue("true"))
	assert.Equal(t, 42, parseFixValue("42"))
	assert.Equal(t, 3.14, parseFixValue("3.14"))
	assert.Equal(t, 511, parseFixValue("0777"))
}

// TestReview_PreservesEscapingSymlinkOnPublicationFailure verifies that when an escaping symlink
// (e.g. base.yaml -> external file) exists in the output directory, EmitKustomizePatch rejects
// publication, leaves the external file untouched, and preserves the pre-existing symlink itself
// without replacing it with a regular file containing external data.
func TestReview_PreservesEscapingSymlinkOnPublicationFailure(t *testing.T) {
	tmpDir := t.TempDir()
	outDir := filepath.Join(tmpDir, "out")
	outsideDir := filepath.Join(tmpDir, "outside")
	require.NoError(t, os.MkdirAll(outDir, 0700))
	require.NoError(t, os.MkdirAll(outsideDir, 0700))

	outsideFile := filepath.Join(outsideDir, "external-target.txt")
	externalContent := "SENSITIVE_EXTERNAL_TARGET_CONTENT"
	require.NoError(t, os.WriteFile(outsideFile, []byte(externalContent), 0600))

	// Create symlink base.yaml inside outDir pointing outside to external-target.txt
	linkPath := filepath.Join(outDir, "base.yaml")
	require.NoError(t, os.Symlink(outsideFile, linkPath))

	svc := makeResource("Service", "web-svc")
	svc.GetObject()["spec"] = map[string]interface{}{"type": "ClusterIP"}
	suggestions := []HelmFixSuggestion{
		{
			Resource:           svc,
			ChartName:          "web-chart",
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "metadata.labels.patched", Value: "\"true\""},
			},
		},
	}

	// EmitKustomizePatch with WithOverwrite(true) must reject the escaping symlink
	res, err := EmitKustomizePatch(suggestions, outDir, WithOverwrite(true))
	require.Error(t, err)
	assert.Nil(t, res)

	// Verify the symlink itself still exists and was not replaced by a regular file
	fi, lErr := os.Lstat(linkPath)
	require.NoError(t, lErr, "base.yaml entry must be preserved")
	assert.True(t, fi.Mode()&os.ModeSymlink != 0, "base.yaml must remain a symlink, not a regular file")

	target, rErr := os.Readlink(linkPath)
	require.NoError(t, rErr)
	assert.Equal(t, outsideFile, target, "base.yaml must still point to outside file")

	// Verify outside file was not modified
	content, rErr := os.ReadFile(outsideFile)
	require.NoError(t, rErr)
	assert.Equal(t, externalContent, string(content), "external target content must remain untouched")
}

// TestReview_PreservesEmptyDirectoryOnPublicationFailure verifies that when an empty directory
// (e.g. base.yaml) already exists in the output directory, EmitKustomizePatch rejects publication
// and preserves the pre-existing empty directory without deleting it on rollback.
func TestReview_PreservesEmptyDirectoryOnPublicationFailure(t *testing.T) {
	outDir := t.TempDir()

	// Create an empty directory named base.yaml in outDir
	emptyDir := filepath.Join(outDir, "base.yaml")
	require.NoError(t, os.Mkdir(emptyDir, 0700))

	svc := makeResource("Service", "web-svc")
	svc.GetObject()["spec"] = map[string]interface{}{"type": "ClusterIP"}
	suggestions := []HelmFixSuggestion{
		{
			Resource:           svc,
			ChartName:          "web-chart",
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "metadata.labels.patched", Value: "\"true\""},
			},
		},
	}

	// EmitKustomizePatch with WithOverwrite(true) must reject overwriting the directory
	res, err := EmitKustomizePatch(suggestions, outDir, WithOverwrite(true))
	require.Error(t, err)
	assert.Nil(t, res)

	// Verify the empty directory was preserved and not deleted
	fi, err := os.Lstat(emptyDir)
	require.NoError(t, err, "empty base.yaml directory must be preserved on failure")
	assert.True(t, fi.IsDir(), "base.yaml must remain a directory")

	entries, err := os.ReadDir(emptyDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "base.yaml directory must remain empty")
}

// TestFollowup_ReleaseNamespacePreservesLargeIntegers verifies that injecting a release namespace
// into caller-supplied UnredactedBase preserves exact integers above 2^53 without float64 precision loss.
func TestFollowup_ReleaseNamespacePreservesLargeIntegers(t *testing.T) {
	outDir := t.TempDir()

	svc := makeResource("Service", "large-int-svc")
	delete(svc.GetObject()["metadata"].(map[string]interface{}), "namespace")
	svc.GetObject()["spec"] = map[string]interface{}{
		"type":     "ClusterIP",
		"largeInt": int64(9007199254740993),
	}
	suggestions := []HelmFixSuggestion{
		{
			Resource:           svc,
			ChartName:          "int-chart",
			FidelityProvenance: true,
			HelmValueOptions: cautils.HelmValueOptions{
				ReleaseNamespace: "injected-ns",
			},
			FixPaths: []armotypes.FixPath{
				{Path: "metadata.labels.patched", Value: "\"true\""},
			},
		},
	}

	res, err := EmitKustomizePatch(suggestions, outDir, WithOverwrite(true))
	require.NoError(t, err)
	assert.NotNil(t, res)

	baseBytes, err := os.ReadFile(filepath.Join(outDir, "base.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(baseBytes), "namespace: injected-ns", "injected release namespace must appear in base.yaml")
	assert.Contains(t, string(baseBytes), "9007199254740993", "exact large integer must not be rounded by float64")
}

// TestResolveBaseObject_ReleaseNamespaceNormalizedBeforeScannedFieldCheck verifies that
// when a scanned Service has metadata.namespace: prod, but the rendered base omits metadata.namespace,
// and ReleaseNamespace == "prod", resolveBaseObject normalizes the namespace on a copy of the candidate
// before verifyScannedFieldsMatch runs, so the Service is not declined or skipped.
func TestResolveBaseObject_ReleaseNamespaceNormalizedBeforeScannedFieldCheck(t *testing.T) {
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: test-svc\nversion: 0.1.0\n"), 0600))
	templatesDir := filepath.Join(chartDir, "templates")
	require.NoError(t, os.MkdirAll(templatesDir, 0755))

	// Template omits metadata.namespace (typical Helm pattern)
	svcNoNsYaml := `apiVersion: v1
kind: Service
metadata:
  name: web-service
spec:
  type: ClusterIP
  ports:
  - port: 80
`
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, "service.yaml"), []byte(svcNoNsYaml), 0600))

	// Scanned resource has metadata.namespace: prod
	scannedSvc := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Service",
			"metadata": map[string]interface{}{
				"name":      "web-service",
				"namespace": "prod",
			},
			"spec": map[string]interface{}{
				"type": "ClusterIP",
				"ports": []interface{}{
					map[string]interface{}{
						"port": 80,
					},
				},
			},
		},
	}

	outDir := t.TempDir()
	suggestions := []HelmFixSuggestion{
		{
			Resource:     scannedSvc,
			ChartPath:    chartDir,
			TemplateFile: "templates/service.yaml",
			HelmValueOptions: cautils.HelmValueOptions{
				ReleaseNamespace: "prod",
			},
			FixPaths: []armotypes.FixPath{
				{Path: "metadata.labels.patched", Value: "\"true\""},
			},
		},
	}

	res, err := EmitKustomizePatch(suggestions, outDir, WithOverwrite(true))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Empty(t, res.SkippedResources, "scanned service with matching ReleaseNamespace must not be declined")
	assert.Len(t, res.EmittedResources, 1)

	baseBytes, err := os.ReadFile(filepath.Join(outDir, "base.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(baseBytes), "namespace: prod")
}

// TestResolveBaseObject_ReleaseNamespaceDoesNotMutateCallerUnredactedBase verifies that
// normalizing the release namespace before verifyScannedFieldsMatch does not mutate caller-owned UnredactedBase.
func TestResolveBaseObject_ReleaseNamespaceDoesNotMutateCallerUnredactedBase(t *testing.T) {
	callerUnredacted := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]interface{}{
			"name": "unredacted-svc",
		},
		"spec": map[string]interface{}{
			"type": "ClusterIP",
		},
	}

	scannedSvc := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Service",
			"metadata": map[string]interface{}{
				"name":      "unredacted-svc",
				"namespace": "prod",
			},
			"spec": map[string]interface{}{
				"type": "ClusterIP",
			},
		},
	}

	outDir := t.TempDir()
	suggestions := []HelmFixSuggestion{
		{
			Resource:       scannedSvc,
			UnredactedBase: callerUnredacted,
			HelmValueOptions: cautils.HelmValueOptions{
				ReleaseNamespace: "prod",
			},
			FixPaths: []armotypes.FixPath{
				{Path: "metadata.labels.patched", Value: "\"true\""},
			},
		},
	}

	res, err := EmitKustomizePatch(suggestions, outDir, WithOverwrite(true))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Empty(t, res.SkippedResources)

	// Caller-owned UnredactedBase must NOT be mutated
	meta, ok := callerUnredacted["metadata"].(map[string]interface{})
	require.True(t, ok)
	_, hasNs := meta["namespace"]
	assert.False(t, hasNs, "caller-owned UnredactedBase must not be mutated")

	baseBytes, err := os.ReadFile(filepath.Join(outDir, "base.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(baseBytes), "namespace: prod", "emitted base.yaml must have normalized namespace")
}

// TestResolveBaseObject_ReleaseNamespaceDeclinesWhenMismatched verifies that
// if ReleaseNamespace does not match the scanned namespace, normalization does not apply and mismatch is reported.
func TestResolveBaseObject_ReleaseNamespaceDeclinesWhenMismatched(t *testing.T) {
	callerUnredacted := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]interface{}{
			"name": "mismatched-svc",
		},
		"spec": map[string]interface{}{
			"type": "ClusterIP",
		},
	}

	scannedSvc := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Service",
			"metadata": map[string]interface{}{
				"name":      "mismatched-svc",
				"namespace": "prod",
			},
			"spec": map[string]interface{}{
				"type": "ClusterIP",
			},
		},
	}

	outDir := t.TempDir()
	suggestions := []HelmFixSuggestion{
		{
			Resource:       scannedSvc,
			UnredactedBase: callerUnredacted,
			HelmValueOptions: cautils.HelmValueOptions{
				ReleaseNamespace: "staging",
			},
			FixPaths: []armotypes.FixPath{
				{Path: "metadata.labels.patched", Value: "\"true\""},
			},
		},
	}

	res, err := EmitKustomizePatch(suggestions, outDir, WithOverwrite(true))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Len(t, res.SkippedResources, 1, "resource must be skipped due to namespace mismatch")
	assert.Contains(t, res.SkippedResources[0].Reason, "metadata.namespace")
}

// TestResolveBaseObject_ReleaseNamespaceClusterScopedResourceRemainsNamespaceFree verifies that
// cluster-scoped resources (such as ClusterRole) remain namespace-free even when ReleaseNamespace is specified.
func TestResolveBaseObject_ReleaseNamespaceClusterScopedResourceRemainsNamespaceFree(t *testing.T) {
	callerUnredacted := map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata": map[string]interface{}{
			"name": "cluster-admin-role",
		},
		"rules": []interface{}{
			map[string]interface{}{
				"apiGroups": []interface{}{""},
				"resources": []interface{}{"pods"},
				"verbs":     []interface{}{"get"},
			},
		},
	}

	scannedRole := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "rbac.authorization.k8s.io/v1",
			"kind":       "ClusterRole",
			"metadata": map[string]interface{}{
				"name": "cluster-admin-role",
			},
			"rules": []interface{}{
				map[string]interface{}{
					"apiGroups": []interface{}{""},
					"resources": []interface{}{"pods"},
					"verbs":     []interface{}{"get"},
				},
			},
		},
	}

	outDir := t.TempDir()
	suggestions := []HelmFixSuggestion{
		{
			Resource:       scannedRole,
			UnredactedBase: callerUnredacted,
			HelmValueOptions: cautils.HelmValueOptions{
				ReleaseNamespace: "prod",
			},
			FixPaths: []armotypes.FixPath{
				{Path: "metadata.labels.patched", Value: "\"true\""},
			},
		},
	}

	res, err := EmitKustomizePatch(suggestions, outDir, WithOverwrite(true))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Empty(t, res.SkippedResources)

	baseBytes, err := os.ReadFile(filepath.Join(outDir, "base.yaml"))
	require.NoError(t, err)
	assert.NotContains(t, string(baseBytes), "namespace:", "cluster-scoped resource must remain namespace-free")
}

// TestVerifyScannedFieldsMatch_ExactLargeIntegers verifies that verifyScannedFieldsMatch
// compares integer types with exact arithmetic instead of float64, catching differences above 2^53.
func TestVerifyScannedFieldsMatch_ExactLargeIntegers(t *testing.T) {
	scanned := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"data": map[string]interface{}{
			"val": int64(9007199254740993),
		},
	}
	// candidate has 9007199254740992, which would equal 9007199254740993 under float64 conversion
	candidateMismatch := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"data": map[string]interface{}{
			"val": int64(9007199254740992),
		},
	}

	err := verifyScannedFieldsMatch(scanned, candidateMismatch, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "value mismatch at data.val: scanned 9007199254740993, rendered 9007199254740992")

	// Same large integer compares equal
	candidateEqual := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"data": map[string]interface{}{
			"val": int64(9007199254740993),
		},
	}
	require.NoError(t, verifyScannedFieldsMatch(scanned, candidateEqual, ""))
}

// TestFollowup_PreloadContainment_ValueFilesAndFileValues verifies that chart preload
// enforces containment checks on HelmValueOptions.ValueFiles and FileValues before reading them.
func TestFollowup_PreloadContainment_ValueFilesAndFileValues(t *testing.T) {
	allowedDir := t.TempDir()
	outsideDir := t.TempDir()

	chartDir := filepath.Join(allowedDir, "mychart")
	templatesDir := filepath.Join(chartDir, "templates")
	require.NoError(t, os.MkdirAll(templatesDir, 0700))

	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: mychart\nversion: 0.1.0\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, "service.yaml"), []byte("apiVersion: v1\nkind: Service\nmetadata:\n  name: my-svc\nspec:\n  ports:\n  - port: 80\n"), 0600))

	outsideValues := filepath.Join(outsideDir, "secret-values.yaml")
	require.NoError(t, os.WriteFile(outsideValues, []byte("foo: secret\n"), 0600))

	svc := makeResource("Service", "my-svc")
	svc.GetObject()["apiVersion"] = "v1"
	delete(svc.GetObject()["metadata"].(map[string]interface{}), "namespace")
	svc.GetObject()["spec"] = map[string]interface{}{
		"ports": []interface{}{
			map[string]interface{}{"port": int64(80)},
		},
	}

	// 1. Suggestion with ValueFiles outside allowedBasePath
	s1 := HelmFixSuggestion{
		Resource:        svc,
		ChartPath:       chartDir,
		AllowedBasePath: allowedDir,
		HelmValueOptions: cautils.HelmValueOptions{
			ValueFiles: []string{outsideValues},
		},
		FixPaths: []armotypes.FixPath{
			{Path: "metadata.labels.patched", Value: "\"true\""},
		},
	}

	outDir := t.TempDir()
	res, err := EmitKustomizePatch([]HelmFixSuggestion{s1}, outDir, WithOverwrite(true))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Empty(t, res.EmittedResources)
	require.Len(t, res.SkippedResources, 1)
	assert.Contains(t, res.SkippedResources[0].Reason, "is outside allowed base path")

	// 2. Suggestion with FileValues outside allowedBasePath
	s2 := HelmFixSuggestion{
		Resource:        svc,
		ChartPath:       chartDir,
		AllowedBasePath: allowedDir,
		HelmValueOptions: cautils.HelmValueOptions{
			FileValues: []string{"custom=" + outsideValues},
		},
		FixPaths: []armotypes.FixPath{
			{Path: "metadata.labels.patched", Value: "\"true\""},
		},
	}

	outDir2 := t.TempDir()
	res2, err := EmitKustomizePatch([]HelmFixSuggestion{s2}, outDir2, WithOverwrite(true))
	require.NoError(t, err)
	require.NotNil(t, res2)
	assert.Empty(t, res2.EmittedResources)
	require.Len(t, res2.SkippedResources, 1)
	assert.Contains(t, res2.SkippedResources[0].Reason, "is outside allowed base path")
}

// TestFollowup_CrossChartCRDScopeIsolation verifies that a cluster-scoped CRD in one chart
// does not pollute or override namespaced custom resources in another chart within the same batch.
func TestFollowup_CrossChartCRDScopeIsolation(t *testing.T) {
	baseDir := t.TempDir()

	// Chart A defines a Namespaced Widget
	chartADir := filepath.Join(baseDir, "chart-a")
	templatesADir := filepath.Join(chartADir, "templates")
	require.NoError(t, os.MkdirAll(templatesADir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(chartADir, "Chart.yaml"), []byte("apiVersion: v2\nname: chart-a\nversion: 0.1.0\n"), 0600))
	crdAYaml := `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: widgets.example.com
spec:
  group: example.com
  scope: Namespaced
  names:
    kind: Widget
`
	widgetAYaml := `apiVersion: example.com/v1
kind: Widget
metadata:
  name: widget-a
spec:
  replicas: 1
`
	require.NoError(t, os.WriteFile(filepath.Join(templatesADir, "crd.yaml"), []byte(crdAYaml), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(templatesADir, "widget.yaml"), []byte(widgetAYaml), 0600))

	// Chart B defines a Cluster-scoped Widget
	chartBDir := filepath.Join(baseDir, "chart-b")
	templatesBDir := filepath.Join(chartBDir, "templates")
	require.NoError(t, os.MkdirAll(templatesBDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(chartBDir, "Chart.yaml"), []byte("apiVersion: v2\nname: chart-b\nversion: 0.1.0\n"), 0600))
	crdBYaml := `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: widgets.example.com
spec:
  group: example.com
  scope: Cluster
  names:
    kind: Widget
`
	widgetBYaml := `apiVersion: example.com/v1
kind: Widget
metadata:
  name: widget-b
spec:
  replicas: 2
`
	require.NoError(t, os.WriteFile(filepath.Join(templatesBDir, "crd.yaml"), []byte(crdBYaml), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(templatesBDir, "widget.yaml"), []byte(widgetBYaml), 0600))

	// Scanned resource for widget-a (namespaced, no explicit metadata.namespace)
	resA := makeResource("Widget", "widget-a")
	resA.GetObject()["apiVersion"] = "example.com/v1"
	delete(resA.GetObject()["metadata"].(map[string]interface{}), "namespace")
	resA.GetObject()["spec"] = map[string]interface{}{
		"replicas": int64(1),
	}

	// Scanned resource for widget-b (cluster-scoped, no explicit metadata.namespace)
	resB := makeResource("Widget", "widget-b")
	resB.GetObject()["apiVersion"] = "example.com/v1"
	delete(resB.GetObject()["metadata"].(map[string]interface{}), "namespace")
	resB.GetObject()["spec"] = map[string]interface{}{
		"replicas": int64(2),
	}

	suggestions := []HelmFixSuggestion{
		{
			Resource:           resA,
			ChartPath:          chartADir,
			AllowedBasePath:    baseDir,
			FidelityProvenance: true,
			HelmValueOptions: cautils.HelmValueOptions{
				ReleaseNamespace: "tenant-a",
			},
			FixPaths: []armotypes.FixPath{
				{Path: "spec.replicas", Value: "3"},
			},
		},
		{
			Resource:           resB,
			ChartPath:          chartBDir,
			AllowedBasePath:    baseDir,
			FidelityProvenance: true,
			FixPaths: []armotypes.FixPath{
				{Path: "spec.replicas", Value: "4"},
			},
		},
	}

	outDir := t.TempDir()
	res, err := EmitKustomizePatch(suggestions, outDir, WithOverwrite(true))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Empty(t, res.SkippedResources)
	assert.Len(t, res.EmittedResources, 2)

	// Verify kustomization.yaml targets
	kustBytes, err := os.ReadFile(filepath.Join(outDir, "kustomization.yaml"))
	require.NoError(t, err)
	var kust kustomizationDoc
	require.NoError(t, yaml.Unmarshal(kustBytes, &kust))

	var targetA, targetB *kustomizeTarget
	for _, p := range kust.Patches {
		if strings.Contains(p.Path, "widget-a") {
			tCopy := p.Target
			targetA = &tCopy
		}
		if strings.Contains(p.Path, "widget-b") {
			tCopy := p.Target
			targetB = &tCopy
		}
	}
	require.NotNil(t, targetA, "patch for widget-a must exist")
	require.NotNil(t, targetB, "patch for widget-b must exist")

	// widget-a belongs to Chart A (Namespaced) and should have target namespace regex matching tenant-a
	assert.Equal(t, "^($|default|tenant-a$)", targetA.Namespace, "namespaced widget from Chart A must have target namespace")

	// widget-b belongs to Chart B (Cluster) and should have NO target namespace
	assert.Empty(t, targetB.Namespace, "cluster-scoped widget from Chart B must not have target namespace")
}

// TestFollowup_HeldRootRenameResilience verifies that restoreBackups operates strictly
// through the open file descriptor in *os.Root even if the directory path is moved on disk.
func TestFollowup_HeldRootRenameResilience(t *testing.T) {
	parent := t.TempDir()
	origDir := filepath.Join(parent, "orig")
	require.NoError(t, os.Mkdir(origDir, 0700))

	backupRelDir := ".backup"
	require.NoError(t, os.Mkdir(filepath.Join(origDir, backupRelDir), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(origDir, backupRelDir, "base.yaml"), []byte("PRESERVED"), 0600))

	root, err := os.OpenRoot(origDir)
	require.NoError(t, err)
	defer root.Close()

	// Simulate origDir being moved or swapped on the filesystem path
	renamedDir := filepath.Join(parent, "renamed")
	require.NoError(t, os.Rename(origDir, renamedDir))

	// restoreBackups must succeed using the held root descriptor even though the original path moved
	err = restoreBackups(root, backupRelDir)
	require.NoError(t, err)

	restored, err := os.ReadFile(filepath.Join(renamedDir, "base.yaml"))
	require.NoError(t, err)
	assert.Equal(t, "PRESERVED", string(restored))
}

// TestFollowup_LazyChartRenderingAndCacheSharing verifies that:
//  1. Suggestions with UnredactedBase for built-in kinds do not attempt to render charts.
//  2. A shared chartCache passed to HasEmittableKustomizePatches, PlannedKustomizeFiles,
//     and EmitKustomizePatch caches rendered charts and avoids re-rendering.
func TestFollowup_LazyChartRenderingAndCacheSharing(t *testing.T) {
	// 1. Suggestion with UnredactedBase for a standard Deployment with non-existent ChartPath
	scannedDep := makeResource("Deployment", "my-app")
	scannedDep.GetObject()["apiVersion"] = "apps/v1"
	scannedDep.GetObject()["spec"] = map[string]interface{}{
		"replicas": int64(1),
	}
	depBase := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      "my-app",
			"namespace": "default",
		},
		"spec": map[string]interface{}{
			"replicas": int64(1),
		},
	}
	depSuggestion := HelmFixSuggestion{
		Resource:       scannedDep,
		UnredactedBase: depBase,
		ChartPath:      filepath.Join(t.TempDir(), "non-existent-chart-dir"),
		FixPaths: []armotypes.FixPath{
			{Path: "spec.replicas", Value: "2"},
		},
	}

	// This must succeed without error or trying to read the non-existent chart directory
	outDir1 := t.TempDir()
	res1, err := EmitKustomizePatch([]HelmFixSuggestion{depSuggestion}, outDir1, WithOverwrite(true))
	require.NoError(t, err, "built-in resource with UnredactedBase must not render chart")
	require.NotNil(t, res1)
	assert.Len(t, res1.EmittedResources, 1)

	// 2. Suggestion that requires chart rendering, sharing chartCache across calls
	chartDir := filepath.Join(t.TempDir(), "sample-chart")
	require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "templates"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("name: sample-chart\nversion: 0.1.0\napiVersion: v2\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "templates", "service.yaml"), []byte(`apiVersion: v1
kind: Service
metadata:
  name: sample-svc
spec:
  type: ClusterIP
`), 0600))

	scannedSvc := makeResource("Service", "sample-svc")
	scannedSvc.GetObject()["apiVersion"] = "v1"
	delete(scannedSvc.GetObject()["metadata"].(map[string]interface{}), "namespace")
	scannedSvc.GetObject()["spec"] = map[string]interface{}{"type": "ClusterIP"}

	chartSuggestion := HelmFixSuggestion{
		Resource:  scannedSvc,
		ChartPath: chartDir,
		ChartName: "sample-chart",
		HelmValueOptions: cautils.HelmValueOptions{
			ReleaseNamespace: "test-ns",
		},
		FixPaths: []armotypes.FixPath{
			{Path: "metadata.labels.env", Value: "prod"},
		},
	}

	sharedCache := NewChartCache()
	assert.Empty(t, sharedCache)

	// HasEmittableKustomizePatches populates sharedCache
	emittable := HasEmittableKustomizePatches([]HelmFixSuggestion{chartSuggestion}, sharedCache)
	assert.True(t, emittable)
	assert.NotEmpty(t, sharedCache, "sharedCache must be populated after HasEmittableKustomizePatches")

	// PlannedKustomizeFiles reuses sharedCache
	files := PlannedKustomizeFiles([]HelmFixSuggestion{chartSuggestion}, sharedCache)
	assert.Contains(t, files, "base.yaml")
	assert.Contains(t, files, "kustomization.yaml")

	// EmitKustomizePatch reuses sharedCache
	outDir2 := t.TempDir()
	res2, err := EmitKustomizePatch([]HelmFixSuggestion{chartSuggestion}, outDir2, WithOverwrite(true), WithChartCache(sharedCache))
	require.NoError(t, err)
	require.NotNil(t, res2)
	assert.Len(t, res2.EmittedResources, 1)
}

// TestKustomize_Uint64MaxBuildLevelPreservation verifies that uint64 values up to the maximum safe
// integer (9007199254740991) are preserved exactly through the final Kustomize build, while values
// exceeding max safe integer (such as 18446744073709551615) that cannot be preserved exactly without
// float64 corruption are rejected.
func TestKustomize_Uint64MaxBuildLevelPreservation(t *testing.T) {
	outDir := t.TempDir()

	// 1. Verify that 18446744073709551615 is rejected because Kustomize's patch applicator cannot preserve it
	scannedSvc := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Service",
			"metadata": map[string]interface{}{
				"name":      "max-uint-svc",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"type": "ClusterIP",
				"ports": []interface{}{
					map[string]interface{}{
						"port": int64(80),
					},
				},
			},
		},
	}
	svcBase := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]interface{}{
			"name":      "max-uint-svc",
			"namespace": "default",
		},
		"spec": map[string]interface{}{
			"type": "ClusterIP",
			"ports": []interface{}{
				map[string]interface{}{
					"port": int64(80),
				},
			},
		},
	}

	suggestions := []HelmFixSuggestion{
		{
			Resource:       scannedSvc,
			UnredactedBase: svcBase,
			FixPaths: []armotypes.FixPath{
				{Path: "spec.ports[0].targetPort", Value: "18446744073709551615"},
			},
		},
	}

	res, err := EmitKustomizePatch(suggestions, outDir, WithOverwrite(true))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Empty(t, res.EmittedResources, "must not emit patch when value cannot be preserved exactly")
	require.Len(t, res.SkippedResources, 1)
	assert.Contains(t, res.SkippedResources[0].Reason, "18446744073709551615")
	assert.Contains(t, res.SkippedResources[0].Reason, "cannot be preserved exactly")

	// 2. Verify that maximum safe integer 9007199254740991 is preserved end-to-end through krusty
	outDirSafe := t.TempDir()
	suggestionsSafe := []HelmFixSuggestion{
		{
			Resource:       scannedSvc,
			UnredactedBase: svcBase,
			FixPaths: []armotypes.FixPath{
				{Path: "metadata.labels.counter", Value: "\"9007199254740991\""},
				{Path: "spec.customCounter", Value: "9007199254740991"},
			},
		},
	}
	resSafe, err := EmitKustomizePatch(suggestionsSafe, outDirSafe, WithOverwrite(true))
	require.NoError(t, err)
	require.NotNil(t, resSafe)
	assert.Len(t, resSafe.EmittedResources, 1)

	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	resMap, err := k.Run(filesys.MakeFsOnDisk(), outDirSafe)
	require.NoError(t, err)
	yamlBytes, err := resMap.AsYaml()
	require.NoError(t, err)
	assert.Contains(t, string(yamlBytes), "9007199254740991", "Kustomize build must preserve exact safe integer value")

	var builtObj map[string]interface{}
	require.NoError(t, yaml.Unmarshal(yamlBytes, &builtObj))
	specMap, ok := builtObj["spec"].(map[string]interface{})
	require.True(t, ok)
	val, ok := toInt64(specMap["customCounter"])
	require.True(t, ok, "customCounter must decode as an integer")
	assert.Equal(t, int64(9007199254740991), val, "customCounter must equal exact safe integer value")

	// 3. Verify sequence member exceeding max safe integer is rejected
	outDirSeq := t.TempDir()
	suggestionsSeq := []HelmFixSuggestion{
		{
			Resource:       scannedSvc,
			UnredactedBase: svcBase,
			FixPaths: []armotypes.FixPath{
				{Path: "spec.ports[0].targetPort", Value: "[9007199254740993]"},
			},
		},
	}
	resSeq, err := EmitKustomizePatch(suggestionsSeq, outDirSeq, WithOverwrite(true))
	require.NoError(t, err)
	require.NotNil(t, resSeq)
	assert.Empty(t, resSeq.EmittedResources)
	require.Len(t, resSeq.SkippedResources, 1)
	assert.Contains(t, resSeq.SkippedResources[0].Reason, "cannot be preserved exactly")
}

// TestKustomize_DestinationLocking verifies that EmitKustomizePatch respects an exclusive file lock
// on .kust.lock and rejects concurrent execution on the same destination directory.
func TestKustomize_DestinationLocking(t *testing.T) {
	outDir := t.TempDir()
	lockPath := filepath.Join(outDir, ".kust.lock")
	fileLock := flock.New(lockPath)
	locked, err := fileLock.TryLock()
	require.NoError(t, err)
	require.True(t, locked)
	defer func() { _ = fileLock.Unlock() }()

	svc := makeResource("Service", "locked-svc")
	sugg := HelmFixSuggestion{
		Resource:       svc,
		UnredactedBase: svc.GetObject(),
		FixPaths:       []armotypes.FixPath{{Path: "metadata.labels.patched", Value: "applied"}},
	}
	_, err = EmitKustomizePatch([]HelmFixSuggestion{sugg}, outDir, WithOverwrite(true))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "locked by another operation")
}

// TestKustomize_ChartLoadingRejectsLargeIntegerPrecisionMismatch verifies that fidelity comparison
// rejects a scanned value of 9007199254740993 against a rendered chart value of 9007199254740992,
// which would otherwise compare equal under float64 conversion.
func TestKustomize_ChartLoadingRejectsLargeIntegerPrecisionMismatch(t *testing.T) {
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: int-mismatch\nversion: 0.1.0\n"), 0600))

	// Define CRD under crds/
	crdsDir := filepath.Join(chartDir, "crds")
	require.NoError(t, os.MkdirAll(crdsDir, 0755))
	crdYaml := `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: widgets.example.com
spec:
  group: example.com
  scope: Namespaced
  names:
    kind: Widget
`
	require.NoError(t, os.WriteFile(filepath.Join(crdsDir, "crd.yaml"), []byte(crdYaml), 0600))

	templatesDir := filepath.Join(chartDir, "templates")
	require.NoError(t, os.MkdirAll(templatesDir, 0755))

	// Rendered chart template has 9007199254740992
	widgetYaml := `apiVersion: example.com/v1
kind: Widget
metadata:
  name: int-widget
  namespace: default
spec:
  largeInt: 9007199254740992
`
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, "widget.yaml"), []byte(widgetYaml), 0600))

	// Scanned resource has 9007199254740993
	scannedWidget := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "example.com/v1",
			"kind":       "Widget",
			"metadata": map[string]interface{}{
				"name":      "int-widget",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"largeInt": int64(9007199254740993),
			},
		},
	}

	outDir := t.TempDir()
	suggestions := []HelmFixSuggestion{
		{
			Resource:     scannedWidget,
			ChartPath:    chartDir,
			TemplateFile: "templates/widget.yaml",
			FixPaths: []armotypes.FixPath{
				{Path: "metadata.labels.patched", Value: "\"true\""},
			},
		},
	}

	res, err := EmitKustomizePatch(suggestions, outDir, WithOverwrite(true))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Empty(t, res.EmittedResources, "must not emit patch when large integer values mismatch")
	require.Len(t, res.SkippedResources, 1, "resource must be skipped due to large integer mismatch")
	assert.Contains(t, res.SkippedResources[0].Reason, "9007199254740993")
	assert.Contains(t, res.SkippedResources[0].Reason, "9007199254740992")
}

// TestResolveBaseObject_ScannedWithoutNamespaceMatchesRenderedWithReleaseNamespace verifies that
// when a scanned resource omits metadata.namespace but its rendered candidate explicitly defines
// metadata.namespace matching the ReleaseNamespace, bidirectional normalization succeeds and emits.
func TestResolveBaseObject_ScannedWithoutNamespaceMatchesRenderedWithReleaseNamespace(t *testing.T) {
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: explicit-ns\nversion: 0.1.0\n"), 0600))
	templatesDir := filepath.Join(chartDir, "templates")
	require.NoError(t, os.MkdirAll(templatesDir, 0755))

	// Rendered chart template explicitly sets metadata.namespace to prod
	svcYaml := `apiVersion: v1
kind: Service
metadata:
  name: explicit-ns-svc
  namespace: prod
spec:
  type: ClusterIP
  ports:
  - port: 80
`
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, "service.yaml"), []byte(svcYaml), 0600))

	// Scanned resource has NO namespace specified
	scannedSvc := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Service",
			"metadata": map[string]interface{}{
				"name": "explicit-ns-svc",
			},
			"spec": map[string]interface{}{
				"type": "ClusterIP",
				"ports": []interface{}{
					map[string]interface{}{
						"port": 80,
					},
				},
			},
		},
	}

	outDir := t.TempDir()
	suggestions := []HelmFixSuggestion{
		{
			Resource:     scannedSvc,
			ChartPath:    chartDir,
			TemplateFile: "templates/service.yaml",
			HelmValueOptions: cautils.HelmValueOptions{
				ReleaseNamespace: "prod",
			},
			FixPaths: []armotypes.FixPath{
				{Path: "metadata.labels.patched", Value: "\"true\""},
			},
		},
	}

	res, err := EmitKustomizePatch(suggestions, outDir, WithOverwrite(true))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Empty(t, res.SkippedResources, "scanned service without namespace matching rendered ReleaseNamespace must not be declined")
	assert.Len(t, res.EmittedResources, 1)

	baseBytes, err := os.ReadFile(filepath.Join(outDir, "base.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(baseBytes), "namespace: prod")
}

// TestFollowup_CRDUnderStandardCrdsAndDependenciesScopeResolved verifies that CRDs placed under
// a chart's standard crds/ directory and dependency charts/subchart/crds/ directory are properly
// discovered and resolved when determining whether a resource is cluster-scoped.
func TestFollowup_CRDUnderStandardCrdsAndDependenciesScopeResolved(t *testing.T) {
	chartDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: parent-chart\nversion: 0.1.0\n"), 0600))

	// Chart's standard crds/ directory
	crdsDir := filepath.Join(chartDir, "crds")
	require.NoError(t, os.MkdirAll(crdsDir, 0755))
	parentCRDYaml := `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: parentclusters.example.com
spec:
  group: example.com
  scope: Cluster
  names:
    kind: ParentCluster
`
	require.NoError(t, os.WriteFile(filepath.Join(crdsDir, "parent-cluster.yaml"), []byte(parentCRDYaml), 0600))

	// Dependency chart under charts/subchart/crds/
	subChartCRDDir := filepath.Join(chartDir, "charts", "subchart", "crds")
	require.NoError(t, os.MkdirAll(subChartCRDDir, 0755))
	subCRDYaml := `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: subclusters.example.com
spec:
  group: example.com
  scope: Cluster
  names:
    kind: SubCluster
`
	require.NoError(t, os.WriteFile(filepath.Join(subChartCRDDir, "sub-cluster.yaml"), []byte(subCRDYaml), 0600))

	// Subchart namespaced CRD
	subNamespacedCRDYaml := `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: subnamespaceds.example.com
spec:
  group: example.com
  scope: Namespaced
  names:
    kind: SubNamespaced
`
	require.NoError(t, os.WriteFile(filepath.Join(subChartCRDDir, "sub-namespaced.yaml"), []byte(subNamespacedCRDYaml), 0600))

	// Workloads using these custom resources
	parentRes := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "example.com/v1",
			"kind":       "ParentCluster",
			"metadata": map[string]interface{}{
				"name": "my-parent-cluster",
			},
			"spec": map[string]interface{}{
				"enabled": true,
			},
		},
	}
	parentBase := map[string]interface{}{
		"apiVersion": "example.com/v1",
		"kind":       "ParentCluster",
		"metadata": map[string]interface{}{
			"name": "my-parent-cluster",
		},
		"spec": map[string]interface{}{
			"enabled": true,
		},
	}

	subClusterRes := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "example.com/v1",
			"kind":       "SubCluster",
			"metadata": map[string]interface{}{
				"name": "my-sub-cluster",
			},
			"spec": map[string]interface{}{
				"replicas": int64(1),
			},
		},
	}
	subClusterBase := map[string]interface{}{
		"apiVersion": "example.com/v1",
		"kind":       "SubCluster",
		"metadata": map[string]interface{}{
			"name": "my-sub-cluster",
		},
		"spec": map[string]interface{}{
			"replicas": int64(1),
		},
	}

	subNamespacedRes := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "example.com/v1",
			"kind":       "SubNamespaced",
			"metadata": map[string]interface{}{
				"name": "my-sub-namespaced",
			},
			"spec": map[string]interface{}{
				"replicas": int64(2),
			},
		},
	}
	subNamespacedBase := map[string]interface{}{
		"apiVersion": "example.com/v1",
		"kind":       "SubNamespaced",
		"metadata": map[string]interface{}{
			"name": "my-sub-namespaced",
		},
		"spec": map[string]interface{}{
			"replicas": int64(2),
		},
	}

	// Unknown CRD (not declared anywhere)
	unknownRes := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "unknown.example.com/v1",
			"kind":       "UnknownResource",
			"metadata": map[string]interface{}{
				"name": "my-unknown",
			},
		},
	}
	unknownBase := map[string]interface{}{
		"apiVersion": "unknown.example.com/v1",
		"kind":       "UnknownResource",
		"metadata": map[string]interface{}{
			"name": "my-unknown",
		},
	}

	suggestions := []HelmFixSuggestion{
		{
			Resource:       parentRes,
			UnredactedBase: parentBase,
			ChartPath:      chartDir,
			HelmValueOptions: cautils.HelmValueOptions{
				ReleaseNamespace: "prod",
			},
			FixPaths: []armotypes.FixPath{
				{Path: "metadata.labels.patched", Value: "\"true\""},
			},
		},
		{
			Resource:       subClusterRes,
			UnredactedBase: subClusterBase,
			ChartPath:      chartDir,
			HelmValueOptions: cautils.HelmValueOptions{
				ReleaseNamespace: "prod",
			},
			FixPaths: []armotypes.FixPath{
				{Path: "metadata.labels.patched", Value: "\"true\""},
			},
		},
		{
			Resource:       subNamespacedRes,
			UnredactedBase: subNamespacedBase,
			ChartPath:      chartDir,
			HelmValueOptions: cautils.HelmValueOptions{
				ReleaseNamespace: "prod",
			},
			FixPaths: []armotypes.FixPath{
				{Path: "metadata.labels.patched", Value: "\"true\""},
			},
		},
		{
			Resource:       unknownRes,
			UnredactedBase: unknownBase,
			ChartPath:      chartDir,
			HelmValueOptions: cautils.HelmValueOptions{
				ReleaseNamespace: "prod",
			},
			FixPaths: []armotypes.FixPath{
				{Path: "metadata.labels.patched", Value: "\"true\""},
			},
		},
	}

	outDir := t.TempDir()
	res, err := EmitKustomizePatch(suggestions, outDir, WithOverwrite(true))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Empty(t, res.SkippedResources)
	assert.Len(t, res.EmittedResources, 4)

	kustBytes, err := os.ReadFile(filepath.Join(outDir, "kustomization.yaml"))
	require.NoError(t, err)
	var kust kustomizationDoc
	require.NoError(t, yaml.Unmarshal(kustBytes, &kust))

	matched := map[string]bool{}
	for _, p := range kust.Patches {
		switch {
		case strings.Contains(p.Path, "ParentCluster"):
			matched["ParentCluster"] = true
			// Cluster-scoped from parent crds/ directory -> namespace MUST be empty
			assert.Empty(t, p.Target.Namespace, "ParentCluster must have empty target namespace")
		case strings.Contains(p.Path, "SubCluster"):
			matched["SubCluster"] = true
			// Cluster-scoped from charts/subchart/crds/ directory -> namespace MUST be empty
			assert.Empty(t, p.Target.Namespace, "SubCluster must have empty target namespace")
		case strings.Contains(p.Path, "SubNamespaced"):
			matched["SubNamespaced"] = true
			// Namespaced from charts/subchart/crds/ directory -> namespace regex must be present
			assert.Equal(t, "^($|default|prod$)", p.Target.Namespace, "SubNamespaced must have target namespace regex")
		case strings.Contains(p.Path, "UnknownResource"):
			matched["UnknownResource"] = true
			// Unknown scope defaults safely to namespaced -> namespace regex must be present
			assert.Equal(t, "^($|default|prod$)", p.Target.Namespace, "UnknownResource must default to namespaced target namespace")
		}
	}
	for _, kind := range []string{"ParentCluster", "SubCluster", "SubNamespaced", "UnknownResource"} {
		assert.True(t, matched[kind], "no patch matched the %s scope branch", kind)
	}
}

func TestKustomize_DetectsAmbiguousOverlappingReleaseNamespaceAndDefaultTarget(t *testing.T) {
	svcNoNs := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Service",
			"metadata": map[string]interface{}{
				"name": "ambiguous-svc",
			},
			"spec": map[string]interface{}{
				"type": "ClusterIP",
			},
		},
	}
	svcExplicitDefault := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Service",
			"metadata": map[string]interface{}{
				"name":      "ambiguous-svc",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"type": "ClusterIP",
			},
		},
	}

	suggestions := []HelmFixSuggestion{
		{
			Resource:           svcNoNs,
			FidelityProvenance: true,
			HelmValueOptions: cautils.HelmValueOptions{
				ReleaseNamespace: "prod",
			},
			FixPaths: []armotypes.FixPath{{Path: "spec.type", Value: "NodePort"}},
		},
		{
			Resource:           svcExplicitDefault,
			FidelityProvenance: true,
			FixPaths:           []armotypes.FixPath{{Path: "spec.type", Value: "LoadBalancer"}},
		},
	}

	outDir := t.TempDir()
	_, err := EmitKustomizePatch(suggestions, outDir, WithOverwrite(true))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ambiguous patch target detected")
}

func TestKustomize_DetectsAmbiguousMixedClusterAndNamespacedTarget(t *testing.T) {
	// Setup Chart A (Namespaced CRD) and Chart B (Cluster CRD) for the same GVK
	tmp := t.TempDir()
	chartADir := filepath.Join(tmp, "chart-a")
	chartBDir := filepath.Join(tmp, "chart-b")
	require.NoError(t, os.MkdirAll(filepath.Join(chartADir, "crds"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(chartBDir, "crds"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(chartADir, "Chart.yaml"), []byte("apiVersion: v2\nname: chart-a\nversion: 0.1.0\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(chartBDir, "Chart.yaml"), []byte("apiVersion: v2\nname: chart-b\nversion: 0.1.0\n"), 0600))

	crdNamespacedYaml := `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: widgets.example.com
spec:
  group: example.com
  scope: Namespaced
  names:
    kind: Widget
`
	require.NoError(t, os.WriteFile(filepath.Join(chartADir, "crds", "widget.yaml"), []byte(crdNamespacedYaml), 0600))

	crdClusterYaml := `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: widgets.example.com
spec:
  group: example.com
  scope: Cluster
  names:
    kind: Widget
`
	require.NoError(t, os.WriteFile(filepath.Join(chartBDir, "crds", "widget.yaml"), []byte(crdClusterYaml), 0600))

	widgetBase := map[string]interface{}{
		"apiVersion": "example.com/v1",
		"kind":       "Widget",
		"metadata": map[string]interface{}{
			"name": "same-widget",
		},
		"spec": map[string]interface{}{
			"foo": "bar",
		},
	}

	suggestions := []HelmFixSuggestion{
		{
			Resource: &reporthandling.Resource{
				Object: widgetBase,
			},
			UnredactedBase: widgetBase,
			ChartPath:      chartADir,
			HelmValueOptions: cautils.HelmValueOptions{
				ReleaseNamespace: "tenant-a",
			},
			FixPaths: []armotypes.FixPath{{Path: "metadata.labels.patched", Value: "\"true\""}},
		},
		{
			Resource: &reporthandling.Resource{
				Object: widgetBase,
			},
			UnredactedBase: widgetBase,
			ChartPath:      chartBDir,
			FixPaths:       []armotypes.FixPath{{Path: "metadata.labels.patched", Value: "\"true\""}},
		},
	}

	outDir := t.TempDir()
	_, err := EmitKustomizePatch(suggestions, outDir, WithOverwrite(true))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ambiguous patch target detected")
}
