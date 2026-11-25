package fixhandler

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

func TestFindKustomizationFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Empty dir
	assert.Empty(t, findKustomizationFile(tmpDir))

	// Create kustomization.yaml
	yamlPath := filepath.Join(tmpDir, "kustomization.yaml")
	require.NoError(t, os.WriteFile(yamlPath, []byte("resources: []"), 0600))
	assert.Equal(t, yamlPath, findKustomizationFile(tmpDir))

	// Clean up and test kustomization.yml
	require.NoError(t, os.Remove(yamlPath))
	ymlPath := filepath.Join(tmpDir, "kustomization.yml")
	require.NoError(t, os.WriteFile(ymlPath, []byte("resources: []"), 0600))
	assert.Equal(t, ymlPath, findKustomizationFile(tmpDir))

	// Clean up and test Kustomization
	require.NoError(t, os.Remove(ymlPath))
	kustPath := filepath.Join(tmpDir, "Kustomization")
	require.NoError(t, os.WriteFile(kustPath, []byte("resources: []"), 0600))
	assert.Equal(t, kustPath, findKustomizationFile(tmpDir))
}

func TestMergePatchOps(t *testing.T) {
	existing := []kustomizePatchOp{
		{
			Op:    "add",
			Path:  "/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem",
			Value: true,
		},
	}

	newOps := []kustomizePatchOp{
		{
			Op:    "add",
			Path:  "/spec/template/spec/containers/0/securityContext/allowPrivilegeEscalation",
			Value: false,
		},
	}

	// 1. Merge distinct ops
	merged := mergePatchOps(existing, newOps)
	require.Len(t, merged, 2)
	assert.Equal(t, "/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem", merged[0].Path)
	assert.Equal(t, "/spec/template/spec/containers/0/securityContext/allowPrivilegeEscalation", merged[1].Path)

	// 2. Overwrite op targeting the same path: keep "add" when new op is "replace"
	// so a fresh build starting from an untouched base still creates the missing field.
	updatedOp := []kustomizePatchOp{
		{
			Op:    "replace",
			Path:  "/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem",
			Value: false,
		},
	}
	mergedUpdate := mergePatchOps(merged, updatedOp)
	require.Len(t, mergedUpdate, 2)
	assert.Equal(t, false, mergedUpdate[0].Value)
	assert.Equal(t, "add", mergedUpdate[0].Op, "must keep add so field is created on fresh build")

	// 3. Overwriting an existing "replace" with another "replace" keeps "replace"
	replaceExisting := []kustomizePatchOp{
		{
			Op:    "replace",
			Path:  "/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem",
			Value: true,
		},
	}
	mergedReplace := mergePatchOps(replaceExisting, updatedOp)
	require.Len(t, mergedReplace, 1)
	assert.Equal(t, false, mergedReplace[0].Value)
	assert.Equal(t, "replace", mergedReplace[0].Op)

	// 4. Preserves "from" on RFC 6902 copy/move operations
	copyExisting := []kustomizePatchOp{
		{
			Op:   "copy",
			From: "/spec/template/spec/containers/0/securityContext",
			Path: "/spec/template/spec/containers/1/securityContext",
		},
	}
	mergedCopy := mergePatchOps(copyExisting, newOps)
	require.Len(t, mergedCopy, 2)
	assert.Equal(t, "/spec/template/spec/containers/0/securityContext", mergedCopy[0].From)

	// 5. Merge with empty existing
	mergedEmptyExisting := mergePatchOps(nil, newOps)
	require.Equal(t, newOps, mergedEmptyExisting)

	// 6. Merge with empty new
	mergedEmptyNew := mergePatchOps(existing, nil)
	require.Equal(t, existing, mergedEmptyNew)
}

func TestAddPatchToKustomizationYAML(t *testing.T) {
	initial := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
`
	target := kustomizeTarget{
		Group:     "apps",
		Version:   "v1",
		Kind:      "Deployment",
		Name:      "nginx",
		Namespace: "prod",
	}

	// First addition: creates patches section with group, version and namespace
	res1, err := addPatchToKustomizationYAML(initial, "patches/deploy-patch.yaml", target)
	require.NoError(t, err)
	assert.Contains(t, res1, "patches:")
	assert.Contains(t, res1, "path: patches/deploy-patch.yaml")
	assert.Contains(t, res1, "group: ^apps$")
	assert.Contains(t, res1, "version: v1")
	assert.Contains(t, res1, "kind: Deployment")
	assert.Contains(t, res1, "name: nginx")
	assert.Contains(t, res1, "namespace: prod")

	// Idempotency check: re-adding exact same patch does not duplicate
	res2, err := addPatchToKustomizationYAML(res1, "patches/deploy-patch.yaml", target)
	require.NoError(t, err)
	count := strings.Count(res2, "patches/deploy-patch.yaml")
	assert.Equal(t, 1, count, "patch path must not be duplicated")

	// Equivalent path check: ./patches/deploy-patch.yaml should be recognized as patches/deploy-patch.yaml
	resEquiv, err := addPatchToKustomizationYAML(res2, "./patches/deploy-patch.yaml", target)
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(resEquiv, "deploy-patch.yaml"), "equivalent path ./patches/... must not create duplicate entry")

	// Adding another patch for a resource with numeric/boolean names and regex meta
	target2 := kustomizeTarget{
		Kind: "Service",
		Name: "123",
	}
	res3, err := addPatchToKustomizationYAML(res2, "patches/svc-patch.yaml", target2)
	require.NoError(t, err)
	assert.Contains(t, res3, "patches/deploy-patch.yaml")
	assert.Contains(t, res3, "patches/svc-patch.yaml")
	assert.Contains(t, res3, "name: \"123\"")

	// Adding another patch with regex characters in name
	target3 := kustomizeTarget{
		Kind: "ConfigMap",
		Name: "my-app.v1+config",
	}
	res4, err := addPatchToKustomizationYAML(res3, "patches/cm-patch.yaml", target3)
	require.NoError(t, err)
	assert.Contains(t, res4, `my-app\.v1\+config`)
}

func TestAddPatchToKustomizationYAML_MergeKeys(t *testing.T) {
	initial := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
common_patches: &common_patches
  patches:
    - path: patches/common.yaml
      target:
        kind: Deployment
<<: *common_patches
resources:
  - ../../base
`
	target := kustomizeTarget{
		Group:   "apps",
		Version: "v1",
		Kind:    "Deployment",
		Name:    "nginx",
	}
	res, err := addPatchToKustomizationYAML(initial, "patches/deploy.yaml", target)
	require.NoError(t, err)
	assert.Contains(t, res, "patches/common.yaml", "must preserve inherited patches from merge key")
	assert.Contains(t, res, "patches/deploy.yaml", "must append new patch")

	// Deduplication test: inherited sequence with ./patches/deploy.yaml should not be duplicated when adding patches/deploy.yaml
	equivInherited := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
common_patches: &common_patches
  patches:
    - path: ./patches/deploy.yaml
      target:
        kind: Deployment
<<: *common_patches
resources:
  - ../../base
`
	resDedupe, err := addPatchToKustomizationYAML(equivInherited, "patches/deploy.yaml", target)
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(resDedupe, "deploy.yaml"), "inherited equivalent patch must not be duplicated")
}

func TestAddPatchToKustomizationYAML_PatchOrderEffectiveness(t *testing.T) {
	initial := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
patches:
  - path: patches/deploy.yaml
    options:
      allowNameChange: true
    target:
      kind: Deployment
      name: nginx
  - path: patches/override.yaml
    target:
      kind: Deployment
      name: nginx
`
	target := kustomizeTarget{
		Kind: "Deployment",
		Name: "nginx",
	}
	// Re-running for deploy.yaml when a later patch override.yaml exists
	// must move deploy.yaml to the end so remediation remains effective.
	res, err := addPatchToKustomizationYAML(initial, "patches/deploy.yaml", target)
	require.NoError(t, err)
	idxDeploy := strings.Index(res, "patches/deploy.yaml")
	idxOverride := strings.Index(res, "patches/override.yaml")
	assert.Greater(t, idxDeploy, idxOverride, "remediation patch must be moved after override.yaml")
	assert.Contains(t, res, "allowNameChange: true", "must preserve custom fields like options intact when moving entry")
}

func TestAddPatchToKustomizationYAML_PreservesFormattingOutsideRegistration(t *testing.T) {
	initial := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

# Important comment header
resources:
    - ../../base
    - other.yaml

# Another comment
`
	target := kustomizeTarget{
		Group:   "apps",
		Version: "v1",
		Kind:    "Deployment",
		Name:    "nginx",
	}
	res, err := addPatchToKustomizationYAML(initial, "patches/deploy.yaml", target)
	require.NoError(t, err)
	assert.Contains(t, res, "    - ../../base", "must preserve 4-space indentation in resources")
	assert.Contains(t, res, "# Important comment header")
	assert.Contains(t, res, "# Another comment")
}

func TestResolveKustomizeOverlaySource(t *testing.T) {
	tmpDir := t.TempDir()
	baseDir := filepath.Join(tmpDir, "base")
	overlayDir := filepath.Join(tmpDir, "overlays", "prod")
	require.NoError(t, os.MkdirAll(baseDir, 0755))
	require.NoError(t, os.MkdirAll(overlayDir, 0755))

	kustFile := filepath.Join(overlayDir, "kustomization.yaml")
	require.NoError(t, os.WriteFile(kustFile, []byte("resources: [../../base]"), 0600))

	handler := &FixHandler{
		localBasePath: tmpDir,
		reportObj:     &reporthandlingv2.PostureReport{},
	}

	res := &reporthandling.Resource{
		Source: &reporthandling.Source{
			FileType:               reporthandling.SourceTypeKustomizeDirectory,
			KustomizeDirectoryName: overlayDir,
			Path:                   tmpDir,
			RelativePath:           "base/deployment.yaml",
		},
	}

	src := handler.resolveKustomizeOverlaySource(context.Background(), res, "base/deployment.yaml")
	assert.Empty(t, src.skipReason)
	assert.True(t, src.isKustomizeOverlay)
	assert.Equal(t, overlayDir, src.kustomizeOverlayDir)
	assert.Equal(t, kustFile, src.filePath)

	// Test escaping overlay directory (path traversal)
	escapingRes := &reporthandling.Resource{
		Source: &reporthandling.Source{
			FileType:               reporthandling.SourceTypeKustomizeDirectory,
			KustomizeDirectoryName: filepath.Join(tmpDir, "..", "escaped"),
			Path:                   tmpDir,
		},
	}
	srcEsc := handler.resolveKustomizeOverlaySource(context.Background(), escapingRes, "base/deployment.yaml")
	assert.NotEmpty(t, srcEsc.skipReason)
	assert.Contains(t, srcEsc.skipReason, "escapes scanned directory")
}

func TestApplyKustomizeOverlayChanges_EndToEnd(t *testing.T) {
	tmpDir := t.TempDir()
	baseDir := filepath.Join(tmpDir, "base")
	overlayDir := filepath.Join(tmpDir, "overlays", "prod")
	require.NoError(t, os.MkdirAll(baseDir, 0755))
	require.NoError(t, os.MkdirAll(overlayDir, 0755))

	baseDeployment := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: prod
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx
          securityContext:
            privileged: false
`
	baseKust := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml
`
	overlayKust := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
`
	baseDeployPath := filepath.Join(baseDir, "deployment.yaml")
	baseKustPath := filepath.Join(baseDir, "kustomization.yaml")
	overlayKustPath := filepath.Join(overlayDir, "kustomization.yaml")

	require.NoError(t, os.WriteFile(baseDeployPath, []byte(baseDeployment), 0600))
	require.NoError(t, os.WriteFile(baseKustPath, []byte(baseKust), 0600))
	require.NoError(t, os.WriteFile(overlayKustPath, []byte(overlayKust), 0600))

	res := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":      "my-app",
				"namespace": "prod",
			},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "app",
								"image": "nginx",
								"securityContext": map[string]interface{}{
									"privileged": false,
								},
							},
						},
					},
				},
			},
		},
		Source: &reporthandling.Source{
			FileType:               reporthandling.SourceTypeKustomizeDirectory,
			KustomizeDirectoryName: overlayDir,
			Path:                   tmpDir,
			RelativePath:           "base/deployment.yaml",
		},
	}

	fixes := []ResourceFixInfo{
		{
			Resource:            res,
			isKustomizeOverlay:  true,
			kustomizeOverlayDir: overlayDir,
			FilePath:            overlayKustPath,
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem": {
					Path:  "spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem",
					Value: "true",
				},
			},
		},
	}

	handler := &FixHandler{
		localBasePath: tmpDir,
		reportObj:     &reporthandlingv2.PostureReport{},
	}

	// Apply overlay changes via ApplyChanges
	count, errs := handler.ApplyChanges(context.Background(), fixes)
	require.Empty(t, errs)
	assert.Equal(t, 1, count)

	// 1. Check that base deployment is 100% UNTOUCHED
	readBase, err := os.ReadFile(baseDeployPath)
	require.NoError(t, err)
	assert.Equal(t, baseDeployment, string(readBase), "CRITICAL: base deployment must not be modified!")

	// 2. Check that base kustomization is 100% UNTOUCHED
	readBaseKust, err := os.ReadFile(baseKustPath)
	require.NoError(t, err)
	assert.Equal(t, baseKust, string(readBaseKust), "CRITICAL: base kustomization must not be modified!")

	// 3. Check that patches/ directory and patch file were created in overlay
	patchesDir := filepath.Join(overlayDir, "patches")
	require.DirExists(t, patchesDir)

	entries, err := os.ReadDir(patchesDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Contains(t, entries[0].Name(), "Deployment-")
	assert.Contains(t, entries[0].Name(), "my-app-")
	assert.True(t, strings.HasSuffix(entries[0].Name(), ".yaml"))

	patchContent, err := os.ReadFile(filepath.Join(patchesDir, entries[0].Name()))
	require.NoError(t, err)
	assert.Contains(t, string(patchContent), "/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem")

	// 4. Check that overlay kustomization.yaml was updated with the patch
	updatedOverlayKust, err := os.ReadFile(overlayKustPath)
	require.NoError(t, err)
	assert.Contains(t, string(updatedOverlayKust), "patches:")
	assert.Contains(t, string(updatedOverlayKust), "patches/"+entries[0].Name())
	assert.Contains(t, string(updatedOverlayKust), "kind: Deployment")
	assert.Contains(t, string(updatedOverlayKust), "name: my-app")
	assert.Contains(t, string(updatedOverlayKust), "namespace: prod")

	// 5. Test with real Kustomize engine (krusty)
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	resMap, err := k.Run(filesys.MakeFsOnDisk(), overlayDir)
	require.NoError(t, err, "kustomize build on overlay must succeed")

	outYAML, err := resMap.AsYaml()
	require.NoError(t, err)

	var builtPod struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Name            string `yaml:"name"`
						SecurityContext struct {
							Privileged             bool `yaml:"privileged"`
							ReadOnlyRootFilesystem bool `yaml:"readOnlyRootFilesystem"`
						} `yaml:"securityContext"`
					} `yaml:"containers"`
				} `yaml:"spec"`
			} `yaml:"template"`
		} `yaml:"spec"`
	}
	require.NoError(t, yaml.Unmarshal(outYAML, &builtPod))
	require.Len(t, builtPod.Spec.Template.Spec.Containers, 1)
	assert.False(t, builtPod.Spec.Template.Spec.Containers[0].SecurityContext.Privileged)
	assert.True(t, builtPod.Spec.Template.Spec.Containers[0].SecurityContext.ReadOnlyRootFilesystem,
		"Rendered container must have readOnlyRootFilesystem=true applied by overlay patch")
}

func TestApplyKustomizeOverlay_ReRunMerging(t *testing.T) {
	tmpDir := t.TempDir()
	baseDir := filepath.Join(tmpDir, "base")
	overlayDir := filepath.Join(tmpDir, "overlays", "prod")
	require.NoError(t, os.MkdirAll(baseDir, 0755))
	require.NoError(t, os.MkdirAll(overlayDir, 0755))

	baseDeployment := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: prod
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx
`
	baseKust := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml
`
	overlayKust := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
`
	require.NoError(t, os.WriteFile(filepath.Join(baseDir, "deployment.yaml"), []byte(baseDeployment), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(baseDir, "kustomization.yaml"), []byte(baseKust), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(overlayKust), 0600))

	res := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name": "my-app",
			},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "app",
								"image": "nginx",
							},
						},
					},
				},
			},
		},
		Source: &reporthandling.Source{
			FileType:               reporthandling.SourceTypeKustomizeDirectory,
			KustomizeDirectoryName: overlayDir,
			Path:                   tmpDir,
			RelativePath:           "base/deployment.yaml",
		},
	}

	handler := &FixHandler{
		localBasePath: tmpDir,
		reportObj:     &reporthandlingv2.PostureReport{},
	}

	// First run: Control A fix
	fixesA := []ResourceFixInfo{
		{
			Resource:            res,
			isKustomizeOverlay:  true,
			kustomizeOverlayDir: overlayDir,
			FilePath:            filepath.Join(overlayDir, "kustomization.yaml"),
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem": {
					Path:  "spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem",
					Value: "true",
				},
			},
		},
	}
	count, errs := handler.ApplyChanges(context.Background(), fixesA)
	require.Empty(t, errs)
	assert.Equal(t, 1, count)

	// Second run: Control B fix for the same resource
	fixesB := []ResourceFixInfo{
		{
			Resource:            res,
			isKustomizeOverlay:  true,
			kustomizeOverlayDir: overlayDir,
			FilePath:            filepath.Join(overlayDir, "kustomization.yaml"),
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation": {
					Path:  "spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation",
					Value: "false",
				},
			},
		},
	}
	count, errs = handler.ApplyChanges(context.Background(), fixesB)
	require.Empty(t, errs)
	assert.Equal(t, 1, count)

	// Verify the patch file still has ONLY 1 patch file and contains BOTH operations!
	patchesDir := filepath.Join(overlayDir, "patches")
	entries, err := os.ReadDir(patchesDir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "Must not create duplicate patch files for same resource")

	patchBytes, err := os.ReadFile(filepath.Join(patchesDir, entries[0].Name()))
	require.NoError(t, err)
	patchContent := string(patchBytes)
	assert.Contains(t, patchContent, "readOnlyRootFilesystem", "Control A operation must be preserved")
	assert.Contains(t, patchContent, "allowPrivilegeEscalation", "Control B operation must be merged in")

	// Verify Kustomize krusty applies BOTH fixes
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	resMap, err := k.Run(filesys.MakeFsOnDisk(), overlayDir)
	require.NoError(t, err)

	outYAML, err := resMap.AsYaml()
	require.NoError(t, err)
	assert.Contains(t, string(outYAML), "readOnlyRootFilesystem: true")
	assert.Contains(t, string(outYAML), "allowPrivilegeEscalation: false")
}

func TestApplyKustomizeOverlay_OutputDir(t *testing.T) {
	tmpDir := t.TempDir()
	destDir := t.TempDir()

	baseDir := filepath.Join(tmpDir, "base")
	overlayDir := filepath.Join(tmpDir, "overlays", "prod")
	require.NoError(t, os.MkdirAll(baseDir, 0755))
	require.NoError(t, os.MkdirAll(overlayDir, 0755))

	baseDeployment := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: prod
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx
`
	baseKust := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml
`
	overlayKust := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
`
	baseDeployPath := filepath.Join(baseDir, "deployment.yaml")
	baseKustPath := filepath.Join(baseDir, "kustomization.yaml")
	overlayKustPath := filepath.Join(overlayDir, "kustomization.yaml")

	require.NoError(t, os.WriteFile(baseDeployPath, []byte(baseDeployment), 0600))
	require.NoError(t, os.WriteFile(baseKustPath, []byte(baseKust), 0600))
	require.NoError(t, os.WriteFile(overlayKustPath, []byte(overlayKust), 0600))

	res := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name": "my-app",
			},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "app",
								"image": "nginx",
							},
						},
					},
				},
			},
		},
		Source: &reporthandling.Source{
			FileType:               reporthandling.SourceTypeKustomizeDirectory,
			KustomizeDirectoryName: overlayDir,
			Path:                   tmpDir,
			RelativePath:           "base/deployment.yaml",
		},
	}

	fixes := []ResourceFixInfo{
		{
			Resource:            res,
			isKustomizeOverlay:  true,
			kustomizeOverlayDir: overlayDir,
			FilePath:            overlayKustPath,
			relativePath:        filepath.Join("overlays", "prod", "kustomization.yaml"),
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem": {
					Path:  "spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem",
					Value: "true",
				},
			},
		},
	}

	handler := &FixHandler{
		localBasePath: tmpDir,
		reportObj:     &reporthandlingv2.PostureReport{},
		fixInfo: &metav1.FixInfo{
			OutputDir: destDir,
		},
	}

	count, errs := handler.ApplyChanges(context.Background(), fixes)
	require.Empty(t, errs)
	assert.Equal(t, 1, count)

	// 1. Scanned repo must be completely UNTOUCHED
	origOverlayContent, err := os.ReadFile(overlayKustPath)
	require.NoError(t, err)
	assert.Equal(t, overlayKust, string(origOverlayContent), "Original kustomization.yaml must not be changed")
	assert.NoDirExists(t, filepath.Join(overlayDir, "patches"), "Original overlay must not have patches directory created")

	// 2. Dest dir must contain the fixed kustomization.yaml and patches directory
	destKustPath := filepath.Join(destDir, "overlays", "prod", "kustomization.yaml")
	require.FileExists(t, destKustPath)
	destKustContent, err := os.ReadFile(destKustPath)
	require.NoError(t, err)
	assert.Contains(t, string(destKustContent), "patches:")

	destPatchesDir := filepath.Join(destDir, "overlays", "prod", "patches")
	require.DirExists(t, destPatchesDir)
	entries, err := os.ReadDir(destPatchesDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	destPatchBytes, err := os.ReadFile(filepath.Join(destPatchesDir, entries[0].Name()))
	require.NoError(t, err)
	assert.Contains(t, string(destPatchBytes), "readOnlyRootFilesystem")
}

func TestApplyKustomizeOverlay_NonRegularFile(t *testing.T) {
	tmpDir := t.TempDir()
	// Create kustomization.yaml as a directory, not a regular file
	kustDir := filepath.Join(tmpDir, "kustomization.yaml")
	require.NoError(t, os.MkdirAll(kustDir, 0755))

	_, err := planOverlayChanges(tmpDir, []ResourceFixInfo{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrManifestNotRegular)
}

func TestBuildPatch_KustomizeOverlay(t *testing.T) {
	tmpDir := t.TempDir()
	baseDir := filepath.Join(tmpDir, "base")
	overlayDir := filepath.Join(tmpDir, "overlays", "prod")
	require.NoError(t, os.MkdirAll(baseDir, 0755))
	require.NoError(t, os.MkdirAll(overlayDir, 0755))

	baseDeployment := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: prod
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx
`
	baseKust := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml
`
	overlayKust := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
`
	overlayKustPath := filepath.Join(overlayDir, "kustomization.yaml")
	require.NoError(t, os.WriteFile(filepath.Join(baseDir, "deployment.yaml"), []byte(baseDeployment), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(baseDir, "kustomization.yaml"), []byte(baseKust), 0600))
	require.NoError(t, os.WriteFile(overlayKustPath, []byte(overlayKust), 0600))

	res := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name": "my-app",
			},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "app",
								"image": "nginx",
							},
						},
					},
				},
			},
		},
		Source: &reporthandling.Source{
			FileType:               reporthandling.SourceTypeKustomizeDirectory,
			KustomizeDirectoryName: overlayDir,
			Path:                   tmpDir,
			RelativePath:           "base/deployment.yaml",
		},
	}

	handler := &FixHandler{
		localBasePath: tmpDir,
		reportObj:     &reporthandlingv2.PostureReport{},
	}

	fixes := []ResourceFixInfo{
		{
			Resource:            res,
			isKustomizeOverlay:  true,
			kustomizeOverlayDir: overlayDir,
			FilePath:            overlayKustPath,
			relativePath:        filepath.Join("overlays", "prod", "kustomization.yaml"),
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem": {
					Path:  "spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem",
					Value: "true",
				},
			},
		},
	}

	patchResult, err := handler.BuildPatch(context.Background(), fixes)
	require.NoError(t, err)
	require.NotNil(t, patchResult)
	assert.NotEmpty(t, patchResult.Patch)
	assert.Contains(t, patchResult.Patch, "patches:")
	assert.Contains(t, patchResult.Patch, "readOnlyRootFilesystem")
	// Verify git apply compatibility: new patch file must have "--- /dev/null"
	assert.Contains(t, patchResult.Patch, "--- /dev/null\n", "New patch file must have --- /dev/null header")
	assert.Equal(t, 2, patchResult.Files)

	// Verify the patch actually applies cleanly using git apply
	cmd := exec.Command("git", "apply", "--whitespace=nowarn", "-")
	cmd.Dir = tmpDir
	cmd.Stdin = strings.NewReader(patchResult.Patch)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git apply refused the patch: %s\nPatch:\n%s", out, patchResult.Patch)

	// Verify the patch file was created by git apply and Kustomize krusty builds cleanly
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	resMap, err := k.Run(filesys.MakeFsOnDisk(), overlayDir)
	require.NoError(t, err, "kustomize build on overlay after git apply must succeed")
	outYAML, err := resMap.AsYaml()
	require.NoError(t, err)
	assert.Contains(t, string(outYAML), "readOnlyRootFilesystem: true")
}

func TestBuildOverlayPatch_IndexedAdditionsOrder(t *testing.T) {
	res := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name": "app-with-args",
			},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name": "nginx",
								"args": []interface{}{},
							},
						},
					},
				},
			},
		},
	}

	fixes := ResourceFixInfo{
		Resource: res,
		YamlExpressions: map[string]armotypes.FixPath{
			"spec.template.spec.containers[0].args[1]": {
				Path:  "spec.template.spec.containers[0].args[1]",
				Value: "--arg-one",
			},
			"spec.template.spec.containers[0].args[0]": {
				Path:  "spec.template.spec.containers[0].args[0]",
				Value: "--arg-zero",
			},
			"spec.template.spec.containers[0].args[2]": {
				Path:  "spec.template.spec.containers[0].args[2]",
				Value: "--arg-two",
			},
		},
	}

	// Run multiple times to verify map iteration order never causes array gap errors
	for i := 0; i < 20; i++ {
		ops, err := buildOverlayPatchForResource(fixes)
		require.NoError(t, err, "must resolve indexed additions without array gap errors")
		require.Len(t, ops, 3)
		assert.Equal(t, "/spec/template/spec/containers/0/args/0", ops[0].Path)
		assert.Equal(t, "--arg-zero", ops[0].Value)
		assert.Equal(t, "/spec/template/spec/containers/0/args/1", ops[1].Path)
		assert.Equal(t, "--arg-one", ops[1].Value)
		assert.Equal(t, "/spec/template/spec/containers/0/args/2", ops[2].Path)
		assert.Equal(t, "--arg-two", ops[2].Value)
	}
}

func TestApplyChanges_OverlayReportsNoUpdateWhenPlanWritesNothing(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlays", "prod")
	require.NoError(t, os.MkdirAll(overlayDir, 0755))
	kustPath := filepath.Join(overlayDir, "kustomization.yaml")
	require.NoError(t, os.WriteFile(kustPath, []byte("resources: []\n"), 0600))

	res := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]interface{}{"name": "my-app"},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{},
					},
				},
			},
		},
	}

	// Wildcard expression that matches nothing in empty containers: []
	fixes := []ResourceFixInfo{
		{
			Resource:            res,
			isKustomizeOverlay:  true,
			kustomizeOverlayDir: overlayDir,
			FilePath:            kustPath,
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.template.spec.containers[*].securityContext.privileged": {
					Path:  "spec.template.spec.containers[*].securityContext.privileged",
					Value: "false",
				},
			},
		},
	}

	handler := &FixHandler{
		localBasePath: tmpDir,
		reportObj:     &reporthandlingv2.PostureReport{},
	}

	count, errs := handler.ApplyChanges(context.Background(), fixes)
	require.Empty(t, errs)
	assert.Equal(t, 0, count, "Must report 0 updated files when no ops were generated")
}

func TestAddPatchToKustomizationYAML_CaseInsensitive(t *testing.T) {
	initial := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
Patches:
  - path: patches/existing.yaml
    target:
      kind: Deployment
      name: my-app
`
	target := kustomizeTarget{
		Kind: "Deployment",
		Name: "sidecar",
	}

	// Should append to existing "Patches:" without creating duplicate "patches:"
	res, err := addPatchToKustomizationYAML(initial, "patches/new-patch.yaml", target)
	require.NoError(t, err)
	assert.Contains(t, res, "Patches:")
	assert.NotContains(t, res, "\npatches:")
	assert.Contains(t, res, "patches/existing.yaml")
	assert.Contains(t, res, "patches/new-patch.yaml")

	// Multiple case-insensitive patches keys should be rejected
	multiPatches := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
patches: []
Patches: []
`
	_, err = addPatchToKustomizationYAML(multiPatches, "patches/p.yaml", target)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "multiple case-insensitive 'patches' fields")

	// Non-sequence patches field should be rejected
	invalidPatches := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
patches: "not-a-sequence"
`
	_, err = addPatchToKustomizationYAML(invalidPatches, "patches/p.yaml", target)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "'patches' field in kustomization yaml is not a sequence")
}

func TestApplyChanges_Overlay_OutputDir_RejectsOverwritingScannedManifest(t *testing.T) {
	tmpDir := t.TempDir()
	scanDir := filepath.Join(tmpDir, "scan")
	overlayDir := filepath.Join(scanDir, "overlays", "prod")
	require.NoError(t, os.MkdirAll(overlayDir, 0755))
	kustPath := filepath.Join(overlayDir, "kustomization.yaml")
	require.NoError(t, os.WriteFile(kustPath, []byte("resources: []\n"), 0600))

	res := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":      "my-app",
				"namespace": "prod",
			},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name": "app",
							},
						},
					},
				},
			},
		},
	}

	fixes := []ResourceFixInfo{
		{
			Resource:            res,
			isKustomizeOverlay:  true,
			kustomizeOverlayDir: overlayDir,
			FilePath:            kustPath,
			relativePath:        filepath.Join("overlays", "prod", "kustomization.yaml"),
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.template.spec.containers[0].securityContext.privileged": {
					Path:  "spec.template.spec.containers[0].securityContext.privileged",
					Value: "false",
				},
			},
		},
	}

	patchName := overlayPatchFileName(res)
	// Output directory overlaps a scanned manifest location
	outDir := filepath.Join(tmpDir, "out")
	patchesDir := filepath.Join(outDir, "overlays", "prod", "patches")
	require.NoError(t, os.MkdirAll(patchesDir, 0755))
	collisionFile := filepath.Join(patchesDir, patchName)
	originalContent := "scanned manifest content\n"
	require.NoError(t, os.WriteFile(collisionFile, []byte(originalContent), 0600))

	// Include collisionFile among scanned resources so FixHandler knows it is a scanned manifest
	fixesWithScanned := append(fixes, ResourceFixInfo{
		FilePath:     collisionFile,
		relativePath: filepath.Join("overlays", "prod", "patches", patchName),
		Resource: &reporthandling.Resource{
			Object: map[string]interface{}{"kind": "ConfigMap"},
		},
	})

	handler := &FixHandler{
		localBasePath: scanDir,
		fixInfo: &metav1.FixInfo{
			OutputDir: outDir,
		},
		reportObj: &reporthandlingv2.PostureReport{},
	}

	count, errs := handler.ApplyChanges(context.Background(), fixesWithScanned)
	require.NotEmpty(t, errs, "must reject destination that overwrites scanned manifest")
	assert.Equal(t, 0, count, "must not write any files when pre-validation fails")
	assert.Contains(t, errs[0].Error(), "holds scanned manifests")
	assert.Contains(t, errs[0].Error(), patchName)

	// Ensure collision file was NOT overwritten
	contentAfter, err := os.ReadFile(collisionFile)
	require.NoError(t, err)
	assert.Equal(t, originalContent, string(contentAfter))
}

func TestAddPatchToKustomizationYAML_NullPatches(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{
			name: "empty scalar",
			content: `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
patches:
`,
		},
		{
			name: "null scalar",
			content: `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
patches: null
`,
		},
		{
			name: "tilde null scalar",
			content: `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
patches: ~
`,
		},
	}

	target := kustomizeTarget{
		Kind: "Deployment",
		Name: "my-app",
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := addPatchToKustomizationYAML(tc.content, "patches/patch.yaml", target)
			require.NoError(t, err)
			assert.Contains(t, res, "patches:")
			assert.Contains(t, res, "path: patches/patch.yaml")
			assert.Contains(t, res, "name: my-app")

			// Parse result to verify it is valid YAML and patches is a sequence
			var node yaml.Node
			require.NoError(t, yaml.Unmarshal([]byte(res), &node))
			doc := node.Content[0]
			var patchesNode *yaml.Node
			for i := 0; i < len(doc.Content)-1; i += 2 {
				if doc.Content[i].Value == "patches" {
					patchesNode = doc.Content[i+1]
					break
				}
			}
			require.NotNil(t, patchesNode)
			assert.Equal(t, yaml.SequenceNode, patchesNode.Kind)
			assert.Len(t, patchesNode.Content, 1)
		})
	}
}

func TestPlanOverlayChanges_UnreadablePatch(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlays", "prod")
	require.NoError(t, os.MkdirAll(overlayDir, 0755))

	kustPath := filepath.Join(overlayDir, "kustomization.yaml")
	require.NoError(t, os.WriteFile(kustPath, []byte("resources: []\n"), 0600))

	res := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name": "my-app",
			},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name": "app",
							},
						},
					},
				},
			},
		},
	}

	target := kustomizeTarget{Kind: "Deployment", Name: "my-app"}
	patchFileName := overlayPatchFileName(res, target)
	patchesDir := filepath.Join(overlayDir, "patches")
	require.NoError(t, os.MkdirAll(patchesDir, 0755))
	corruptPatchPath := filepath.Join(patchesDir, patchFileName)
	// Write corrupt YAML content that fails unmarshal
	require.NoError(t, os.WriteFile(corruptPatchPath, []byte("invalid: [yaml: unclosed"), 0600))

	fixes := []ResourceFixInfo{
		{
			Resource:            res,
			isKustomizeOverlay:  true,
			kustomizeOverlayDir: overlayDir,
			FilePath:            kustPath,
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.template.spec.containers[0].securityContext.privileged": {
					Path:  "spec.template.spec.containers[0].securityContext.privileged",
					Value: "false",
				},
			},
		},
	}

	_, err := planOverlayChanges(overlayDir, fixes)
	require.Error(t, err, "must return error for corrupt/unreadable existing patch")
	assert.Contains(t, err.Error(), "failed to parse existing patch")

	// Ensure corrupt file was NOT overwritten
	content, rErr := os.ReadFile(corruptPatchPath)
	require.NoError(t, rErr)
	assert.Equal(t, "invalid: [yaml: unclosed", string(content))
}

func TestApplyKustomizeOverlay_NamePrefixAndNamespace(t *testing.T) {
	tmpDir := t.TempDir()
	baseDir := filepath.Join(tmpDir, "base")
	overlayDir := filepath.Join(tmpDir, "overlays", "prod")
	require.NoError(t, os.MkdirAll(baseDir, 0755))
	require.NoError(t, os.MkdirAll(overlayDir, 0755))

	baseDeployment := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx
`
	baseKust := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml
`
	// Overlay sets namePrefix and namespace
	overlayKust := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namePrefix: prod-
namespace: prod
resources:
  - ../../base
`
	baseDeployPath := filepath.Join(baseDir, "deployment.yaml")
	baseKustPath := filepath.Join(baseDir, "kustomization.yaml")
	overlayKustPath := filepath.Join(overlayDir, "kustomization.yaml")

	require.NoError(t, os.WriteFile(baseDeployPath, []byte(baseDeployment), 0600))
	require.NoError(t, os.WriteFile(baseKustPath, []byte(baseKust), 0600))
	require.NoError(t, os.WriteFile(overlayKustPath, []byte(overlayKust), 0600))

	// Rendered resource has namePrefix and namespace applied (as Kubescape sees it after build)
	res := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":      "prod-my-app",
				"namespace": "prod",
			},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "app",
								"image": "nginx",
							},
						},
					},
				},
			},
		},
		Source: &reporthandling.Source{
			FileType:               reporthandling.SourceTypeKustomizeDirectory,
			KustomizeDirectoryName: overlayDir,
			Path:                   tmpDir,
			RelativePath:           "base/deployment.yaml",
		},
	}

	fixes := []ResourceFixInfo{
		{
			Resource:            res,
			isKustomizeOverlay:  true,
			kustomizeOverlayDir: overlayDir,
			FilePath:            overlayKustPath,
			reportedPath:        baseDeployPath,
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem": {
					Path:  "spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem",
					Value: "true",
				},
			},
		},
	}

	handler := &FixHandler{
		localBasePath: tmpDir,
		reportObj:     &reporthandlingv2.PostureReport{},
	}

	count, errs := handler.ApplyChanges(context.Background(), fixes)
	require.Empty(t, errs)
	assert.Equal(t, 1, count)

	// Check that target in kustomization.yaml resolved to pre-transformation name "my-app"
	// and does not match the injected overlay namespace at the patches stage
	updatedOverlayKust, err := os.ReadFile(overlayKustPath)
	require.NoError(t, err)
	var kustObj struct {
		Patches []struct {
			Path   string `yaml:"path"`
			Target struct {
				Kind      string `yaml:"kind"`
				Name      string `yaml:"name"`
				Namespace string `yaml:"namespace"`
			} `yaml:"target"`
		} `yaml:"patches"`
	}
	require.NoError(t, yaml.Unmarshal(updatedOverlayKust, &kustObj))
	require.Len(t, kustObj.Patches, 1)
	assert.Equal(t, "my-app", kustObj.Patches[0].Target.Name, "Target name must be resolved to 'my-app' at patches stage")
	assert.Equal(t, "Deployment", kustObj.Patches[0].Target.Kind)
	assert.Empty(t, kustObj.Patches[0].Target.Namespace, "Target selector must NOT constrain to overlay-injected namespace at patches stage")

	// Verify that krusty applies the patch cleanly and builds the remediated resource
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	resMap, err := k.Run(filesys.MakeFsOnDisk(), overlayDir)
	require.NoError(t, err, "kustomize build on overlay with namePrefix/namespace must succeed")

	outYAML, err := resMap.AsYaml()
	require.NoError(t, err)

	var built struct {
		Metadata struct {
			Name      string `yaml:"name"`
			Namespace string `yaml:"namespace"`
		} `yaml:"metadata"`
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Name            string `yaml:"name"`
						SecurityContext struct {
							ReadOnlyRootFilesystem bool `yaml:"readOnlyRootFilesystem"`
						} `yaml:"securityContext"`
					} `yaml:"containers"`
				} `yaml:"spec"`
			} `yaml:"template"`
		} `yaml:"spec"`
	}
	require.NoError(t, yaml.Unmarshal(outYAML, &built))
	assert.Equal(t, "prod-my-app", built.Metadata.Name)
	assert.Equal(t, "prod", built.Metadata.Namespace)
	require.Len(t, built.Spec.Template.Spec.Containers, 1)
	assert.True(t, built.Spec.Template.Spec.Containers[0].SecurityContext.ReadOnlyRootFilesystem,
		"Rendered container must have readOnlyRootFilesystem=true applied by overlay patch")
}

func TestApplyKustomizeOverlay_UnsupportedNamePrefix(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlays", "prod")
	require.NoError(t, os.MkdirAll(overlayDir, 0755))

	overlayKust := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namePrefix: prod-
resources: []
`
	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(overlayKust), 0600))

	// Resource name does NOT match the overlay's namePrefix
	res := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name": "other-app",
			},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{"name": "app"},
						},
					},
				},
			},
		},
	}

	fixes := []ResourceFixInfo{
		{
			Resource:            res,
			isKustomizeOverlay:  true,
			kustomizeOverlayDir: overlayDir,
			FilePath:            filepath.Join(overlayDir, "kustomization.yaml"),
			relativePath:        filepath.Join("overlays", "prod", "kustomization.yaml"),
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.template.spec.containers[0].securityContext.privileged": {
					Path:  "spec.template.spec.containers[0].securityContext.privileged",
					Value: "false",
				},
			},
		},
	}

	_, err := planOverlayChanges(overlayDir, fixes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported: cannot resolve resource identity at Kustomize patches stage")
}

func TestApplyKustomizeOverlay_TargetGroupAndVersionDifferentiation(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlays", "prod")
	require.NoError(t, os.MkdirAll(overlayDir, 0755))

	overlayKust := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: []
`
	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(overlayKust), 0600))

	res := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "networking.k8s.io/v1",
			"kind":       "Ingress",
			"metadata": map[string]interface{}{
				"name":      "my-ingress",
				"namespace": "prod",
			},
		},
	}

	fixes := []ResourceFixInfo{
		{
			Resource:            res,
			isKustomizeOverlay:  true,
			kustomizeOverlayDir: overlayDir,
			FilePath:            filepath.Join(overlayDir, "kustomization.yaml"),
			relativePath:        filepath.Join("overlays", "prod", "kustomization.yaml"),
			YamlExpressions: map[string]armotypes.FixPath{
				"metadata.annotations.ssl-redirect": {
					Path:  "metadata.annotations.ssl-redirect",
					Value: "true",
				},
			},
		},
	}

	plan, err := planOverlayChanges(overlayDir, fixes)
	require.NoError(t, err)
	require.Len(t, plan.patches, 1)
	assert.Equal(t, "networking.k8s.io", plan.patches[0].target.Group)
	assert.Equal(t, "v1", plan.patches[0].target.Version)
	assert.Contains(t, plan.updatedKust, `^networking\.k8s\.io$`)
	assert.Contains(t, plan.updatedKust, "version: v1")
}

func TestApplyKustomizeOverlay_ContainerIndexResolutionWithPatchesJson6902(t *testing.T) {
	tmpDir := t.TempDir()
	baseDir := filepath.Join(tmpDir, "base")
	overlayDir := filepath.Join(tmpDir, "overlays", "prod")
	require.NoError(t, os.MkdirAll(baseDir, 0755))
	require.NoError(t, os.MkdirAll(overlayDir, 0755))

	baseDeployment := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx
`
	baseKust := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml
`
	// Overlay inserts a sidecar container at index 0 via patchesJson6902
	overlayKust := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
patchesJson6902:
  - target:
      group: apps
      version: v1
      kind: Deployment
      name: my-app
    patch: |-
      - op: add
        path: /spec/template/spec/containers/0
        value:
          name: sidecar
          image: busybox
`
	baseDeployPath := filepath.Join(baseDir, "deployment.yaml")
	require.NoError(t, os.WriteFile(baseDeployPath, []byte(baseDeployment), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(baseDir, "kustomization.yaml"), []byte(baseKust), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(overlayKust), 0600))

	// Rendered resource: sidecar is at index 0, app is shifted to index 1
	res := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name": "my-app",
			},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "sidecar",
								"image": "busybox",
							},
							map[string]interface{}{
								"name":  "app",
								"image": "nginx",
							},
						},
					},
				},
			},
		},
		Source: &reporthandling.Source{
			FileType:               reporthandling.SourceTypeKustomizeDirectory,
			KustomizeDirectoryName: overlayDir,
			Path:                   tmpDir,
			RelativePath:           "base/deployment.yaml",
		},
	}

	// Fix targets the "app" container which is reported at rendered index 1
	fixes := []ResourceFixInfo{
		{
			Resource:            res,
			isKustomizeOverlay:  true,
			kustomizeOverlayDir: overlayDir,
			FilePath:            filepath.Join(overlayDir, "kustomization.yaml"),
			reportedPath:        baseDeployPath,
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.template.spec.containers[1].securityContext.readOnlyRootFilesystem": {
					Path:  "spec.template.spec.containers[1].securityContext.readOnlyRootFilesystem",
					Value: "true",
				},
			},
		},
	}

	handler := &FixHandler{
		localBasePath: tmpDir,
		reportObj:     &reporthandlingv2.PostureReport{},
	}

	count, errs := handler.ApplyChanges(context.Background(), fixes)
	require.Empty(t, errs)
	assert.Equal(t, 1, count)

	// Build with Kustomize krusty to verify final rendered containers
	k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
	m, err := k.Run(filesys.MakeFsOnDisk(), overlayDir)
	require.NoError(t, err)
	yamlBytes, err := m.AsYaml()
	require.NoError(t, err)

	var doc struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Name            string                 `yaml:"name"`
						SecurityContext map[string]interface{} `yaml:"securityContext"`
					} `yaml:"containers"`
				} `yaml:"spec"`
			} `yaml:"template"`
		} `yaml:"spec"`
	}
	require.NoError(t, yaml.Unmarshal(yamlBytes, &doc))
	require.Len(t, doc.Spec.Template.Spec.Containers, 2)

	// Sidecar at index 0 must be UNCHANGED (no readOnlyRootFilesystem)
	assert.Equal(t, "sidecar", doc.Spec.Template.Spec.Containers[0].Name)
	assert.Nil(t, doc.Spec.Template.Spec.Containers[0].SecurityContext)

	// App at index 1 must have received readOnlyRootFilesystem=true
	assert.Equal(t, "app", doc.Spec.Template.Spec.Containers[1].Name)
	require.NotNil(t, doc.Spec.Template.Spec.Containers[1].SecurityContext)
	assert.Equal(t, true, doc.Spec.Template.Spec.Containers[1].SecurityContext["readOnlyRootFilesystem"])

	// And base manifest on disk must be 100% untouched
	baseContentAfter, err := os.ReadFile(baseDeployPath)
	require.NoError(t, err)
	assert.Equal(t, baseDeployment, string(baseContentAfter))
}

func TestApplyKustomizeOverlay_InjectedContainerUnsupported(t *testing.T) {
	tmpDir := t.TempDir()
	baseDir := filepath.Join(tmpDir, "base")
	overlayDir := filepath.Join(tmpDir, "overlays", "prod")
	require.NoError(t, os.MkdirAll(baseDir, 0755))
	require.NoError(t, os.MkdirAll(overlayDir, 0755))

	baseDeployment := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx
`
	baseDeployPath := filepath.Join(baseDir, "deployment.yaml")
	require.NoError(t, os.WriteFile(baseDeployPath, []byte(baseDeployment), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte("resources: [../../base]"), 0600))

	// Rendered resource includes an injected sidecar that is NOT in the origin manifest
	res := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name": "my-app",
			},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "sidecar",
								"image": "busybox",
							},
						},
					},
				},
			},
		},
		Source: &reporthandling.Source{
			FileType:               reporthandling.SourceTypeKustomizeDirectory,
			KustomizeDirectoryName: overlayDir,
			Path:                   tmpDir,
			RelativePath:           "base/deployment.yaml",
		},
	}

	fixes := []ResourceFixInfo{
		{
			Resource:            res,
			isKustomizeOverlay:  true,
			kustomizeOverlayDir: overlayDir,
			FilePath:            filepath.Join(overlayDir, "kustomization.yaml"),
			reportedPath:        baseDeployPath,
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem": {
					Path:  "spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem",
					Value: "true",
				},
			},
		},
	}

	_, err := planOverlayChanges(overlayDir, fixes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported: cannot resolve container index for container \"sidecar\"")
}

func TestApplyKustomizeOverlay_PrecedingPatchesModifyContainersUnsupported(t *testing.T) {
	tmpDir := t.TempDir()
	baseDir := filepath.Join(tmpDir, "base")
	overlayDir := filepath.Join(tmpDir, "overlays", "prod")
	require.NoError(t, os.MkdirAll(baseDir, 0755))
	require.NoError(t, os.MkdirAll(overlayDir, 0755))

	baseDeployment := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx
`
	baseDeployPath := filepath.Join(baseDir, "deployment.yaml")
	require.NoError(t, os.WriteFile(baseDeployPath, []byte(baseDeployment), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(baseDir, "kustomization.yaml"), []byte("resources: [deployment.yaml]"), 0600))

	// Overlay has an existing patch in patches: that inserts a sidecar before remediation
	overlayKust := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
patches:
  - target:
      kind: Deployment
      name: my-app
    patch: |-
      - op: add
        path: /spec/template/spec/containers/0
        value:
          name: sidecar
          image: busybox
`
	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(overlayKust), 0600))

	// Rendered resource: sidecar is at 0, app is at 1
	res := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name": "my-app",
			},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "sidecar",
								"image": "busybox",
							},
							map[string]interface{}{
								"name":  "app",
								"image": "nginx",
							},
						},
					},
				},
			},
		},
		Source: &reporthandling.Source{
			FileType:               reporthandling.SourceTypeKustomizeDirectory,
			KustomizeDirectoryName: overlayDir,
			Path:                   tmpDir,
			RelativePath:           "base/deployment.yaml",
		},
	}

	fixes := []ResourceFixInfo{
		{
			Resource:            res,
			isKustomizeOverlay:  true,
			kustomizeOverlayDir: overlayDir,
			FilePath:            filepath.Join(overlayDir, "kustomization.yaml"),
			reportedPath:        baseDeployPath,
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.template.spec.containers[1].securityContext.readOnlyRootFilesystem": {
					Path:  "spec.template.spec.containers[1].securityContext.readOnlyRootFilesystem",
					Value: "true",
				},
			},
		},
	}

	_, err := planOverlayChanges(overlayDir, fixes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "preceding patches modify resource container layout before remediation")
}

func TestApplyKustomizeOverlay_DestinationConflictWithOrdinaryOutput(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlays", "prod")
	outDir := filepath.Join(tmpDir, "out")
	require.NoError(t, os.MkdirAll(overlayDir, 0755))
	require.NoError(t, os.MkdirAll(outDir, 0755))

	kustContent := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: []
`
	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(kustContent), 0600))

	res := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name": "my-app",
			},
		},
	}
	patchName := overlayPatchFileName(res)
	ordinaryFile := filepath.Join(tmpDir, "manifests", "ordinary.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(ordinaryFile), 0755))
	require.NoError(t, os.WriteFile(ordinaryFile, []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: my-cm\n"), 0600))

	fixes := []ResourceFixInfo{
		{
			Resource:            res,
			isKustomizeOverlay:  true,
			kustomizeOverlayDir: overlayDir,
			FilePath:            filepath.Join(overlayDir, "kustomization.yaml"),
			relativePath:        filepath.Join("overlays", "prod", "kustomization.yaml"),
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.replicas": {
					Path:  "spec.replicas",
					Value: "2",
				},
			},
		},
		{
			FilePath:     ordinaryFile,
			relativePath: filepath.Join("overlays", "prod", "patches", patchName),
			Resource: &reporthandling.Resource{
				Object: map[string]interface{}{"kind": "ConfigMap"},
			},
			YamlExpressions: map[string]armotypes.FixPath{
				"metadata.name": {Path: "metadata.name", Value: "conflict"},
			},
		},
	}

	handler := &FixHandler{
		localBasePath: tmpDir,
		fixInfo: &metav1.FixInfo{
			OutputDir: outDir,
		},
		reportObj: &reporthandlingv2.PostureReport{},
	}

	count, errs := handler.ApplyChanges(context.Background(), fixes)
	require.NotEmpty(t, errs)
	assert.Equal(t, 0, count)
	assert.Contains(t, errs[0].Error(), "conflict: overlay patch destination")
}

func TestApplyKustomizeOverlay_DestinationDirectoryConflictWithOrdinaryOutput(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlays", "prod")
	outDir := filepath.Join(tmpDir, "out")
	require.NoError(t, os.MkdirAll(overlayDir, 0755))
	require.NoError(t, os.MkdirAll(outDir, 0755))

	kustContent := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: []
`
	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(kustContent), 0600))

	res := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name": "my-app",
			},
		},
	}
	patchName := overlayPatchFileName(res)
	ordinaryFile := filepath.Join(tmpDir, "manifests", "ordinary.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(ordinaryFile), 0755))
	require.NoError(t, os.WriteFile(ordinaryFile, []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: my-cm\n"), 0600))

	// Ordinary file's output destination would make patchName a directory: patches/<patchName>/child.yaml
	fixes := []ResourceFixInfo{
		{
			Resource:            res,
			isKustomizeOverlay:  true,
			kustomizeOverlayDir: overlayDir,
			FilePath:            filepath.Join(overlayDir, "kustomization.yaml"),
			relativePath:        filepath.Join("overlays", "prod", "kustomization.yaml"),
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.replicas": {
					Path:  "spec.replicas",
					Value: "2",
				},
			},
		},
		{
			FilePath:     ordinaryFile,
			relativePath: filepath.Join("overlays", "prod", "patches", patchName, "child.yaml"),
			Resource: &reporthandling.Resource{
				Object: map[string]interface{}{"kind": "ConfigMap"},
			},
			YamlExpressions: map[string]armotypes.FixPath{
				"metadata.name": {Path: "metadata.name", Value: "conflict"},
			},
		},
	}

	handler := &FixHandler{
		localBasePath: tmpDir,
		fixInfo: &metav1.FixInfo{
			OutputDir: outDir,
		},
		reportObj: &reporthandlingv2.PostureReport{},
	}

	count, errs := handler.ApplyChanges(context.Background(), fixes)
	require.NotEmpty(t, errs)
	assert.Equal(t, 0, count)
	assert.Contains(t, errs[0].Error(), "conflict: overlay patch destination")
}

func TestApplyKustomizeOverlay_ExportCopiesKustomizationWhenAlreadyRegistered(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlays", "prod")
	outDir := filepath.Join(tmpDir, "out")
	require.NoError(t, os.MkdirAll(overlayDir, 0755))

	res := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name": "my-app",
			},
		},
	}
	patchName := overlayPatchFileName(res)

	// Patch is ALREADY registered in kustomization.yaml
	initialKust := fmt.Sprintf(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: []
patches:
  - path: patches/%s
    target:
      group: apps
      version: v1
      kind: Deployment
      name: my-app
`, patchName)

	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(initialKust), 0600))
	require.NoError(t, os.MkdirAll(filepath.Join(overlayDir, "patches"), 0755))
	initialPatch := `- op: add
  path: /spec/replicas
  value: 1
`
	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "patches", patchName), []byte(initialPatch), 0600))

	fixes := []ResourceFixInfo{
		{
			Resource:            res,
			isKustomizeOverlay:  true,
			kustomizeOverlayDir: overlayDir,
			FilePath:            filepath.Join(overlayDir, "kustomization.yaml"),
			relativePath:        filepath.Join("overlays", "prod", "kustomization.yaml"),
			YamlExpressions: map[string]armotypes.FixPath{
				"spec.replicas": {
					Path:  "spec.replicas",
					Value: "3",
				},
			},
		},
	}

	handler := &FixHandler{
		localBasePath: tmpDir,
		fixInfo: &metav1.FixInfo{
			OutputDir: outDir,
		},
		reportObj: &reporthandlingv2.PostureReport{},
	}

	count, errs := handler.ApplyChanges(context.Background(), fixes)
	require.Empty(t, errs)
	assert.Equal(t, 1, count)

	// kustomization.yaml MUST be copied to outDir even though its content did not change
	exportedKust := filepath.Join(outDir, "overlays", "prod", "kustomization.yaml")
	require.FileExists(t, exportedKust, "kustomization.yaml must be exported even when patch was already registered")
}

func TestApplyKustomizeOverlay_ZeroWritesReportsZeroCount(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlays", "prod")
	require.NoError(t, os.MkdirAll(overlayDir, 0755))

	overlayKust := `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: []
`
	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(overlayKust), 0600))

	res := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]interface{}{"name": "my-app"},
		},
	}

	fixes := []ResourceFixInfo{
		{
			Resource:            res,
			isKustomizeOverlay:  true,
			kustomizeOverlayDir: overlayDir,
			FilePath:            filepath.Join(overlayDir, "kustomization.yaml"),
			YamlExpressions:     map[string]armotypes.FixPath{}, // No operations
		},
	}

	handler := &FixHandler{
		localBasePath: tmpDir,
		reportObj:     &reporthandlingv2.PostureReport{},
	}

	count, errs := handler.ApplyChanges(context.Background(), fixes)
	require.Empty(t, errs)
	assert.Equal(t, 0, count, "zero-write plan must report 0 updated files")
}

func TestApplyKustomizeOverlay_SourceRootContainment(t *testing.T) {
	workspace := t.TempDir()
	outside := t.TempDir()

	overlayDir := filepath.Join(outside, "overlays", "prod")
	require.NoError(t, os.MkdirAll(overlayDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte("resources: []"), 0600))

	root, err := os.OpenRoot(workspace)
	require.NoError(t, err)
	defer root.Close()

	_, err = planOverlayChanges(overlayDir, []ResourceFixInfo{}, root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "outside source root")
}

func TestReadPatchContent_OutsideSourceRoot(t *testing.T) {
	workspace := t.TempDir()
	outside := t.TempDir()

	outsidePatch := filepath.Join(outside, "patch.yaml")
	require.NoError(t, os.WriteFile(outsidePatch, []byte("containers: []"), 0600))

	root, err := os.OpenRoot(workspace)
	require.NoError(t, err)
	defer root.Close()

	// When sourceRoot is provided, external patch path must return empty and not be opened
	content := readPatchContent(outsidePatch, workspace, root)
	assert.Empty(t, content)

	// When sourceRoot is nil, fallback opens the path
	contentNoRoot := readPatchContent(outsidePatch, workspace, nil)
	assert.Equal(t, "containers: []", contentNoRoot)
}

func TestFormatYAMLPath_QuotesNonBareKeys(t *testing.T) {
	parts := []yamlPathPart{
		{key: "spec"},
		{key: "containers"},
		{sequence: true, index: 1},
		{key: "env"},
		{key: "app:config key"},
		{key: "sub.field"},
	}
	got := formatYAMLPath(parts)
	assert.Equal(t, `spec.containers[1].env."app:config key"."sub.field"`, got)
}

func TestRemapContainerFixPath_UnreadableOriginWithContainerPatchesUnsupported(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlays", "prod")
	require.NoError(t, os.MkdirAll(overlayDir, 0755))

	meta := kustomizationMeta{
		PatchesJson6902: []interface{}{
			map[string]interface{}{
				"target": map[string]interface{}{
					"kind": "Deployment",
					"name": "my-app",
				},
				"patch": "- op: add\n  path: /spec/template/spec/containers/0\n  value:\n    name: sidecar\n",
			},
		},
	}

	renderedObj := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]interface{}{"name": "my-app"},
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{"name": "app"},
					},
				},
			},
		},
	}

	fp := armotypes.FixPath{
		Path:  "spec.template.spec.containers[0].securityContext.runAsNonRoot",
		Value: "true",
	}

	_, err := remapContainerFixPath(renderedObj, nil, fp, meta, "", overlayDir, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "origin manifest is unreadable")
}
