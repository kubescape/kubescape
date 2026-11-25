package fixhandler

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

// Two resources can share a kind, name and namespace in different API groups
// (a custom resource named like a built-in one). The overlay patch must target
// only the API group and version of the resource that was fixed: a target
// without them selects both, and Kustomize patches the other one too.
func TestApplyKustomizeOverlayChanges_TargetsOnlyTheFixedAPIGroupVersion(t *testing.T) {
	tmpDir := t.TempDir()
	baseDir := filepath.Join(tmpDir, "base")
	overlayDir := filepath.Join(tmpDir, "overlays", "prod")
	require.NoError(t, os.MkdirAll(baseDir, 0o755))
	require.NoError(t, os.MkdirAll(overlayDir, 0o755))

	workload := func(apiVersion string) string {
		return `apiVersion: ` + apiVersion + `
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
	}
	require.NoError(t, os.WriteFile(filepath.Join(baseDir, "apps.yaml"), []byte(workload("apps/v1")), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(baseDir, "custom.yaml"), []byte(workload("example.com/v1")), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(baseDir, "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - apps.yaml
  - custom.yaml
`), 0o600))
	overlayKustPath := filepath.Join(overlayDir, "kustomization.yaml")
	require.NoError(t, os.WriteFile(overlayKustPath, []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
`), 0o600))

	res := &reporthandling.Resource{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]interface{}{"name": "my-app", "namespace": "prod"},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{"name": "app", "image": "nginx"},
						},
					},
				},
			},
		},
		Source: &reporthandling.Source{
			FileType:               reporthandling.SourceTypeKustomizeDirectory,
			KustomizeDirectoryName: overlayDir,
			Path:                   tmpDir,
			RelativePath:           "base/apps.yaml",
		},
	}
	fixPath := "spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem"
	fixes := []ResourceFixInfo{{
		Resource:            res,
		isKustomizeOverlay:  true,
		kustomizeOverlayDir: overlayDir,
		FilePath:            overlayKustPath,
		YamlExpressions:     map[string]armotypes.FixPath{fixPath: {Path: fixPath, Value: "true"}},
	}}
	handler := &FixHandler{localBasePath: tmpDir, reportObj: &reporthandlingv2.PostureReport{}}
	count, errs := handler.ApplyChanges(context.Background(), fixes)
	require.Empty(t, errs)
	require.Equal(t, 1, count)

	kust, err := os.ReadFile(overlayKustPath)
	require.NoError(t, err)
	assert.Contains(t, string(kust), "group: apps", "the patch target names the API group")
	assert.Contains(t, string(kust), "version: v1", "and the version")

	resMap, err := krusty.MakeKustomizer(krusty.MakeDefaultOptions()).Run(filesys.MakeFsOnDisk(), overlayDir)
	require.NoError(t, err, "kustomize build on the overlay must succeed")
	readOnly := map[string]bool{}
	for _, r := range resMap.Resources() {
		out, err := r.AsYAML()
		require.NoError(t, err)
		var built struct {
			APIVersion string `yaml:"apiVersion"`
			Spec       struct {
				Template struct {
					Spec struct {
						Containers []struct {
							SecurityContext struct {
								ReadOnlyRootFilesystem bool `yaml:"readOnlyRootFilesystem"`
							} `yaml:"securityContext"`
						} `yaml:"containers"`
					} `yaml:"spec"`
				} `yaml:"template"`
			} `yaml:"spec"`
		}
		require.NoError(t, yaml.Unmarshal(out, &built))
		require.Len(t, built.Spec.Template.Spec.Containers, 1)
		readOnly[built.APIVersion] = built.Spec.Template.Spec.Containers[0].SecurityContext.ReadOnlyRootFilesystem
	}
	require.Len(t, readOnly, 2)
	assert.True(t, readOnly["apps/v1"], "the fixed resource is patched")
	assert.False(t, readOnly["example.com/v1"], "the resource of the same kind and name in another API group is not")
}
