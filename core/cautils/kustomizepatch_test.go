package cautils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMockKustomizeWorkload(kind, name string) workloadinterface.IMetadata {
	return localworkload.NewLocalWorkload(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       kind,
		"metadata": map[string]any{
			"name":      name,
			"namespace": "default",
		},
		"spec": map[string]any{
			"replicas": 3,
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "nginx",
							"image": "nginx:1.27",
						},
					},
				},
			},
		},
	})
}

func TestCleanFindingPath(t *testing.T) {
	assert.Equal(t, "", CleanFindingPath("@ base/deployment.yaml"))
	assert.Equal(t, "spec.replicas", CleanFindingPath("spec.replicas (current: 3)"))
	assert.Equal(t, "spec.containers[0].securityContext.privileged", CleanFindingPath("spec.containers[0].securityContext.privileged=false"))
	assert.Equal(t, "spec.containers[0].image", CleanFindingPath("spec.containers[0].image (app) (current: nginx:1.27)"))
	assert.Equal(t, "spec.containers[0].securityContext.privileged", CleanFindingPath("spec.containers[0].securityContext.privileged (line 42)"))
}

func TestTraceKustomizePatch_StrategicMergeFile(t *testing.T) {
	root := t.TempDir()
	overlayDir := filepath.Join(root, "overlay")
	require.NoError(t, os.MkdirAll(overlayDir, 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(`
resources:
- ../base
patches:
- path: patch.yaml
  target:
    kind: Deployment
    name: demo
`), 0o600))

	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "patch.yaml"), []byte(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  replicas: 3
`), 0o600))

	source := reporthandling.Source{
		Path:                   root,
		RelativePath:           "base/deployment.yaml",
		FileType:               reporthandling.SourceTypeKustomizeDirectory,
		KustomizeDirectoryName: overlayDir,
	}

	wl := newMockKustomizeWorkload("Deployment", "demo")

	// Matching path
	patchFile := TraceKustomizePatch(wl, []string{"spec.replicas (current: 3)"}, source)
	assert.Equal(t, "overlay/patch.yaml", patchFile)

	// Unrelated path
	unrelatedPatch := TraceKustomizePatch(wl, []string{"spec.template.spec.containers[0].securityContext.privileged=false"}, source)
	assert.Equal(t, "", unrelatedPatch)
}

func TestTraceKustomizePatch_Json6902File(t *testing.T) {
	root := t.TempDir()
	overlayDir := filepath.Join(root, "overlay")
	require.NoError(t, os.MkdirAll(overlayDir, 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(`
resources:
- ../base
patchesJson6902:
- target:
    kind: Deployment
    name: demo
  path: patch.json
`), 0o600))

	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "patch.json"), []byte(`[
  {"op": "replace", "path": "/spec/replicas", "value": 3}
]`), 0o600))

	source := reporthandling.Source{
		Path:                   root,
		RelativePath:           "base/deployment.yaml",
		FileType:               reporthandling.SourceTypeKustomizeDirectory,
		KustomizeDirectoryName: overlayDir,
	}

	wl := newMockKustomizeWorkload("Deployment", "demo")

	patchFile := TraceKustomizePatch(wl, []string{"spec.replicas (current: 3)"}, source)
	assert.Equal(t, "overlay/patch.json", patchFile)
}

func TestTraceKustomizePatch_InlinePatch(t *testing.T) {
	root := t.TempDir()
	overlayDir := filepath.Join(root, "overlay")
	require.NoError(t, os.MkdirAll(overlayDir, 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(`
resources:
- ../base
patches:
- patch: |-
    - op: replace
      path: /spec/replicas
      value: 3
  target:
    kind: Deployment
    name: demo
`), 0o600))

	source := reporthandling.Source{
		Path:                   root,
		RelativePath:           "base/deployment.yaml",
		FileType:               reporthandling.SourceTypeKustomizeDirectory,
		KustomizeDirectoryName: overlayDir,
	}

	wl := newMockKustomizeWorkload("Deployment", "demo")

	patchFile := TraceKustomizePatch(wl, []string{"spec.replicas (current: 3)"}, source)
	assert.Equal(t, "overlay/kustomization.yaml", patchFile)
}

func TestTraceKustomizePatch_NonKustomizeSource(t *testing.T) {
	source := reporthandling.Source{
		Path:         "repo",
		RelativePath: "deploy.yaml",
		FileType:     reporthandling.SourceTypeYaml,
	}
	wl := newMockKustomizeWorkload("Deployment", "demo")
	assert.Equal(t, "", TraceKustomizePatch(wl, []string{"spec.replicas"}, source))
}
