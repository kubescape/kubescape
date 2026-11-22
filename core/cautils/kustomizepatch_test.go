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
			"labels": map[string]any{
				"app": "demo",
			},
			"annotations": map[string]any{
				"tier": "backend",
			},
		},
		"spec": map[string]any{
			"replicas": 3,
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "sidecar",
							"image": "log-agent:1",
						},
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

func TestTraceKustomizePatch_EffectiveLastWriterWins(t *testing.T) {
	root := t.TempDir()
	overlayDir := filepath.Join(root, "overlay")
	require.NoError(t, os.MkdirAll(overlayDir, 0o755))

	// patch1 sets replicas, but patch2 later overrides it
	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(`
resources:
- ../base
patches:
- path: patch1.yaml
  target:
    kind: Deployment
    name: demo
- path: patch2.yaml
  target:
    kind: Deployment
    name: demo
`), 0o600))

	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "patch1.yaml"), []byte(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  replicas: 2
`), 0o600))

	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "patch2.yaml"), []byte(`
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

	// Last writer (patch2.yaml) must be reported
	patchFile := TraceKustomizePatch(wl, []string{"spec.replicas (current: 3)"}, source)
	assert.Equal(t, "overlay/patch2.yaml", patchFile)
}

func TestTraceKustomizePatch_LabelAndAnnotationSelectors(t *testing.T) {
	root := t.TempDir()
	overlayDir := filepath.Join(root, "overlay")
	require.NoError(t, os.MkdirAll(overlayDir, 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(`
resources:
- ../base
patches:
- path: patch-frontend.yaml
  target:
    kind: Deployment
    labelSelector: app=frontend
- path: patch-backend.yaml
  target:
    kind: Deployment
    labelSelector: app=demo
    annotationSelector: tier=backend
`), 0o600))

	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "patch-frontend.yaml"), []byte(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: not-used
spec:
  replicas: 1
`), 0o600))

	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "patch-backend.yaml"), []byte(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: not-used
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

	patchFile := TraceKustomizePatch(wl, []string{"spec.replicas (current: 3)"}, source)
	assert.Equal(t, "overlay/patch-backend.yaml", patchFile)
}

func TestTraceKustomizePatch_Json6902TestOpIgnored(t *testing.T) {
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
  path: patch-test.json
`), 0o600))

	// JSON patch contains only a "test" operation, not a write
	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "patch-test.json"), []byte(`[
  {"op": "test", "path": "/spec/replicas", "value": 3}
]`), 0o600))

	source := reporthandling.Source{
		Path:                   root,
		RelativePath:           "base/deployment.yaml",
		FileType:               reporthandling.SourceTypeKustomizeDirectory,
		KustomizeDirectoryName: overlayDir,
	}

	wl := newMockKustomizeWorkload("Deployment", "demo")

	patchFile := TraceKustomizePatch(wl, []string{"spec.replicas (current: 3)"}, source)
	assert.Equal(t, "", patchFile, "test op should not be attributed as a patch writer")
}

func TestTraceKustomizePatch_MultiDocStrategicMerge(t *testing.T) {
	root := t.TempDir()
	overlayDir := filepath.Join(root, "overlay")
	require.NoError(t, os.MkdirAll(overlayDir, 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(`
resources:
- ../base
patchesStrategicMerge:
- multi-patch.yaml
`), 0o600))

	// Multi-document YAML patch: first doc is for "other", second doc is for "demo"
	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "multi-patch.yaml"), []byte(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: other
spec:
  replicas: 5
---
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

	patchFile := TraceKustomizePatch(wl, []string{"spec.replicas (current: 3)"}, source)
	assert.Equal(t, "overlay/multi-patch.yaml", patchFile)
}

func TestTraceKustomizePatch_ApiVersionComparison(t *testing.T) {
	root := t.TempDir()
	overlayDir := filepath.Join(root, "overlay")
	require.NoError(t, os.MkdirAll(overlayDir, 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(`
resources:
- ../base
patchesStrategicMerge:
- patch-batch.yaml
`), 0o600))

	// Patch has apiVersion: batch/v1, while resource is apps/v1
	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "patch-batch.yaml"), []byte(`
apiVersion: batch/v1
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

	patchFile := TraceKustomizePatch(wl, []string{"spec.replicas (current: 3)"}, source)
	assert.Equal(t, "", patchFile, "apiVersion mismatch must not match")
}

func TestTraceKustomizePatch_ListMergeKeyMatching(t *testing.T) {
	root := t.TempDir()
	overlayDir := filepath.Join(root, "overlay")
	require.NoError(t, os.MkdirAll(overlayDir, 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(`
resources:
- ../base
patchesStrategicMerge:
- patch-container.yaml
`), 0o600))

	// Patch only touches the container named "nginx" (which is index 0 in the patch,
	// but index 1 in the rendered resource [sidecar, nginx])
	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "patch-container.yaml"), []byte(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  template:
    spec:
      containers:
      - name: nginx
        securityContext:
          privileged: true
`), 0o600))

	source := reporthandling.Source{
		Path:                   root,
		RelativePath:           "base/deployment.yaml",
		FileType:               reporthandling.SourceTypeKustomizeDirectory,
		KustomizeDirectoryName: overlayDir,
	}

	wl := newMockKustomizeWorkload("Deployment", "demo")

	// Finding is on nginx (containers[1] in rendered resource) -> must match patch by merge key "name"
	nginxPatch := TraceKustomizePatch(wl, []string{"spec.template.spec.containers[1].securityContext.privileged"}, source)
	assert.Equal(t, "overlay/patch-container.yaml", nginxPatch)

	// Finding is on sidecar (containers[0] in rendered resource) -> patch does NOT touch sidecar, so must not match
	sidecarPatch := TraceKustomizePatch(wl, []string{"spec.template.spec.containers[0].securityContext.privileged"}, source)
	assert.Equal(t, "", sidecarPatch, "patch touching only nginx must not attribute sidecar")
}
