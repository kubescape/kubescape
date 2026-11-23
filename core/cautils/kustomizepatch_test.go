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
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"
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

func TestTraceKustomizePatch_RenderedOverlay(t *testing.T) {
	const base = "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: demo, labels: {stage: old}, annotations: {tier: old}}\nspec: {replicas: 1}\n"
	const replace = "- {op: replace, path: /spec/replicas, value: 2}\n"
	const legacy = "patchesJson6902:\n- path: legacy.yaml\n  target: {kind: Deployment, name: demo}\n"
	const modern = "patches:\n- path: modern.yaml\n  target: {kind: Deployment, name: demo}\n"
	const affixes = "namePrefix: prod-\nnameSuffix: -west\n"
	const selected = "patches:\n- path: modern.yaml\n  target: {kind: Deployment, labelSelector: stage=old, annotationSelector: tier=old}\n"
	const changeMetadata = "- {op: replace, path: /metadata/labels/stage, value: new}\n- {op: replace, path: /metadata/annotations/tier, value: new}\n"
	for _, tc := range []struct {
		name, config, patch, want string
		replicas                  int64
	}{
		{"trailing JSON document", modern, changeMetadata + "---\n" + replace, "", 1},
		{"target matches only after rename", affixes + "patches:\n- path: legacy.yaml\n  target: {kind: Deployment, name: renamed}\n- path: modern.yaml\n  target: {kind: Deployment, name: demo}\n", "- {op: replace, path: /metadata/name, value: renamed}\n", "", 1},
		{"target matches only after namespace transform", affixes + "namespace: new\npatches:\n- path: modern.yaml\n  target: {kind: Deployment, name: demo, namespace: new}\n", replace, "", 1},
		{"mixed patch families", modern + legacy, replace, "legacy.yaml", 3},
		{"prefixed target", affixes + modern, replace, "modern.yaml", 2},
		{"prefixed merge identity", affixes + "patchesStrategicMerge: [modern.yaml]\n", "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: demo}\nspec: {replicas: 2}\n", "modern.yaml", 2},
		{"selector before patch changes metadata", selected, replace + changeMetadata, "modern.yaml", 2},
		{"ambiguous later writer hides earlier candidate", "patches:\n- path: legacy.yaml\n  target: {kind: Deployment, name: demo}\n- path: modern.yaml\n  target: {kind: Deployment, labelSelector: stage=old}\n", replace + changeMetadata, "", 2},
		{"selector matches only after transform", "commonLabels: {stage: new}\npatches:\n- path: modern.yaml\n  target: {kind: Deployment, labelSelector: stage=new}\n", replace, "", 1},
		{"replica transformer overrides patch", affixes + modern + "replicas: [{name: demo, count: 5}]\n", replace, "", 5},
		{"replica transformer matches rendered name", affixes + modern + "replicas: [{name: prod-demo-west, count: 5}]\n", replace, "", 5},
		{"replica transformer matches name before an earlier rename", "patches:\n- path: modern.yaml\n  target: {kind: Deployment, name: demo}\n- path: legacy.yaml\n  target: {kind: Deployment, name: renamed}\nreplicas: [{name: demo, count: 5}]\n", "- {op: replace, path: /metadata/name, value: renamed}\n", "", 5},
		{"legacy selector matches only build metadata label", "buildMetadata: [managedByLabel]\npatchesJson6902:\n- path: legacy.yaml\n  target: {kind: Deployment, name: demo, labelSelector: app.kubernetes.io/managed-by}\n", replace, "", 1},
		{"legacy selector unaffected by build metadata", "buildMetadata: [managedByLabel]\npatchesJson6902:\n- path: legacy.yaml\n  target: {kind: Deployment, name: demo, labelSelector: stage=old}\n", replace, "legacy.yaml", 3},
		{"modern selector unaffected by build metadata", "buildMetadata: [managedByLabel]\n" + selected, replace, "modern.yaml", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for file, contents := range map[string]string{
				"kustomization.yaml": "resources: [base.yaml]\n" + tc.config,
				"base.yaml":          base,
				"modern.yaml":        tc.patch,
				"legacy.yaml":        "- {op: replace, path: /spec/replicas, value: 3}\n",
			} {
				require.NoError(t, os.WriteFile(filepath.Join(dir, file), []byte(contents), 0600))
			}
			result, err := krusty.MakeKustomizer(krusty.MakeDefaultOptions()).Run(filesys.MakeFsOnDisk(), dir)
			require.NoError(t, err)
			require.Len(t, result.Resources(), 1)
			obj, err := result.Resources()[0].Map()
			require.NoError(t, err)
			require.EqualValues(t, tc.replicas, obj["spec"].(map[string]any)["replicas"])
			src := reporthandling.Source{Path: dir, RelativePath: ".", FileType: reporthandling.SourceTypeKustomizeDirectory, KustomizeDirectoryName: dir}
			require.Equal(t, tc.want, TraceKustomizePatch(localworkload.NewLocalWorkload(obj), []string{"spec.replicas"}, src))
		})
	}
}

func TestTraceKustomizePatch_RenderedNestedBase(t *testing.T) {
	const early = "patches:\n- path: early.yaml\n  target: {kind: Deployment, name: base-demo}\n"
	for _, tc := range []struct {
		name, base, overlay, want string
		replicas                  int64
		origin, inputs            string
	}{
		{"later writer selects a base name", "namePrefix: base-\n", "namePrefix: prod-\n" + early + "- path: late.yaml\n  target: {kind: Deployment, name: demo}\n", "", 3, "", "resources"},
		{"later merge patch selects a base name", "namePrefix: base-\n", "namePrefix: prod-\npatchesStrategicMerge: [early-smp.yaml, late-smp.yaml]\n", "", 3, "", "resources"},
		// The base name is invisible from the overlay, so an unmatched name stays uncertain.
		{"later writer with an unrelated name", "namePrefix: base-\n", "namePrefix: prod-\n" + early + "- path: late.yaml\n  target: {kind: Deployment, name: other}\n", "", 2, "", "resources"},
		{"recorded origin reveals a later writer", "namePrefix: base-\n", "namePrefix: prod-\n" + early + "- path: late.yaml\n  target: {kind: Deployment, name: demo}\n", "late.yaml", 3, "base/deployment.yaml", "resources"},
		{"recorded origin reveals a later merge patch", "namePrefix: base-\n", "namePrefix: prod-\npatchesStrategicMerge: [early-smp.yaml, late-smp.yaml]\n", "late-smp.yaml", 3, "base/deployment.yaml", "resources"},
		{"recorded origin rules out an unrelated name", "namePrefix: base-\n", "namePrefix: prod-\n" + early + "- path: late.yaml\n  target: {kind: Deployment, name: other}\n", "early.yaml", 2, "base/deployment.yaml", "resources"},
		{"recorded origin namespace", "namespace: moved\n", "patches:\n- path: late.yaml\n  target: {kind: Deployment, name: demo, namespace: start}\n", "late.yaml", 3, "base/deployment.yaml", "resources"},
		{"recorded origin namespace pattern", "namespace: moved\n", early + "- path: late.yaml\n  target: {kind: Deployment, name: demo, namespace: sta.*}\n", "late.yaml", 3, "base/deployment.yaml", "resources"},
		{"later writer for another kind", "namePrefix: base-\n", "namePrefix: prod-\n" + early + "- path: late.yaml\n  target: {kind: StatefulSet, name: demo}\n", "early.yaml", 2, "", "resources"},
		{"single writer through a base prefix", "namePrefix: base-\n", "namePrefix: prod-\n" + early, "early.yaml", 2, "", "resources"},
		{"single writer through a plain base", "", "patches:\n- path: early.yaml\n  target: {kind: Deployment, name: demo}\n", "early.yaml", 2, "", "resources"},
		{"legacy bases hide a later writer", "namePrefix: base-\n", "namePrefix: prod-\n" + early + "- path: late.yaml\n  target: {kind: Deployment, name: demo}\n", "", 3, "", "bases"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(root, "base"), 0o700))
			require.NoError(t, os.MkdirAll(filepath.Join(root, "overlay"), 0o700))
			for file, contents := range map[string]string{
				"base/kustomization.yaml":    "resources: [deployment.yaml]\n" + tc.base,
				"base/deployment.yaml":       "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: demo, namespace: start}\nspec: {replicas: 1}\n",
				"overlay/kustomization.yaml": tc.inputs + ": [../base]\n" + tc.overlay,
				"overlay/early.yaml":         "- {op: replace, path: /spec/replicas, value: 2}\n",
				"overlay/late.yaml":          "- {op: replace, path: /spec/replicas, value: 3}\n",
				"overlay/early-smp.yaml":     "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: base-demo, namespace: start}\nspec: {replicas: 2}\n",
				"overlay/late-smp.yaml":      "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: demo, namespace: start}\nspec: {replicas: 3}\n",
			} {
				require.NoError(t, os.WriteFile(filepath.Join(root, file), []byte(contents), 0o600))
			}
			overlay := filepath.Join(root, "overlay")
			result, err := krusty.MakeKustomizer(krusty.MakeDefaultOptions()).Run(filesys.MakeFsOnDisk(), overlay)
			require.NoError(t, err)
			require.Len(t, result.Resources(), 1)
			obj, err := result.Resources()[0].Map()
			require.NoError(t, err)
			require.EqualValues(t, tc.replicas, obj["spec"].(map[string]any)["replicas"])
			if tc.origin == "" {
				tc.origin = "overlay"
			}
			src := reporthandling.Source{Path: root, RelativePath: tc.origin, FileType: reporthandling.SourceTypeKustomizeDirectory, KustomizeDirectoryName: overlay}
			got := TraceKustomizePatch(localworkload.NewLocalWorkload(obj), []string{"spec.replicas"}, src)
			if tc.want != "" {
				tc.want = "overlay/" + tc.want
			}
			require.Equal(t, tc.want, got)
		})
	}
}

// renderKustomization writes files under a temporary root, builds dir with
// Kustomize and returns the root and the rendered resource in namespace.
func renderKustomization(t *testing.T, files map[string]string, dir, namespace string) (string, map[string]any) {
	t.Helper()
	root := t.TempDir()
	for file, contents := range files {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(root, file)), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(root, file), []byte(contents), 0o600))
	}
	result, err := krusty.MakeKustomizer(krusty.MakeDefaultOptions()).Run(filesys.MakeFsOnDisk(), filepath.Join(root, dir))
	require.NoError(t, err)
	for _, res := range result.Resources() {
		if res.GetNamespace() == namespace {
			obj, err := res.Map()
			require.NoError(t, err)
			return root, obj
		}
	}
	require.FailNow(t, "no rendered resource in namespace "+namespace)
	return "", nil
}

func TestTraceKustomizePatch_ReplicaEntryForAnotherResource(t *testing.T) {
	root, obj := renderKustomization(t, map[string]string{
		"kustomization.yaml": "resources: [demo.yaml, worker.yaml]\npatches:\n- path: patch.yaml\n  target: {kind: Deployment, name: demo}\nreplicas: [{name: worker, count: 2}]\n",
		"demo.yaml":          "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: demo, namespace: a}\nspec: {replicas: 1}\n",
		"worker.yaml":        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: worker, namespace: b}\nspec: {replicas: 1}\n",
		"patch.yaml":         "- {op: replace, path: /spec/replicas, value: 2}\n",
	}, ".", "a")
	require.EqualValues(t, 2, obj["spec"].(map[string]any)["replicas"])
	src := reporthandling.Source{Path: root, RelativePath: "demo.yaml", FileType: reporthandling.SourceTypeKustomizeDirectory, KustomizeDirectoryName: root}
	require.Equal(t, "patch.yaml", TraceKustomizePatch(localworkload.NewLocalWorkload(obj), []string{"spec.replicas"}, src))
}

func TestTraceKustomizePatch_ReplicaEntryForMiddleName(t *testing.T) {
	// Two bases rename the resource, so a-demo is a name only Kustomize saw.
	root, obj := renderKustomization(t, map[string]string{
		"inner/kustomization.yaml":   "resources: [deployment.yaml]\nnamePrefix: a-\n",
		"inner/deployment.yaml":      "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: demo, namespace: start}\nspec: {replicas: 1}\n",
		"outer/kustomization.yaml":   "resources: [../inner]\nnamePrefix: b-\n",
		"overlay/kustomization.yaml": "resources: [../outer]\npatches:\n- path: patch.yaml\n  target: {kind: Deployment, name: b-a-demo}\nreplicas: [{name: a-demo, count: 5}]\n",
		"overlay/patch.yaml":         "- {op: replace, path: /spec/replicas, value: 2}\n",
	}, "overlay", "start")
	require.EqualValues(t, 5, obj["spec"].(map[string]any)["replicas"])
	src := reporthandling.Source{Path: root, RelativePath: "inner/deployment.yaml", FileType: reporthandling.SourceTypeKustomizeDirectory, KustomizeDirectoryName: filepath.Join(root, "overlay")}
	require.Empty(t, TraceKustomizePatch(localworkload.NewLocalWorkload(obj), []string{"spec.replicas"}, src))
}

func TestTraceKustomizePatch_AmbiguousOriginDocument(t *testing.T) {
	// Both documents share a name, so the origin file cannot tell which one
	// became the traced resource, nor which namespace it started in.
	root, obj := renderKustomization(t, map[string]string{
		"base/kustomization.yaml":    "resources: [deployments.yaml]\n",
		"base/deployments.yaml":      "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: demo, namespace: a}\nspec: {replicas: 1}\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata: {name: demo, namespace: b}\nspec: {replicas: 1}\n",
		"overlay/kustomization.yaml": "resources: [../base]\npatches:\n- path: early.yaml\n  target: {kind: Deployment, name: demo, namespace: b}\n- path: late.yaml\n  target: {kind: Deployment, name: demo, namespace: a}\n",
		"overlay/early.yaml":         "- {op: replace, path: /spec/replicas, value: 2}\n",
		"overlay/late.yaml":          "- {op: replace, path: /spec/replicas, value: 3}\n",
	}, "overlay", "b")
	require.EqualValues(t, 2, obj["spec"].(map[string]any)["replicas"])
	src := reporthandling.Source{Path: root, RelativePath: "base/deployments.yaml", FileType: reporthandling.SourceTypeKustomizeDirectory, KustomizeDirectoryName: filepath.Join(root, "overlay")}
	require.Empty(t, TraceKustomizePatch(localworkload.NewLocalWorkload(obj), []string{"spec.replicas"}, src))
}

func TestTraceKustomizePatch_InvalidDocument(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte("patchesStrategicMerge: [patch.yaml]\n"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "patch.yaml"), []byte("kind: Deployment\nmetadata: {name: demo}\nspec: {replicas: 3}\n---\n[\n"), 0600))
	src := reporthandling.Source{Path: dir, FileType: reporthandling.SourceTypeKustomizeDirectory, KustomizeDirectoryName: dir}
	require.Empty(t, TraceKustomizePatch(newMockKustomizeWorkload("Deployment", "demo"), []string{"spec.replicas"}, src))
}

func TestMatchYamlHeader_PaddedPatchNamespace(t *testing.T) {
	resource := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "web", "namespace": "prod"},
	})
	header := func(ns string) map[string]any {
		return map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "web", "namespace": ns}}
	}
	assert.True(t, matchYamlHeader(header(" prod "), resource, "web"))
	assert.False(t, matchYamlHeader(header("staging"), resource, "web"))
}
