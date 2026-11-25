package cautils

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

// kustomizeOriginFixture writes a base and an overlay that composes it and
// returns the directory that holds both. The overlay patches the base's
// Deployment, adds a resource of its own, and generates a ConfigMap, so every
// way a resource can reach the output is present.
func kustomizeOriginFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(name, content string) {
		path := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	write("base/kustomization.yaml", "resources:\n- deployment.yaml\n- service.yaml\n")
	write("base/deployment.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
  annotations:
    team: platform
spec:
  replicas: 1
`)
	write("base/service.yaml", "apiVersion: v1\nkind: Service\nmetadata:\n  name: demo\n")
	write("overlay/kustomization.yaml", `resources:
- ../base
- extra.yaml
configMapGenerator:
- name: generated
  literals:
  - key=value
patches:
- patch: |-
    - op: replace
      path: /spec/replicas
      value: 3
  target:
    kind: Deployment
`)
	write("overlay/extra.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: extra\n")
	return root
}

// renderedKustomizeWorkloads renders dir and returns the workloads by kind and
// name, with the directory's own origin map.
func renderedKustomizeWorkloads(t *testing.T, dir string) (map[string]workloadinterface.IMetadata, map[string]string) {
	t.Helper()
	kd := NewKustomizeDirectory(dir)
	workloads, errs := kd.GetWorkloads(dir)
	require.Empty(t, errs)

	byName := map[string]workloadinterface.IMetadata{}
	for _, list := range workloads {
		for _, workload := range list {
			byName[workload.GetKind()+"/"+workload.GetName()] = workload
		}
	}
	return byName, kd.OriginFiles()
}

func TestKustomizeWorkloadsRecordTheirOriginFile(t *testing.T) {
	root := kustomizeOriginFixture(t)
	overlay := filepath.Join(root, "overlay")
	byName, origins := renderedKustomizeWorkloads(t, overlay)

	require.Len(t, byName, 4)

	file := func(kindAndName string) string {
		workload, ok := byName[kindAndName]
		require.True(t, ok, kindAndName)
		return origins[workload.GetID()]
	}

	assert.Equal(t, filepath.Join(root, "base", "deployment.yaml"), file("Deployment/demo"),
		"a patched resource is attributed to the file it was read from, not to the overlay that patched it")
	assert.Equal(t, filepath.Join(root, "base", "service.yaml"), file("Service/demo"))
	assert.Equal(t, filepath.Join(root, "overlay", "extra.yaml"), file("ConfigMap/extra"))
	assert.Equal(t, filepath.Join(overlay, "kustomization.yaml"), origins[generatedConfigMap(t, byName).GetID()],
		"a generated resource is attributed to the kustomization that configures the generator")
}

// TestKustomizeOriginsWhenTheTemporaryDirectoryIsASymlink pins the origin
// files when the temporary directory is reached through a symlink, as on macOS,
// where $TMPDIR is under /var and /var is a link to /private/var. Kustomize
// resolves the wrapper's directory before it follows the wrapper's relative
// reference to the scanned one, so a reference computed from the unresolved
// directory climbed the wrong number of levels, the wrapper build failed, and
// every resource fell back to its Kustomize directory.
func TestKustomizeOriginsWhenTheTemporaryDirectoryIsASymlink(t *testing.T) {
	root := kustomizeOriginFixture(t)
	overlay := filepath.Join(root, "overlay")

	// The link and its target sit at different depths, so a relative path from
	// one is not a relative path from the other.
	target := filepath.Join(t.TempDir(), "a", "b", "c")
	require.NoError(t, os.MkdirAll(target, 0o700))
	link := filepath.Join(t.TempDir(), "tmp")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	// os.TempDir reads TMPDIR on Unix and TMP, then TEMP, on Windows.
	t.Setenv("TMPDIR", link)
	t.Setenv("TMP", link)
	t.Setenv("TEMP", link)
	require.Equal(t, link, os.TempDir(), "the wrapper must be created under the link")

	byName, origins := renderedKustomizeWorkloads(t, overlay)

	require.Len(t, byName, 4)
	deployment, ok := byName["Deployment/demo"]
	require.True(t, ok)
	assert.Equal(t, filepath.Join(root, "base", "deployment.yaml"), origins[deployment.GetID()])
	assert.Equal(t, filepath.Join(root, "overlay", "extra.yaml"), origins[byName["ConfigMap/extra"].GetID()])
}

// generatedConfigMap returns the ConfigMap the overlay's generator made. Kustomize
// adds a hash to its name, so it is found by prefix.
func generatedConfigMap(t *testing.T, byName map[string]workloadinterface.IMetadata) workloadinterface.IMetadata {
	t.Helper()
	for _, workload := range byName {
		if workload.GetKind() == "ConfigMap" && strings.HasPrefix(workload.GetName(), "generated-") {
			return workload
		}
	}
	t.Fatal("no generated ConfigMap in the output")
	return nil
}

// The annotation is Kubescape's own request to Kustomize. It must not reach the
// resource a rule reads, and the annotations the user wrote must.
func TestKustomizeWorkloadsDoNotKeepTheOriginAnnotation(t *testing.T) {
	root := kustomizeOriginFixture(t)
	byName, _ := renderedKustomizeWorkloads(t, filepath.Join(root, "overlay"))

	for name, workload := range byName {
		assert.NotContains(t, annotationsOf(workload), kustomizeOriginAnnotation, name)
	}
	assert.Equal(t, "platform", annotationsOf(byName["Deployment/demo"])["team"], "an annotation the user wrote is kept")

	// A resource with no annotations of its own gets none, rather than an empty map.
	metadata, _ := byName["Service/demo"].GetObject()["metadata"].(map[string]any)
	assert.NotContains(t, metadata, "annotations")
}

// Rendering through the wrapper must give the same resources as the plain build.
func TestKustomizeWorkloadsMatchThePlainBuild(t *testing.T) {
	root := kustomizeOriginFixture(t)
	overlay := filepath.Join(root, "overlay")

	withOrigins, _ := renderedKustomizeWorkloads(t, overlay)

	original := originRenderer
	t.Cleanup(func() { originRenderer = original })
	originRenderer = func(func() *krusty.Kustomizer, string, []string) ([]byte, string, bool) { return nil, "", false }
	plain, origins := renderedKustomizeWorkloads(t, overlay)

	assert.Empty(t, origins, "the plain build records no origin")
	require.Len(t, plain, len(withOrigins))
	for name, workload := range plain {
		other, ok := withOrigins[name]
		require.True(t, ok, name)
		assert.Equal(t, workload.GetObject(), other.GetObject(), name)
	}
	assert.Equal(t, int64(3), replicasOf(t, plain["Deployment/demo"]), "the patch still applies")
}

func annotationsOf(workload workloadinterface.IMetadata) map[string]any {
	metadata, _ := workload.GetObject()["metadata"].(map[string]any)
	annotations, _ := metadata["annotations"].(map[string]any)
	return annotations
}

func replicasOf(t *testing.T, workload workloadinterface.IMetadata) int64 {
	t.Helper()
	spec, _ := workload.GetObject()["spec"].(map[string]any)
	switch replicas := spec["replicas"].(type) {
	case int64:
		return replicas
	case float64:
		return int64(replicas)
	case int:
		return int64(replicas)
	}
	t.Fatalf("no replicas in %v", spec)
	return 0
}

// The workload's own path stays the Kustomize directory: the fix command reads it.
func TestKustomizeWorkloadPathStaysTheDirectory(t *testing.T) {
	root := kustomizeOriginFixture(t)
	overlay := filepath.Join(root, "overlay")
	kd := NewKustomizeDirectory(overlay)
	workloads, errs := kd.GetWorkloads(overlay)
	require.Empty(t, errs)

	require.Len(t, workloads, 1, "still keyed by the one Kustomize directory")
	for dir := range workloads {
		assert.Equal(t, lexicalAbsPath(overlay), dir)
	}
}

func TestTakeKustomizeOrigin(t *testing.T) {
	base := t.TempDir()
	file := filepath.Join(base, "deploy.yaml")
	require.NoError(t, os.WriteFile(file, []byte("kind: Deployment\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(base), "deploy.yaml"), []byte("kind: Deployment\n"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(base, "dir"), 0o755))

	object := func(annotations map[string]any) map[string]any {
		metadata := map[string]any{"name": "demo"}
		if annotations != nil {
			metadata["annotations"] = annotations
		}
		return map[string]any{"metadata": metadata}
	}
	annotated := func(origin string, others ...string) map[string]any {
		annotations := map[string]any{kustomizeOriginAnnotation: origin}
		for _, other := range others {
			annotations[other] = "kept"
		}
		return object(annotations)
	}

	tests := []struct {
		name string
		obj  map[string]any
		want string
	}{
		{"a local file", annotated("path: deploy.yaml\n"), file},
		{"a file reached through a parent directory", annotated("path: dir/../deploy.yaml\n"), file},
		{"a generator's config file when no path is given", annotated("configuredIn: deploy.yaml\n"), file},
		{"a remote repository", annotated("path: deploy.yaml\nrepo: https://example.com/org/repo\n"), ""},
		{"a file that is not there", annotated("path: gone.yaml\n"), ""},
		{"a directory", annotated("path: dir\n"), ""},
		{"an empty origin", annotated("{}\n"), ""},
		{"an origin that is not YAML", annotated("path: [unclosed\n"), ""},
		{"an origin escaping the base directory", annotated("path: ../deploy.yaml\n"), ""},
		{"no annotation at all", object(nil), ""},
		{"no metadata at all", map[string]any{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, takeKustomizeOrigin(tt.obj, base, true))

			metadata, _ := tt.obj["metadata"].(map[string]any)
			annotations, _ := metadata["annotations"].(map[string]any)
			assert.NotContains(t, annotations, kustomizeOriginAnnotation, "the annotation is removed whatever it said")
		})
	}

	t.Run("an origin pointing to a symlink that escapes base directory is rejected", func(t *testing.T) {
		outsideDir := t.TempDir()
		outsideFile := filepath.Join(outsideDir, "secret.yaml")
		require.NoError(t, os.WriteFile(outsideFile, []byte("kind: Secret\n"), 0o600))
		symlink := filepath.Join(base, "symlink-outside.yaml")
		require.NoError(t, os.Symlink(outsideFile, symlink))

		obj := annotated("path: symlink-outside.yaml\n")
		assert.Equal(t, "", takeKustomizeOrigin(obj, base, true))
	})

	t.Run("wrapper mode accepts file in allowed scanned directory even when outside wrapper base", func(t *testing.T) {
		wrapperBase := t.TempDir()
		scannedDir := t.TempDir()
		scannedFile := filepath.Join(scannedDir, "workload.yaml")
		require.NoError(t, os.WriteFile(scannedFile, []byte("kind: Deployment\n"), 0o600))

		relPath, err := filepath.Rel(wrapperBase, scannedFile)
		require.NoError(t, err)

		obj := annotated("path: " + relPath + "\n")
		assert.Equal(t, scannedFile, takeKustomizeOrigin(obj, wrapperBase, true, scannedDir))

		// But forged path escaping scanned directory is rejected
		outsideDir := t.TempDir()
		forgedFile := filepath.Join(outsideDir, "escaped.yaml")
		require.NoError(t, os.WriteFile(forgedFile, []byte("kind: Deployment\n"), 0o600))
		forgedRel, err := filepath.Rel(wrapperBase, forgedFile)
		require.NoError(t, err)

		forgedObj := annotated("path: " + forgedRel + "\n")
		assert.Equal(t, "", takeKustomizeOrigin(forgedObj, wrapperBase, true, scannedDir))

		// Symlink inside scanned directory pointing outside is rejected
		symlinkInScanned := filepath.Join(scannedDir, "symlink-escaped.yaml")
		require.NoError(t, os.Symlink(forgedFile, symlinkInScanned))
		symlinkRel, err := filepath.Rel(wrapperBase, symlinkInScanned)
		require.NoError(t, err)

		symlinkObj := annotated("path: " + symlinkRel + "\n")
		assert.Equal(t, "", takeKustomizeOrigin(symlinkObj, wrapperBase, true, scannedDir))
	})

	t.Run("other annotations survive and the annotation map is dropped when empty", func(t *testing.T) {
		obj := annotated("path: deploy.yaml\n", "team")
		require.Equal(t, file, takeKustomizeOrigin(obj, base, true))
		assert.Equal(t, map[string]any{"team": "kept"}, obj["metadata"].(map[string]any)["annotations"])

		only := annotated("path: deploy.yaml\n")
		require.Equal(t, file, takeKustomizeOrigin(only, base, true))
		assert.NotContains(t, only["metadata"], "annotations")
	})
}

// With no relative path from the temporary directory to the scanned one, the
// wrapper cannot be built and the caller has to do the plain build.
func TestRenderWithOriginsReportsFailureInsteadOfGuessing(t *testing.T) {
	newKustomizer := func() *krusty.Kustomizer { return krusty.MakeKustomizer(krusty.MakeDefaultOptions()) }

	_, _, ok := renderWithOrigins(newKustomizer, filepath.Join(t.TempDir(), "does-not-exist"), nil)
	assert.False(t, ok, "a directory that is not there cannot be rendered")
}

// The wrapper must not replace what the scanned kustomization asked Kustomize to
// add to its resources. Kustomize hands the outermost kustomization's
// buildMetadata to everything below it, so a wrapper with a list of its own would.
func TestOriginModeFollowsTheScannedBuildMetadata(t *testing.T) {
	tests := []struct {
		name          string
		buildMetadata string
		want          originMode
		preserved     []string
	}{
		{"nothing requested", "", originWrapper, nil},
		{"only the managed-by label", "buildMetadata: [managedByLabel]\n", originWrapper, []string{"managedByLabel"}},
		{"origin annotations", "buildMetadata: [originAnnotations]\n", originOwn, nil},
		{"origin annotations and the managed-by label", "buildMetadata: [managedByLabel, originAnnotations]\n", originOwn, nil},
		{"transformer annotations", "buildMetadata: [transformerAnnotations]\n", originUnavailable, nil},
		{"transformer and origin annotations", "buildMetadata: [transformerAnnotations, originAnnotations]\n", originOwn, nil},
		{"transformer annotations and the managed-by label", "buildMetadata: [managedByLabel, transformerAnnotations]\n", originUnavailable, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "d.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: d\n"), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte("resources:\n- d.yaml\n"+tt.buildMetadata), 0o600))

			plan := originModeFor(dir)

			assert.Equal(t, tt.want, plan.mode)
			assert.Equal(t, tt.preserved, plan.preserved)
		})
	}

	t.Run("no kustomization to read", func(t *testing.T) {
		assert.Equal(t, originUnavailable, originModeFor(t.TempDir()).mode)
	})
	t.Run("a kustomization that is not YAML", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte("resources: [unclosed\n"), 0o600))
		assert.Equal(t, originUnavailable, originModeFor(dir).mode)
	})
}

// kustomizeBuildMetadataFixture is a single-resource kustomization that asks for
// the given buildMetadata.
func kustomizeBuildMetadataFixture(t *testing.T, buildMetadata string) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "app"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "app", "deployment.yaml"),
		[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n  annotations:\n    team: platform\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "app", "kustomization.yaml"),
		[]byte("resources:\n- deployment.yaml\n"+buildMetadata), 0o600))
	return filepath.Join(root, "app")
}

func TestKustomizeKeepsTheManagedByLabelItAsked(t *testing.T) {
	dir := kustomizeBuildMetadataFixture(t, "buildMetadata: [managedByLabel]\n")

	byName, origins := renderedKustomizeWorkloads(t, dir)
	deployment := byName["Deployment/demo"]
	metadata, _ := deployment.GetObject()["metadata"].(map[string]any)
	labels, _ := metadata["labels"].(map[string]any)

	assert.Contains(t, labels, "app.kubernetes.io/managed-by", "the label the kustomization asked for is still added")
	assert.NotContains(t, annotationsOf(deployment), kustomizeOriginAnnotation, "the annotation Kubescape asked for is removed")
	assert.Equal(t, filepath.Join(dir, "deployment.yaml"), origins[deployment.GetID()], "and the origin is still found")

	// Identical to what the plain build gives.
	original := originRenderer
	t.Cleanup(func() { originRenderer = original })
	originRenderer = func(func() *krusty.Kustomizer, string, []string) ([]byte, string, bool) { return nil, "", false }
	plain, _ := renderedKustomizeWorkloads(t, dir)
	assert.Equal(t, plain["Deployment/demo"].GetObject(), deployment.GetObject())
}

// A kustomization that asked for origin annotations gets them, as it did before.
func TestKustomizeKeepsTheOriginAnnotationItAsked(t *testing.T) {
	dir := kustomizeBuildMetadataFixture(t, "buildMetadata: [originAnnotations]\n")

	byName, origins := renderedKustomizeWorkloads(t, dir)
	deployment := byName["Deployment/demo"]

	assert.Contains(t, annotationsOf(deployment), kustomizeOriginAnnotation, "the user asked for it, so a rule can read it")
	assert.Equal(t, "platform", annotationsOf(deployment)["team"])
	assert.Equal(t, filepath.Join(dir, "deployment.yaml"), origins[deployment.GetID()],
		"the origin is read from the annotation the plain build already carries")

	// The annotation is the one the plain build writes: relative to the scanned
	// directory, not to a wrapper.
	assert.Equal(t, "path: deployment.yaml\n", annotationsOf(deployment)[kustomizeOriginAnnotation])
}

// transformerAnnotations records paths relative to the build's root, which a
// wrapper would change, so such a kustomization is rendered as it always was.
func TestKustomizeWithTransformerAnnotationsIsRenderedAsBefore(t *testing.T) {
	dir := kustomizeBuildMetadataFixture(t, "buildMetadata: [transformerAnnotations]\n")

	called := false
	original := originRenderer
	t.Cleanup(func() { originRenderer = original })
	originRenderer = func(func() *krusty.Kustomizer, string, []string) ([]byte, string, bool) {
		called = true
		return nil, "", false
	}

	byName, origins := renderedKustomizeWorkloads(t, dir)

	assert.False(t, called, "no wrapper is built for it")
	assert.Empty(t, origins, "and the resources are attributed to the directory")
	assert.Contains(t, byName, "Deployment/demo")
}

// A patch can select on the very annotation the wrapper adds. The wrapper's
// build would then skip it, and removing the annotation afterwards cannot bring
// the patch back. The plain build is what the scan evaluates, so the resource
// must come out patched, and with no attribution since the wrapper disagreed.
func TestKustomizePlainBuildStaysAuthoritativeWhenTheOriginAnnotationChangesPatchSelection(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "deployment.yaml"),
		[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\nspec:\n  replicas: 1\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "kustomization.yaml"), []byte(`resources:
- deployment.yaml
patches:
- patch: |-
    - op: replace
      path: /spec/replicas
      value: 3
  target:
    kind: Deployment
    annotationSelector: "!config.kubernetes.io/origin"
`), 0o600))

	// The scenario is real: the wrapper's own build skips the patch.
	newKustomizer := func() *krusty.Kustomizer { return krusty.MakeKustomizer(krusty.MakeDefaultOptions()) }
	rendered, _, ok := renderWithOrigins(newKustomizer, root, nil)
	require.True(t, ok)
	wrapped, err := ReadFile(rendered, YAML_FILE_FORMAT)
	require.NoError(t, err)
	require.Len(t, wrapped, 1)
	require.Equal(t, int64(1), replicasOf(t, wrapped[0]), "the wrapper's build does not apply this patch")

	// The scan uses the plain build.
	byName, origins := renderedKustomizeWorkloads(t, root)
	assert.Equal(t, int64(3), replicasOf(t, byName["Deployment/demo"]), "the patch applies, as it does without Kubescape")
	assert.Empty(t, origins, "the wrapper rendered something else, so none of its file names is trusted")
}

func TestKustomizeDoesNotTrustPatchedOriginAnnotation(t *testing.T) {
	// takeKustomizeOrigin returns a resolved path, and the wrapper directory the
	// forged origin is relative to is resolved too, so both the root and the
	// temporary directory the forged path climbs from have to be resolved for
	// the test to pass where they are links, as /var is on macOS.
	root := resolvedTempDir(t)
	deploymentFile := filepath.Join(root, "deployment.yaml")
	decoyFile := filepath.Join(root, "service.yaml")
	require.NoError(t, os.WriteFile(deploymentFile,
		[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\nspec:\n  replicas: 1\n"), 0o600))
	require.NoError(t, os.WriteFile(decoyFile,
		[]byte("apiVersion: v1\nkind: Service\nmetadata:\n  name: demo\n"), 0o600))

	tempDir, err := filepath.EvalSymlinks(os.TempDir())
	require.NoError(t, err)
	relFromTemp, err := filepath.Rel(tempDir, decoyFile)
	require.NoError(t, err)
	forgedOriginPath := filepath.ToSlash(filepath.Join("..", relFromTemp))

	require.NoError(t, os.WriteFile(filepath.Join(root, "kustomization.yaml"), []byte(`resources:
- deployment.yaml
patches:
- patch: |-
    - op: replace
      path: /metadata/annotations/config.kubernetes.io~1origin
      value: |
        path: `+forgedOriginPath+`
  target:
    kind: Deployment
    annotationSelector: config.kubernetes.io/origin
`), 0o600))

	newKustomizer := func() *krusty.Kustomizer { return krusty.MakeKustomizer(krusty.MakeDefaultOptions()) }
	rendered, base, ok := renderWithOrigins(newKustomizer, root, nil)
	require.True(t, ok)
	wrapped, err := ReadFile(rendered, YAML_FILE_FORMAT)
	require.NoError(t, err)
	require.Len(t, wrapped, 1)
	// The wrapper's base is resolved and root may not be (on macOS, /private/var
	// and /var), so the forged path is checked by the file it names.
	forged := takeKustomizeOrigin(wrapped[0].GetObject(), base, true, root)
	require.True(t, isSameFile(decoyFile, forged), "the forged annotation names %q", forged)

	byName, origins := renderedKustomizeWorkloads(t, root)
	require.Contains(t, byName, "Deployment/demo")
	assert.NotContains(t, annotationsOf(byName["Deployment/demo"]), kustomizeOriginAnnotation)
	assert.Empty(t, origins)

	t.Run("originAnnotations requested in buildMetadata", func(t *testing.T) {
		ownDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(ownDir, "deployment.yaml"),
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(ownDir, "service.yaml"),
			[]byte("apiVersion: v1\nkind: Service\nmetadata:\n  name: demo\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(ownDir, "kustomization.yaml"), []byte(`resources:
- deployment.yaml
buildMetadata: [originAnnotations]
patches:
- patch: |-
    - op: replace
      path: /metadata/annotations/config.kubernetes.io~1origin
      value: |
        path: service.yaml
  target:
    kind: Deployment
    annotationSelector: config.kubernetes.io/origin
`), 0o600))

		_, ownOrigins := renderedKustomizeWorkloads(t, ownDir)
		assert.Empty(t, ownOrigins)
	})

	t.Run("a patch renames a resource to the name of a deleted one", func(t *testing.T) {
		renameDir := t.TempDir()
		for _, name := range []string{"a", "b"} {
			require.NoError(t, os.WriteFile(filepath.Join(renameDir, name+".yaml"),
				[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: "+name+"\n"), 0o600))
		}
		require.NoError(t, os.WriteFile(filepath.Join(renameDir, "kustomization.yaml"), []byte(`resources:
- a.yaml
- b.yaml
buildMetadata: [originAnnotations]
patches:
- patch: |-
    $patch: delete
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: b
- patch: |-
    - op: replace
      path: /metadata/name
      value: b
    - op: replace
      path: /metadata/annotations/config.kubernetes.io~1origin
      value: |
        path: b.yaml
  target:
    kind: Deployment
    name: a
`), 0o600))

		require.Equal(t, originUnavailable, originModeFor(renameDir).mode)
		byName, renamedOrigins := renderedKustomizeWorkloads(t, renameDir)
		require.Contains(t, byName, "Deployment/b")
		assert.Empty(t, renamedOrigins)
	})

	t.Run("two-resource swap regression", func(t *testing.T) {
		swapDir := t.TempDir()
		for _, name := range []string{"a", "b"} {
			require.NoError(t, os.WriteFile(filepath.Join(swapDir, name+".yaml"),
				[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: "+name+"\n  labels:\n    app: "+name+"\n"), 0o600))
		}
		require.NoError(t, os.WriteFile(filepath.Join(swapDir, "kustomization.yaml"), []byte(`resources:
- a.yaml
- b.yaml
buildMetadata: [originAnnotations]
patches:
- patch: |-
    - op: replace
      path: /metadata/name
      value: b
    - op: replace
      path: /metadata/annotations/config.kubernetes.io~1origin
      value: |
        path: b.yaml
  target:
    kind: Deployment
    labelSelector: "app=a"
- patch: |-
    - op: replace
      path: /metadata/name
      value: a
    - op: replace
      path: /metadata/annotations/config.kubernetes.io~1origin
      value: |
        path: a.yaml
  target:
    kind: Deployment
    labelSelector: "app=b"
`), 0o600))

		// 1. Verify that raw Kustomize build performs the swap and carries forged origin annotations
		newKustomizer := func() *krusty.Kustomizer { return krusty.MakeKustomizer(krusty.MakeDefaultOptions()) }
		rawResMap, err := newKustomizer().Run(filesys.MakeFsOnDisk(), swapDir)
		require.NoError(t, err)
		rawYml, err := rawResMap.AsYaml()
		require.NoError(t, err)
		rawWls, err := ReadFile(rawYml, YAML_FILE_FORMAT)
		require.NoError(t, err)
		require.Len(t, rawWls, 2)
		byAppLabel := map[string]workloadinterface.IMetadata{}
		for _, wl := range rawWls {
			meta, _ := wl.GetObject()["metadata"].(map[string]any)
			labels, _ := meta["labels"].(map[string]any)
			appLabel, _ := labels["app"].(string)
			byAppLabel[appLabel] = wl
		}
		require.Contains(t, byAppLabel, "a")
		require.Contains(t, byAppLabel, "b")

		wlA := byAppLabel["a"]
		assert.Equal(t, "b", wlA.GetName())
		metaA, _ := wlA.GetObject()["metadata"].(map[string]any)
		annosA, _ := metaA["annotations"].(map[string]any)
		assert.Contains(t, annosA[kustomizeOriginAnnotation], "path: b.yaml")

		wlB := byAppLabel["b"]
		assert.Equal(t, "a", wlB.GetName())
		metaB, _ := wlB.GetObject()["metadata"].(map[string]any)
		annosB, _ := metaB["annotations"].(map[string]any)
		assert.Contains(t, annosB[kustomizeOriginAnnotation], "path: a.yaml")

		// 2. Verify that Kubescape detects ambiguous transformations, suppresses attribution, and falls back to directory
		require.Equal(t, originUnavailable, originModeFor(swapDir).mode)
		kd := NewKustomizeDirectory(swapDir)
		workloads, errs := kd.GetWorkloads(swapDir)
		require.Empty(t, errs, "scanning must still succeed")
		byKindAndName := map[string]workloadinterface.IMetadata{}
		for _, list := range workloads {
			for _, wl := range list {
				byKindAndName[wl.GetKind()+"/"+wl.GetName()] = wl
			}
		}
		require.Contains(t, byKindAndName, "Deployment/a")
		require.Contains(t, byKindAndName, "Deployment/b")

		origins := kd.OriginFiles()
		assert.Empty(t, origins, "neither resource must be attributed to the forged file")

		for dirPath, wls := range workloads {
			assert.Equal(t, lexicalAbsPath(swapDir), dirPath, "workload path stays the directory")
			for _, wl := range wls {
				assert.NotEmpty(t, wl.GetName())
			}
		}
	})

	t.Run("originOwn mode rejects forged origin annotation and falls back to directory", func(t *testing.T) {
		ownDir := t.TempDir()
		deployFile := filepath.Join(ownDir, "deployment.yaml")
		serviceFile := filepath.Join(ownDir, "service.yaml")
		require.NoError(t, os.WriteFile(deployFile,
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"), 0o600))
		require.NoError(t, os.WriteFile(serviceFile,
			[]byte("apiVersion: v1\nkind: Service\nmetadata:\n  name: demo\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(ownDir, "kustomization.yaml"), []byte(`resources:
- deployment.yaml
buildMetadata: [originAnnotations]
patches:
- patch: |-
    - op: replace
      path: /metadata/annotations/config.kubernetes.io~1origin
      value: |
        path: service.yaml
  target:
    kind: Deployment
`), 0o600))

		require.Equal(t, originUnavailable, originModeFor(ownDir).mode)
		kd := NewKustomizeDirectory(ownDir)
		workloads, errs := kd.GetWorkloads(ownDir)
		require.Empty(t, errs, "scan must succeed even when origin annotations are forged")
		byKindAndName := map[string]workloadinterface.IMetadata{}
		for _, list := range workloads {
			for _, wl := range list {
				byKindAndName[wl.GetKind()+"/"+wl.GetName()] = wl
			}
		}
		require.Contains(t, byKindAndName, "Deployment/demo")

		origins := kd.OriginFiles()
		assert.Empty(t, origins, "forged origin must not become file attribution in originOwn mode")

		for dirPath, wls := range workloads {
			assert.Equal(t, lexicalAbsPath(ownDir), dirPath)
			for _, wl := range wls {
				assert.NotEmpty(t, wl.GetName())
			}
		}
	})

	t.Run("user-supplied origin annotation cannot forge file attribution", func(t *testing.T) {
		for _, mode := range []string{"wrapper", "originOwn"} {
			t.Run(mode, func(t *testing.T) {
				dir := t.TempDir()
				victimFile := filepath.Join(dir, "victim.yaml")
				attackerFile := filepath.Join(dir, "attacker.yaml")
				require.NoError(t, os.WriteFile(victimFile, []byte("apiVersion: v1\nkind: Service\nmetadata:\n  name: victim\n"), 0o600))
				require.NoError(t, os.WriteFile(attackerFile, []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: attacker
  annotations:
    config.kubernetes.io/origin: |
      path: victim.yaml
spec:
  replicas: 1
`), 0o600))
				kust := `resources:
- attacker.yaml
- victim.yaml
`
				if mode == "originOwn" {
					kust += "buildMetadata: [originAnnotations]\n"
				}
				require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(kust), 0o600))

				require.Equal(t, originUnavailable, originModeFor(dir).mode)
				kd := NewKustomizeDirectory(dir)
				workloads, errs := kd.GetWorkloads(dir)
				require.Empty(t, errs)
				byKindAndName := map[string]workloadinterface.IMetadata{}
				for _, list := range workloads {
					for _, wl := range list {
						byKindAndName[wl.GetKind()+"/"+wl.GetName()] = wl
					}
				}
				require.Contains(t, byKindAndName, "Deployment/attacker")
				require.Contains(t, byKindAndName, "Service/victim")
				origins := kd.OriginFiles()
				for _, wls := range workloads {
					for _, wl := range wls {
						if wl.GetName() == "attacker" {
							assert.NotEqual(t, victimFile, origins[wl.GetID()],
								"user-supplied origin annotation must never forge file attribution")
						}
					}
				}
				assert.Empty(t, origins, "attribution must be suppressed when input manifests forge origins in "+mode+" mode")
			})
		}
	})

	t.Run("generatorOptions forging origin annotation is rejected", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(`generatorOptions:
  annotations:
    config.kubernetes.io/origin: "path: forged.yaml\n"
configMapGenerator:
- name: generated
  literals:
  - key=value
`), 0o600))

		require.Equal(t, originUnavailable, originModeFor(dir).mode)
		kd := NewKustomizeDirectory(dir)
		workloads, errs := kd.GetWorkloads(dir)
		require.Empty(t, errs)
		found := false
		for _, wls := range workloads {
			for _, wl := range wls {
				if wl.GetKind() == "ConfigMap" && strings.HasPrefix(wl.GetName(), "generated-") {
					found = true
					break
				}
			}
		}
		require.True(t, found, "expected generated ConfigMap to be present")
		assert.Empty(t, kd.OriginFiles())
	})

	t.Run("patch file escaping baseDir is rejected", func(t *testing.T) {
		root := t.TempDir()
		base := filepath.Join(root, "app")
		outside := filepath.Join(root, "outside")
		require.NoError(t, os.MkdirAll(base, 0o755))
		require.NoError(t, os.MkdirAll(outside, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(base, "deploy.yaml"),
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(outside, "patch.yaml"),
			[]byte(`- op: replace
  path: /spec/replicas
  value: 3
`), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(base, "kustomization.yaml"), []byte(`resources:
- deploy.yaml
patches:
- path: ../outside/patch.yaml
  target:
    kind: Deployment
`), 0o600))

		require.Equal(t, originUnavailable, originModeFor(base).mode)
	})

	t.Run("originOwn mode follows a safe symlinked directory reference", func(t *testing.T) {
		root := t.TempDir()
		outside := t.TempDir()
		outsideBase := filepath.Join(outside, "base")
		require.NoError(t, os.MkdirAll(outsideBase, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(outsideBase, "deploy.yaml"),
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(outsideBase, "kustomization.yaml"),
			[]byte("resources:\n- deploy.yaml\n"), 0o600))

		app := filepath.Join(root, "app")
		require.NoError(t, os.MkdirAll(app, 0o755))
		if err := os.Symlink(outsideBase, filepath.Join(app, "symlink-base")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		require.NoError(t, os.WriteFile(filepath.Join(app, "kustomization.yaml"), []byte(`resources:
- symlink-base
buildMetadata: [originAnnotations]
`), 0o600))

		// The symlinked directory is inspected like any other reference; with nothing
		// ambiguous in the graph the scanned build's own origin annotations are used.
		assert.Equal(t, originOwn, originModeFor(app).mode)
		kd := NewKustomizeDirectory(app)
		workloads, errs := kd.GetWorkloads(app)
		require.Empty(t, errs, "scan must succeed")
		require.NotEmpty(t, workloads)
	})

	t.Run("originOwn mode inspects a forged patch behind a symlinked directory reference", func(t *testing.T) {
		root := t.TempDir()
		outside := t.TempDir()
		outsideBase := filepath.Join(outside, "base")
		require.NoError(t, os.MkdirAll(outsideBase, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(outsideBase, "deploy.yaml"),
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(outsideBase, "kustomization.yaml"), []byte(`resources:
- deploy.yaml
patches:
- patch: |-
    - op: replace
      path: /metadata/annotations/config.kubernetes.io~1origin
      value: |
        path: forged.yaml
  target:
    kind: Deployment
`), 0o600))

		app := filepath.Join(root, "app")
		require.NoError(t, os.MkdirAll(app, 0o755))
		if err := os.Symlink(outsideBase, filepath.Join(app, "symlink-base")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		require.NoError(t, os.WriteFile(filepath.Join(app, "kustomization.yaml"), []byte(`resources:
- symlink-base
buildMetadata: [originAnnotations]
`), 0o600))

		// The forging patch lives in the referenced base, so only graph inspection
		// can catch it; it must fail closed to the directory fallback.
		assert.Equal(t, originUnavailable, originModeFor(app).mode)
	})

	t.Run("patch loaded from file with metadata modification is suppressed", func(t *testing.T) {
		patchDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(patchDir, "deploy.yaml"),
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(patchDir, "patch.yaml"),
			[]byte(`- op: replace
  path: /metadata/annotations/config.kubernetes.io~1origin
  value: |
    path: forged.yaml
`), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(patchDir, "kustomization.yaml"), []byte(`resources:
- deploy.yaml
patches:
- path: patch.yaml
  target:
    kind: Deployment
`), 0o600))

		require.Equal(t, originUnavailable, originModeFor(patchDir).mode)
		byName, origins := renderedKustomizeWorkloads(t, patchDir)
		require.Contains(t, byName, "Deployment/demo")
		assert.Empty(t, origins)
	})

	t.Run("provably safe patch loaded from file retains attribution", func(t *testing.T) {
		patchDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(patchDir, "deploy.yaml"),
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\nspec:\n  replicas: 1\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(patchDir, "patch.yaml"),
			[]byte(`- op: replace
  path: /spec/replicas
  value: 5
`), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(patchDir, "kustomization.yaml"), []byte(`resources:
- deploy.yaml
patches:
- path: patch.yaml
  target:
    kind: Deployment
`), 0o600))

		require.Equal(t, originWrapper, originModeFor(patchDir).mode)
		byName, origins := renderedKustomizeWorkloads(t, patchDir)
		require.Contains(t, byName, "Deployment/demo")
		assert.Equal(t, int64(5), replicasOf(t, byName["Deployment/demo"]))
		assert.Equal(t, filepath.Join(patchDir, "deploy.yaml"), origins[byName["Deployment/demo"].GetID()])
	})

	t.Run("ambiguous patch in referenced base suppresses attribution", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, "base"), 0o755))
		require.NoError(t, os.MkdirAll(filepath.Join(root, "overlay"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, "base", "deploy.yaml"),
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(root, "base", "kustomization.yaml"), []byte(`resources:
- deploy.yaml
patches:
- patch: |-
    - op: replace
      path: /metadata/name
      value: renamed
  target:
    kind: Deployment
`), 0o600))
		overlay := filepath.Join(root, "overlay")
		require.NoError(t, os.WriteFile(filepath.Join(overlay, "kustomization.yaml"), []byte(`resources:
- ../base
`), 0o600))

		require.Equal(t, originUnavailable, originModeFor(overlay).mode)
		byName, origins := renderedKustomizeWorkloads(t, overlay)
		require.Contains(t, byName, "Deployment/renamed")
		assert.Empty(t, origins)
	})

	t.Run("ambiguous patch in referenced component suppresses attribution", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, "comp"), 0o755))
		require.NoError(t, os.MkdirAll(filepath.Join(root, "app"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, "app", "deploy.yaml"),
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(root, "comp", "kustomization.yaml"), []byte(`apiVersion: kustomize.config.k8s.io/v1alpha1
kind: Component
patches:
- patch: |-
    - op: replace
      path: /metadata/annotations/config.kubernetes.io~1origin
      value: |
        path: forged.yaml
  target:
    kind: Deployment
`), 0o600))
		app := filepath.Join(root, "app")
		require.NoError(t, os.WriteFile(filepath.Join(app, "kustomization.yaml"), []byte(`resources:
- deploy.yaml
components:
- ../comp
`), 0o600))

		require.Equal(t, originUnavailable, originModeFor(app).mode)
		byName, origins := renderedKustomizeWorkloads(t, app)
		require.Contains(t, byName, "Deployment/demo")
		assert.Empty(t, origins)
	})

	t.Run("commonAnnotations setting origin annotation suppresses attribution", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "deploy.yaml"),
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(`resources:
- deploy.yaml
commonAnnotations:
  config.kubernetes.io/origin: "path: forged.yaml\n"
`), 0o600))

		require.Equal(t, originUnavailable, originModeFor(dir).mode)
		byName, origins := renderedKustomizeWorkloads(t, dir)
		require.Contains(t, byName, "Deployment/demo")
		assert.Empty(t, origins)
	})

	t.Run("patch replacing whole metadata suppresses attribution", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "deploy.yaml"),
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(`resources:
- deploy.yaml
patches:
- patch: |-
    - op: replace
      path: /metadata
      value:
        name: demo
        annotations:
          config.kubernetes.io/origin: "path: forged.yaml\n"
  target:
    kind: Deployment
`), 0o600))

		require.Equal(t, originUnavailable, originModeFor(dir).mode)
		byName, origins := renderedKustomizeWorkloads(t, dir)
		require.Contains(t, byName, "Deployment/demo")
		assert.Empty(t, origins)
	})

	t.Run("namePrefix preserves exact expected file-to-workload mapping", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "deployment.yaml"),
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(`resources:
- deployment.yaml
namePrefix: prod-
`), 0o600))

		require.Equal(t, originWrapper, originModeFor(dir).mode)
		byName, origins := renderedKustomizeWorkloads(t, dir)
		require.Contains(t, byName, "Deployment/prod-demo")
		workload := byName["Deployment/prod-demo"]
		assert.Equal(t, filepath.Join(dir, "deployment.yaml"), origins[workload.GetID()],
			"normal namePrefix transformation retains safe file attribution")
	})

	t.Run("valid referenced base in supported layout preserves exact attribution", func(t *testing.T) {
		root := t.TempDir()
		base := filepath.Join(root, "base")
		overlay := filepath.Join(root, "overlay")
		require.NoError(t, os.MkdirAll(base, 0o755))
		require.NoError(t, os.MkdirAll(overlay, 0o755))
		baseDeploy := filepath.Join(base, "deploy.yaml")
		require.NoError(t, os.WriteFile(baseDeploy,
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(base, "kustomization.yaml"),
			[]byte("resources:\n- deploy.yaml\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(overlay, "kustomization.yaml"),
			[]byte("resources:\n- ../base\n"), 0o600))

		require.Equal(t, originWrapper, originModeFor(overlay).mode)
		byName, origins := renderedKustomizeWorkloads(t, overlay)
		require.Contains(t, byName, "Deployment/demo")
		assert.Equal(t, baseDeploy, origins[byName["Deployment/demo"].GetID()],
			"valid referenced base preserves exact file attribution")
	})

	t.Run("directory reference outside the scanned directory is attributed to its real file", func(t *testing.T) {
		root := t.TempDir()
		shared := filepath.Join(root, "shared")
		app := filepath.Join(root, "app")
		require.NoError(t, os.MkdirAll(shared, 0o755))
		require.NoError(t, os.MkdirAll(app, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(shared, "deploy.yaml"),
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(shared, "kustomization.yaml"),
			[]byte("resources:\n- deploy.yaml\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(app, "kustomization.yaml"),
			[]byte("resources:\n- ../shared\n"), 0o600))

		require.Equal(t, originWrapper, originModeFor(app).mode)
		byName, origins := renderedKustomizeWorkloads(t, app)
		require.Contains(t, byName, "Deployment/demo")
		assert.Equal(t, filepath.Join(shared, "deploy.yaml"), origins[byName["Deployment/demo"].GetID()])
	})

	t.Run("missing directory reference fails closed", func(t *testing.T) {
		app := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(app, "kustomization.yaml"),
			[]byte("resources:\n- ../does-not-exist\n"), 0o600))
		assert.Equal(t, originUnavailable, originModeFor(app).mode)
	})

	t.Run("symlinked directory reference outside the scanned directory is safe", func(t *testing.T) {
		root := t.TempDir()
		shared := filepath.Join(root, "shared")
		app := filepath.Join(root, "app")
		require.NoError(t, os.MkdirAll(shared, 0o755))
		require.NoError(t, os.MkdirAll(app, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(shared, "deploy.yaml"),
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(shared, "kustomization.yaml"),
			[]byte("resources:\n- deploy.yaml\n"), 0o600))

		symlinkBase := filepath.Join(app, "symlink-base")
		if err := os.Symlink(shared, symlinkBase); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		require.NoError(t, os.WriteFile(filepath.Join(app, "kustomization.yaml"),
			[]byte("resources:\n- symlink-base\n"), 0o600))

		require.Equal(t, originWrapper, originModeFor(app).mode)
	})

	t.Run("two-resource swap in wrapper mode suppresses attribution", func(t *testing.T) {
		swapDir := t.TempDir()
		for _, name := range []string{"a", "b"} {
			require.NoError(t, os.WriteFile(filepath.Join(swapDir, name+".yaml"),
				[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: "+name+"\n  labels:\n    app: "+name+"\n"), 0o600))
		}
		require.NoError(t, os.WriteFile(filepath.Join(swapDir, "kustomization.yaml"), []byte(`resources:
- a.yaml
- b.yaml
patches:
- patch: |-
    - op: replace
      path: /metadata/name
      value: b
    - op: replace
      path: /metadata/annotations/config.kubernetes.io~1origin
      value: |
        path: b.yaml
  target:
    kind: Deployment
    labelSelector: "app=a"
    annotationSelector: "config.kubernetes.io/origin"
- patch: |-
    - op: replace
      path: /metadata/name
      value: a
    - op: replace
      path: /metadata/annotations/config.kubernetes.io~1origin
      value: |
        path: a.yaml
  target:
    kind: Deployment
    labelSelector: "app=b"
    annotationSelector: "config.kubernetes.io/origin"
`), 0o600))

		// 1. Show that in the raw wrapper build, annotationSelector matches and carries swapped origins
		newKustomizer := func() *krusty.Kustomizer { return krusty.MakeKustomizer(krusty.MakeDefaultOptions()) }
		rawWrapperYml, _, ok := renderWithOrigins(newKustomizer, swapDir, nil)
		require.True(t, ok, "raw wrapper build can render")
		rawWls, err := ReadFile(rawWrapperYml, YAML_FILE_FORMAT)
		require.NoError(t, err)
		require.Len(t, rawWls, 2)
		byAppLabel := map[string]workloadinterface.IMetadata{}
		for _, wl := range rawWls {
			meta, _ := wl.GetObject()["metadata"].(map[string]any)
			labels, _ := meta["labels"].(map[string]any)
			appLabel, _ := labels["app"].(string)
			byAppLabel[appLabel] = wl
		}
		require.Contains(t, byAppLabel, "a")
		require.Contains(t, byAppLabel, "b")

		wlA := byAppLabel["a"]
		assert.Equal(t, "b", wlA.GetName())
		metaA, _ := wlA.GetObject()["metadata"].(map[string]any)
		annosA, _ := metaA["annotations"].(map[string]any)
		assert.Contains(t, annosA[kustomizeOriginAnnotation], "path: b.yaml",
			"raw wrapper build output matched annotationSelector and carries swapped origin")

		wlB := byAppLabel["b"]
		assert.Equal(t, "a", wlB.GetName())
		metaB, _ := wlB.GetObject()["metadata"].(map[string]any)
		annosB, _ := metaB["annotations"].(map[string]any)
		assert.Contains(t, annosB[kustomizeOriginAnnotation], "path: a.yaml",
			"raw wrapper build output matched annotationSelector and carries swapped origin")

		// 2. Verify Kubescape detects the ambiguous patch, sets originUnavailable, and falls back to directory
		require.Equal(t, originUnavailable, originModeFor(swapDir).mode)
		kd := NewKustomizeDirectory(swapDir)
		workloads, errs := kd.GetWorkloads(swapDir)
		require.Empty(t, errs, "scanning must still succeed in wrapper mode")
		byKindAndName := map[string]workloadinterface.IMetadata{}
		for _, list := range workloads {
			for _, wl := range list {
				byKindAndName[wl.GetKind()+"/"+wl.GetName()] = wl
			}
		}
		require.Contains(t, byKindAndName, "Deployment/a")
		require.Contains(t, byKindAndName, "Deployment/b")

		origins := kd.OriginFiles()
		assert.Empty(t, origins, "neither resource must receive file attribution in wrapper mode")
	})

	t.Run("patch modifying metadata without origin annotation suppresses attribution", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "deploy.yaml"),
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(`resources:
- deploy.yaml
patches:
- patch: |-
    - op: add
      path: /metadata/labels
      value:
        env: prod
  target:
    kind: Deployment
`), 0o600))

		require.Equal(t, originUnavailable, originModeFor(dir).mode)
		kd := NewKustomizeDirectory(dir)
		workloads, errs := kd.GetWorkloads(dir)
		require.Empty(t, errs, "scan must succeed when patch modifies metadata")
		byKindAndName := map[string]workloadinterface.IMetadata{}
		for _, list := range workloads {
			for _, wl := range list {
				byKindAndName[wl.GetKind()+"/"+wl.GetName()] = wl
			}
		}
		require.Contains(t, byKindAndName, "Deployment/demo")
		assert.Empty(t, kd.OriginFiles(), "modifying metadata isolates the /metadata rule and suppresses file attribution")
	})

	t.Run("patch file with forged origin in second document suppresses attribution", func(t *testing.T) {
		for _, mode := range []string{"wrapper", "originOwn"} {
			t.Run(mode, func(t *testing.T) {
				patchDir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(patchDir, "deploy.yaml"),
					[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\nspec:\n  replicas: 1\n"), 0o600))
				require.NoError(t, os.WriteFile(filepath.Join(patchDir, "patch.yaml"), []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  replicas: 3
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
  annotations:
    config.kubernetes.io/origin: |
      path: forged.yaml
`), 0o600))
				kustContent := `resources:
- deploy.yaml
patches:
- path: patch.yaml
`
				if mode == "originOwn" {
					kustContent += "buildMetadata: [originAnnotations]\n"
				}
				require.NoError(t, os.WriteFile(filepath.Join(patchDir, "kustomization.yaml"), []byte(kustContent), 0o600))

				require.Equal(t, originUnavailable, originModeFor(patchDir).mode)
				kd := NewKustomizeDirectory(patchDir)
				workloads, errs := kd.GetWorkloads(patchDir)
				require.Empty(t, errs, "scan must succeed")
				byKindAndName := map[string]workloadinterface.IMetadata{}
				for _, list := range workloads {
					for _, wl := range list {
						byKindAndName[wl.GetKind()+"/"+wl.GetName()] = wl
					}
				}
				require.Contains(t, byKindAndName, "Deployment/demo")
				assert.Empty(t, kd.OriginFiles(), "second document forging origin must suppress attribution in "+mode+" mode")
			})
		}
	})

	t.Run("patch with allowNameChange or allowKindChange is rejected", func(t *testing.T) {
		for _, opt := range []string{"allowNameChange", "allowKindChange"} {
			t.Run(opt, func(t *testing.T) {
				dir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir, "deploy.yaml"),
					[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\nspec:\n  replicas: 1\n"), 0o600))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(fmt.Sprintf(`resources:
- deploy.yaml
patches:
- patch: |-
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: demo
    spec:
      replicas: 2
  options:
    %s: true
`, opt)), 0o600))

				require.Equal(t, originUnavailable, originModeFor(dir).mode)
				kd := NewKustomizeDirectory(dir)
				workloads, errs := kd.GetWorkloads(dir)
				require.Empty(t, errs)
				byKindAndName := map[string]workloadinterface.IMetadata{}
				for _, list := range workloads {
					for _, wl := range list {
						byKindAndName[wl.GetKind()+"/"+wl.GetName()] = wl
					}
				}
				require.Contains(t, byKindAndName, "Deployment/demo")
				assert.Empty(t, kd.OriginFiles(), "patches setting "+opt+" must suppress attribution")
			})
		}
	})

	t.Run("manifest with kind List containing origin annotation suppresses attribution", func(t *testing.T) {
		for _, mode := range []string{"wrapper", "originOwn"} {
			t.Run(mode, func(t *testing.T) {
				dir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir, "list.yaml"), []byte(`apiVersion: v1
kind: List
items:
- apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: demo
    annotations:
      config.kubernetes.io/origin: |
        path: forged.yaml
  spec:
    replicas: 1
`), 0o600))
				kust := "resources:\n- list.yaml\n"
				if mode == "originOwn" {
					kust += "buildMetadata: [originAnnotations]\n"
				}
				require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(kust), 0o600))

				require.Equal(t, originUnavailable, originModeFor(dir).mode)
				kd := NewKustomizeDirectory(dir)
				workloads, errs := kd.GetWorkloads(dir)
				require.Empty(t, errs)
				byKindAndName := map[string]workloadinterface.IMetadata{}
				for _, list := range workloads {
					for _, wl := range list {
						byKindAndName[wl.GetKind()+"/"+wl.GetName()] = wl
					}
				}
				require.Contains(t, byKindAndName, "Deployment/demo")
				assert.Empty(t, kd.OriginFiles(), "List items containing origin annotation must suppress attribution in "+mode+" mode")
			})
		}
	})

	t.Run("commonAnnotations with empty origin annotation is rejected", func(t *testing.T) {
		for _, mode := range []string{"wrapper", "originOwn"} {
			t.Run(mode, func(t *testing.T) {
				dir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir, "deploy.yaml"),
					[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"), 0o600))
				kust := `resources:
- deploy.yaml
commonAnnotations:
  config.kubernetes.io/origin: ""
`
				if mode == "originOwn" {
					kust += "buildMetadata: [originAnnotations]\n"
				}
				require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(kust), 0o600))

				require.Equal(t, originUnavailable, originModeFor(dir).mode)
				kd := NewKustomizeDirectory(dir)
				workloads, errs := kd.GetWorkloads(dir)
				require.Empty(t, errs)
				byKindAndName := map[string]workloadinterface.IMetadata{}
				for _, list := range workloads {
					for _, wl := range list {
						byKindAndName[wl.GetKind()+"/"+wl.GetName()] = wl
					}
				}
				require.Contains(t, byKindAndName, "Deployment/demo")
				assert.Empty(t, kd.OriginFiles(), "presence of origin key with empty value must suppress attribution in "+mode+" mode")
			})
		}
	})

	t.Run("overlays/prod referencing ../../base preserves exact attribution", func(t *testing.T) {
		root := t.TempDir()

		baseDir := filepath.Join(root, "base")
		prodDir := filepath.Join(root, "overlays", "prod")
		require.NoError(t, os.MkdirAll(baseDir, 0o755))
		require.NoError(t, os.MkdirAll(prodDir, 0o755))

		baseDeploy := filepath.Join(baseDir, "deploy.yaml")
		require.NoError(t, os.WriteFile(baseDeploy, []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: prod-app
spec:
  replicas: 2
`), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(baseDir, "kustomization.yaml"), []byte(`resources:
- deploy.yaml
`), 0o600))

		require.NoError(t, os.WriteFile(filepath.Join(prodDir, "kustomization.yaml"), []byte(`resources:
- ../../base
namePrefix: prod-
`), 0o600))

		require.Equal(t, originWrapper, originModeFor(prodDir).mode)

		kd := NewKustomizeDirectory(prodDir)
		workloads, errs := kd.GetWorkloads(prodDir)
		require.Empty(t, errs)
		byKindAndName := map[string]workloadinterface.IMetadata{}
		for _, list := range workloads {
			for _, wl := range list {
				byKindAndName[wl.GetKind()+"/"+wl.GetName()] = wl
			}
		}
		require.Contains(t, byKindAndName, "Deployment/prod-prod-app")
		origins := kd.OriginFiles()
		assert.Equal(t, baseDeploy, origins[byKindAndName["Deployment/prod-prod-app"].GetID()],
			"resource from ../../base must be attributed to exact source file")
	})

	t.Run("manifest with an escaped origin annotation key is rejected", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "deploy.yaml"), []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
  annotations:
    "config.kubernetes.io\/origin": "path: forged.yaml"
`), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"),
			[]byte("resources:\n- deploy.yaml\n"), 0o600))
		assert.Equal(t, originUnavailable, originModeFor(dir).mode)
	})

	t.Run("JSON patch with case-colliding keys yields originUnavailable", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "deploy.yaml"),
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(`resources:
- deploy.yaml
patches:
- patch: '[{"op":"replace","path":"/metadata/name","Path":"/spec/replicas","value":"x"}]'
  target:
    kind: Deployment
`), 0o600))
		assert.Equal(t, originUnavailable, originModeFor(dir).mode)
	})

	t.Run("inline patchesJson6902 replacing /spec/replicas yields originWrapper", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "deploy.yaml"),
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\nspec:\n  replicas: 1\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(`resources:
- deploy.yaml
patchesJson6902:
- target:
    kind: Deployment
    name: demo
  patch: |-
    - op: replace
      path: /spec/replicas
      value: 3
`), 0o600))
		assert.Equal(t, originWrapper, originModeFor(dir).mode)
		byName, origins := renderedKustomizeWorkloads(t, dir)
		require.Contains(t, byName, "Deployment/demo")
		assert.Equal(t, int64(3), replicasOf(t, byName["Deployment/demo"]))
		assert.Equal(t, filepath.Join(dir, "deploy.yaml"), origins[byName["Deployment/demo"].GetID()])
	})

	t.Run("patchesStrategicMerge entry replicas.json containing a spec-only strategic-merge patch yields originWrapper", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "deploy.yaml"),
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "replicas.json"),
			[]byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"demo"},"spec":{"replicas":3}}`), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "kustomization.yaml"), []byte(`resources:
- deploy.yaml
patchesStrategicMerge:
- replicas.json
`), 0o600))
		assert.Equal(t, originWrapper, originModeFor(dir).mode)
	})

	t.Run("kustomization.yaml symlinked to config/settings.yaml with deploy.yaml next to symlink yields originWrapper", func(t *testing.T) {
		root := t.TempDir()
		configDir := filepath.Join(root, "config")
		require.NoError(t, os.MkdirAll(configDir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, "deploy.yaml"),
			[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(configDir, "settings.yaml"), []byte(`resources:
- deploy.yaml
`), 0o600))
		if err := os.Symlink(filepath.Join(configDir, "settings.yaml"), filepath.Join(root, "kustomization.yaml")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		assert.Equal(t, originWrapper, originModeFor(root).mode)
	})
}

func TestKustomizeAmbiguousBuildsStillScanSuccessfullyAndFallbackToDirectory(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "deploy.yaml"),
		[]byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "kustomization.yaml"), []byte(`resources:
- deploy.yaml
patches:
- patch: |-
    - op: replace
      path: /metadata/annotations/config.kubernetes.io~1origin
      value: |
        path: forged.yaml
  target:
    kind: Deployment
`), 0o600))

	kd := NewKustomizeDirectory(root)
	workloads, errs := kd.GetWorkloads(root)
	require.Empty(t, errs, "ambiguous builds must still render and scan successfully")
	require.Len(t, workloads, 1)
	assert.Empty(t, kd.OriginFiles(), "origins are empty so file attribution falls back to the directory")

	byKindAndName := map[string]workloadinterface.IMetadata{}
	for dirPath, list := range workloads {
		assert.Equal(t, lexicalAbsPath(root), dirPath, "workload path stays the directory")
		for _, wl := range list {
			byKindAndName[wl.GetKind()+"/"+wl.GetName()] = wl
		}
	}
	assert.Contains(t, byKindAndName, "Deployment/demo")
}

func TestManifestHasOriginAnnotation_BoundedRead(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("directory path is rejected safely by bounded reader", func(t *testing.T) {
		t.Parallel()
		assert.True(t, manifestHasOriginAnnotation(tmpDir), "unreadable/non-regular path conservatively falls back to true")
	})

	t.Run("non-existent file falls back safely to true", func(t *testing.T) {
		t.Parallel()
		missing := filepath.Join(tmpDir, "does-not-exist.yaml")
		assert.True(t, manifestHasOriginAnnotation(missing))
	})

	t.Run("size limit for manifest without origin annotation", func(t *testing.T) {
		path := filepath.Join(tmpDir, "plain.yaml")
		content := []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: plain\n")
		require.NoError(t, os.WriteFile(path, content, 0o600))

		t.Setenv(MaxFileSizeEnvVar, strconv.Itoa(len(content)))
		assert.False(t, manifestHasOriginAnnotation(path))
		t.Setenv(MaxFileSizeEnvVar, strconv.Itoa(len(content)-1))
		assert.True(t, manifestHasOriginAnnotation(path))
	})

	t.Run("regular file with origin annotation returns true", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(tmpDir, "with-origin.yaml")
		content := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: annotated\n  annotations:\n    config.kubernetes.io/origin: \"path: origin.yaml\"\n"
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		assert.True(t, manifestHasOriginAnnotation(path))
	})
}

func TestIsPatchProvablySafe_BoundedRead(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("patch file pointing to directory returns false", func(t *testing.T) {
		t.Parallel()
		subDir := filepath.Join(tmpDir, "patchdir")
		require.NoError(t, os.MkdirAll(subDir, 0o755))

		patch := types.Patch{Path: "patchdir"}
		assert.False(t, isPatchProvablySafe(tmpDir, patch))
	})

	t.Run("size limit for valid patch file", func(t *testing.T) {
		patchPath := filepath.Join(tmpDir, "patch.yaml")
		patchContent := "- op: replace\n  path: /spec/replicas\n  value: 3\n"
		require.NoError(t, os.WriteFile(patchPath, []byte(patchContent), 0o600))

		patch := types.Patch{Path: "patch.yaml"}
		t.Setenv(MaxFileSizeEnvVar, strconv.Itoa(len(patchContent)))
		assert.True(t, isPatchProvablySafe(tmpDir, patch))
		t.Setenv(MaxFileSizeEnvVar, strconv.Itoa(len(patchContent)-1))
		assert.False(t, isPatchProvablySafe(tmpDir, patch))
	})
}

func TestIsRemoteReference(t *testing.T) {
	tests := []struct {
		ref  string
		want bool
	}{
		{"github.com:org/repo//base", true},
		{"gh:org/repo", true},
		{"git@github.com:org/repo.git", true},
		{"https://x/y", true},
		{"../base", false},
		{"./overlays/prod", false},
		{"base", false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, isRemoteReference(tt.ref), "ref: %s", tt.ref)
	}
}

// writeKustomizeFiles writes files, keyed by slash-separated paths relative to
// root.
func writeKustomizeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
}

const demoDeployment = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\nspec:\n  replicas: 1\n"

// A base reached through a directory link climbs out of the link's target, not
// out of the link: Kustomize resolves the link first. Its origin annotation is
// the references joined as text, so it names a path next to the link instead.
// Attribution has to report the file Kustomize read, and must not report a
// different file that happens to sit at the annotated path.
func TestKustomizeOriginThroughALinkedBase(t *testing.T) {
	root := t.TempDir()
	writeKustomizeFiles(t, root, map[string]string{
		"app/kustomization.yaml":           "resources:\n- base-link\n",
		"shared/base/kustomization.yaml":   "resources:\n- ../common\n",
		"shared/common/kustomization.yaml": "resources:\n- deployment.yaml\n",
		"shared/common/deployment.yaml":    demoDeployment,
	})
	if err := os.Symlink(filepath.Join("..", "shared", "base"), filepath.Join(root, "app", "base-link")); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	require.NoError(t, err)
	want := filepath.Join(resolvedRoot, "shared", "common", "deployment.yaml")
	app := filepath.Join(root, "app")

	t.Run("the file Kustomize read is reported", func(t *testing.T) {
		byName, origins := renderedKustomizeWorkloads(t, app)
		require.Contains(t, byName, "Deployment/demo")
		assert.Equal(t, want, origins[byName["Deployment/demo"].GetID()])
	})

	t.Run("not a different file at the path the annotation names", func(t *testing.T) {
		writeKustomizeFiles(t, root, map[string]string{
			"app/common/deployment.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: unrelated\n",
		})
		byName, origins := renderedKustomizeWorkloads(t, app)
		require.Len(t, byName, 1, "the file next to the link is not part of the build")
		assert.Equal(t, want, origins[byName["Deployment/demo"].GetID()])
	})

	t.Run("nothing when the build reads two files under the same name", func(t *testing.T) {
		writeKustomizeFiles(t, root, map[string]string{
			"app/kustomization.yaml":        "resources:\n- base-link\n- common\n",
			"app/common/kustomization.yaml": "resources:\n- deployment.yaml\n",
			"app/common/deployment.yaml":    "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: unrelated\n",
		})
		byName, origins := renderedKustomizeWorkloads(t, app)
		require.Len(t, byName, 2)
		assert.Empty(t, origins, "both resources are annotated with app/common/deployment.yaml")
	})
}

// Git shorthand only applies to a base or a component. A resource that is a
// local file is read from disk whatever its name, and so is a patch file.
func TestKustomizeOriginForFileNamesWithAColon(t *testing.T) {
	probe := filepath.Join(t.TempDir(), "a:b.yaml")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Skipf("this file system does not allow a colon in a file name: %v", err)
	}

	t.Run("a resource", func(t *testing.T) {
		root := t.TempDir()
		writeKustomizeFiles(t, root, map[string]string{
			"app/kustomization.yaml": "resources:\n- \"demo:v1.yaml\"\n",
			"app/demo:v1.yaml":       demoDeployment,
		})
		app := filepath.Join(root, "app")
		require.Equal(t, originWrapper, originModeFor(app).mode)
		byName, origins := renderedKustomizeWorkloads(t, app)
		assert.Equal(t, filepath.Join(app, "demo:v1.yaml"), origins[byName["Deployment/demo"].GetID()])
	})

	t.Run("a patch file", func(t *testing.T) {
		root := t.TempDir()
		writeKustomizeFiles(t, root, map[string]string{
			"base/kustomization.yaml":    "resources:\n- deployment.yaml\n",
			"base/deployment.yaml":       demoDeployment,
			"overlay/kustomization.yaml": "resources:\n- ../base\npatches:\n- path: \"replicas:v2.yaml\"\n",
			"overlay/replicas:v2.yaml":   "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\nspec:\n  replicas: 2\n",
		})
		overlay := filepath.Join(root, "overlay")
		require.Equal(t, originWrapper, originModeFor(overlay).mode)
		byName, origins := renderedKustomizeWorkloads(t, overlay)
		assert.Equal(t, filepath.Join(root, "base", "deployment.yaml"), origins[byName["Deployment/demo"].GetID()])
	})

	t.Run("a base is still taken for Git shorthand", func(t *testing.T) {
		app := t.TempDir()
		writeKustomizeFiles(t, app, map[string]string{
			"kustomization.yaml":             "resources:\n- \"gh:org/repo\"\n",
			"gh:org/repo/kustomization.yaml": "resources:\n- deployment.yaml\n",
			"gh:org/repo/deployment.yaml":    demoDeployment,
		})
		assert.Equal(t, originUnavailable, originModeFor(app).mode)
	})

	t.Run("an invalid local file named like Git shorthand is still rejected", func(t *testing.T) {
		app := t.TempDir()
		writeKustomizeFiles(t, app, map[string]string{
			"kustomization.yaml": "resources:\n- \"gh:org/repo\"\n",
			// Missing metadata.name: Kustomize's accumulateFile rejects it and
			// falls back to loader.New, which treats gh:org/repo as Git shorthand.
			"gh:org/repo": "{kind: Deployment}\n",
		})
		assert.Equal(t, originUnavailable, originModeFor(app).mode)
	})

	t.Run("a remote http patch URL is rejected", func(t *testing.T) {
		app := t.TempDir()
		writeKustomizeFiles(t, app, map[string]string{
			"deployment.yaml":    demoDeployment,
			"kustomization.yaml": "resources:\n- deployment.yaml\npatches:\n- path: https://example.com/patch.yaml\n  target:\n    kind: Deployment\n",
		})
		assert.Equal(t, originUnavailable, originModeFor(app).mode)
	})
}

// Kustomize reads a patchesStrategicMerge entry as patch content first, and as
// a file name only when it is not, so a patch on one line is content.
func TestKustomizeOriginForAOneLineStrategicMergePatch(t *testing.T) {
	t.Run("a spec-only patch on one line keeps attribution", func(t *testing.T) {
		root := t.TempDir()
		writeKustomizeFiles(t, root, map[string]string{
			"base/kustomization.yaml": "resources:\n- deployment.yaml\n",
			"base/deployment.yaml":    demoDeployment,
			"overlay/kustomization.yaml": `resources:
- ../base
patchesStrategicMerge:
- '{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "demo"}, "spec": {"replicas": 2}}'
`,
		})
		overlay := filepath.Join(root, "overlay")
		require.Equal(t, originWrapper, originModeFor(overlay).mode)
		byName, origins := renderedKustomizeWorkloads(t, overlay)
		assert.Equal(t, filepath.Join(root, "base", "deployment.yaml"), origins[byName["Deployment/demo"].GetID()])
	})

	t.Run("a one-line inline patch modifying metadata suppresses attribution", func(t *testing.T) {
		app := t.TempDir()
		writeKustomizeFiles(t, app, map[string]string{
			"deployment.yaml": demoDeployment,
			"kustomization.yaml": `resources:
- deployment.yaml
patchesStrategicMerge:
- '{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "demo", "labels": {"a": "b"}}}'
`,
		})
		assert.Equal(t, originUnavailable, originModeFor(app).mode)
	})

	t.Run("a one-line map rejected by Kustomize inline parse is inspected as a file path", func(t *testing.T) {
		app := t.TempDir()
		patchName := "{kind: Deployment}"
		if err := os.WriteFile(filepath.Join(app, patchName), []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
  annotations:
    config.kubernetes.io/origin: |
      path: service.yaml
`), 0o600); err != nil {
			t.Skipf("this file system does not allow %q as a file name: %v", patchName, err)
		}
		writeKustomizeFiles(t, app, map[string]string{
			"deployment.yaml": demoDeployment,
			"service.yaml":    "apiVersion: v1\nkind: Service\nmetadata:\n  name: demo\n",
			"kustomization.yaml": `resources:
- deployment.yaml
- service.yaml
buildMetadata: [originAnnotations]
patchesStrategicMerge:
- '{kind: Deployment}'
`,
		})

		require.Equal(t, originUnavailable, originModeFor(app).mode)
		byName, origins := renderedKustomizeWorkloads(t, app)
		require.Equal(t, "service.yaml", takeOriginPath(byName["Deployment/demo"].GetObject(), false),
			"Kustomize rejected the inline parse and loaded the patch file of that name")
		assert.Empty(t, origins)
	})
}

func TestStrategicMergeEntry(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		want  types.Patch
	}{
		{"a file name", "replicas.yaml", types.Patch{Path: "replicas.yaml"}},
		{"a file name with a colon", "replicas:v2.yaml", types.Patch{Path: "replicas:v2.yaml"}},
		{"a map without metadata.name is a file name", "{kind: Deployment}", types.Patch{Path: "{kind: Deployment}"}},
		{"a patch on one line", `{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "demo"}}`,
			types.Patch{Patch: `{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "demo"}}`}},
		{"a patch on several lines", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n",
			types.Patch{Patch: "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, strategicMergeEntry(tt.entry))
		})
	}
}

// changingDisk is the disk, with change run once, right after the build reads
// the file whose slash-separated path ends in trigger.
type changingDisk struct {
	filesys.FileSystem
	trigger string
	change  func()
	changed bool
}

func (d *changingDisk) ReadFile(path string) ([]byte, error) {
	content, err := d.FileSystem.ReadFile(path)
	if !d.changed && strings.HasSuffix(filepath.ToSlash(path), d.trigger) {
		d.changed = true
		d.change()
	}
	return content, err
}

// changeDuringBuild makes the next plain build run change once it has read
// trigger, and reports whether it did.
func changeDuringBuild(t *testing.T, trigger string, change func()) *changingDisk {
	t.Helper()
	disk := &changingDisk{FileSystem: filesys.MakeFsOnDisk(), trigger: trigger, change: change}
	original := kustomizeDisk
	t.Cleanup(func() { kustomizeDisk = original })
	kustomizeDisk = func() filesys.FileSystem { return disk }
	return disk
}

// assertEachInItsFile checks that every attributed resource is in the file it
// is attributed to.
func assertEachInItsFile(t *testing.T, byName map[string]workloadinterface.IMetadata, origins map[string]string) {
	t.Helper()
	for kindAndName, workload := range byName {
		file := origins[workload.GetID()]
		if file == "" {
			continue
		}
		content, err := os.ReadFile(file)
		require.NoError(t, err)
		objects, err := ReadFile(content, YAML_FILE_FORMAT)
		require.NoError(t, err)
		var found bool
		for _, obj := range objects {
			found = found || obj.GetKind()+"/"+obj.GetName() == kindAndName
		}
		assert.True(t, found, "%s is attributed to %s, which does not hold it", kindAndName, file)
	}
}

// The inspection and the builds read the disk at different times. A file that
// changes during the scan must not get a resource attributed to a file that
// does not hold it.
func TestKustomizeOriginWhenAFileChangesDuringTheBuild(t *testing.T) {
	const (
		service     = "apiVersion: v1\nkind: Service\nmetadata:\n  name: demo\n"
		harmless    = "- op: replace\n  path: /spec/replicas\n  value: 2\n"
		forging     = "- op: replace\n  path: /metadata/annotations/config.kubernetes.io~1origin\n  value: |\n    path: service.yaml\n"
		ownOrigins  = "buildMetadata: [originAnnotations]\n"
		patchedKust = "resources:\n- deployment.yaml\n- service.yaml\n" + ownOrigins +
			"patches:\n- path: patch.yaml\n  target:\n    kind: Deployment\n"
	)

	patchTests := []struct {
		name          string
		before, after string
		trigger       string
	}{
		// The build reads the patch after the change.
		{"a patch file rewritten to forge the origin", harmless, forging, "/deployment.yaml"},
		// The build reads the patch before the change.
		{"a forging patch file made harmless", forging, harmless, "/patch.yaml"},
	}
	for _, tt := range patchTests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeKustomizeFiles(t, dir, map[string]string{
				"deployment.yaml":    demoDeployment,
				"service.yaml":       service,
				"patch.yaml":         tt.before,
				"kustomization.yaml": patchedKust,
			})
			disk := changeDuringBuild(t, tt.trigger, func() {
				writeKustomizeFiles(t, dir, map[string]string{"patch.yaml": tt.after})
			})

			byName, origins := renderedKustomizeWorkloads(t, dir)
			require.True(t, disk.changed)
			require.Equal(t, "service.yaml", takeOriginPath(byName["Deployment/demo"].GetObject(), false),
				"the build applied the forging patch")
			assertEachInItsFile(t, byName, origins)
		})
	}

	linkTests := []struct {
		name          string
		buildMetadata string
		trigger       string
		built         string
	}{
		// The build follows the link after the change.
		{"a base link pointed elsewhere before the build follows it, through the wrapper", "", "/app/kustomization.yaml", "ConfigMap/other"},
		{"a base link pointed elsewhere before the build follows it, with the kustomization's own origins", ownOrigins, "/app/kustomization.yaml", "ConfigMap/other"},
		// The build has read the base when the link changes.
		{"a base link pointed elsewhere after the build read the base, through the wrapper", "", "/common/deployment.yaml", "Deployment/demo"},
		{"a base link pointed elsewhere after the build read the base, with the kustomization's own origins", ownOrigins, "/common/deployment.yaml", "Deployment/demo"},
	}
	for _, tt := range linkTests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeKustomizeFiles(t, root, map[string]string{
				"app/kustomization.yaml":           "resources:\n- base-link\n" + tt.buildMetadata,
				"shared/base/kustomization.yaml":   "resources:\n- ../common\n",
				"shared/common/kustomization.yaml": "resources:\n- deployment.yaml\n",
				"shared/common/deployment.yaml":    demoDeployment,
				"other/base/kustomization.yaml":    "resources:\n- ../common\n",
				"other/common/kustomization.yaml":  "resources:\n- deployment.yaml\n",
				"other/common/deployment.yaml":     "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: other\n",
			})
			link := filepath.Join(root, "app", "base-link")
			if err := os.Symlink(filepath.Join("..", "shared", "base"), link); err != nil {
				t.Skipf("symlinks are unavailable: %v", err)
			}
			disk := changeDuringBuild(t, tt.trigger, func() {
				require.NoError(t, os.Remove(link))
				require.NoError(t, os.Symlink(filepath.Join("..", "other", "base"), link))
			})

			byName, origins := renderedKustomizeWorkloads(t, filepath.Join(root, "app"))
			require.True(t, disk.changed)
			require.Len(t, byName, 1)
			require.Contains(t, byName, tt.built)
			assertEachInItsFile(t, byName, origins)
		})
	}

	t.Run("a resource's content changing keeps the files", func(t *testing.T) {
		dir := t.TempDir()
		writeKustomizeFiles(t, dir, map[string]string{
			"deployment.yaml":    demoDeployment,
			"service.yaml":       service,
			"kustomization.yaml": "resources:\n- deployment.yaml\n- service.yaml\n" + ownOrigins,
		})
		disk := changeDuringBuild(t, "/deployment.yaml", func() {
			writeKustomizeFiles(t, dir, map[string]string{
				"deployment.yaml": strings.Replace(demoDeployment, "replicas: 1", "replicas: 3", 1),
			})
		})

		byName, origins := renderedKustomizeWorkloads(t, dir)
		require.True(t, disk.changed)
		assert.Equal(t, filepath.Join(dir, "deployment.yaml"), origins[byName["Deployment/demo"].GetID()])
		assert.Equal(t, filepath.Join(dir, "service.yaml"), origins[byName["Service/demo"].GetID()])
	})
}
