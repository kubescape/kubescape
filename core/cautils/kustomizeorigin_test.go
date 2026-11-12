package cautils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/kustomize/api/krusty"
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
