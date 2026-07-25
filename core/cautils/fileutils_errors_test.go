package cautils

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validPodManifest = `apiVersion: v1
kind: Pod
metadata:
  name: valid-pod
  namespace: default
spec:
  containers:
    - name: app
      image: nginx:latest
`

func writeManifestFixture(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func TestLoadResourcesFromFilesReturnsErrorForMissingInput(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	workloads, err := LoadResourcesFromFiles(context.Background(), missing, missing, nil)

	require.Error(t, err)
	assert.Nil(t, workloads)
	assert.Contains(t, err.Error(), "no YAML or JSON manifest files")
	assert.Contains(t, err.Error(), missing)
}

func TestLoadResourcesFromFilesReturnsErrorForEmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	workloads, err := LoadResourcesFromFiles(context.Background(), dir, dir, nil)

	require.Error(t, err)
	assert.Nil(t, workloads)
	assert.Contains(t, err.Error(), "no YAML or JSON manifest files")
}

func TestLoadResourcesFromFilesReturnsJSONParseErrorWithPath(t *testing.T) {
	dir := t.TempDir()
	broken := writeManifestFixture(t, dir, "broken.json", `{"apiVersion":`)

	workloads, err := LoadResourcesFromFiles(context.Background(), dir, dir, nil)

	require.Error(t, err)
	assert.Empty(t, workloads)
	assert.Contains(t, err.Error(), broken)
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestLoadResourcesFromFilesReturnsYAMLDocumentNumber(t *testing.T) {
	dir := t.TempDir()
	manifest := validPodManifest + "---\nmetadata: [unterminated\n"
	path := writeManifestFixture(t, dir, "mixed.yaml", manifest)

	workloads, err := LoadResourcesFromFiles(context.Background(), dir, dir, nil)

	require.Error(t, err)
	require.Contains(t, workloads, path)
	assert.Len(t, workloads[path], 1, "valid documents should remain available for diagnostics")
	assert.Contains(t, err.Error(), "document 2")
	assert.Contains(t, err.Error(), path)
}

func TestLoadResourcesFromFilesDoesNotHidePartialDirectoryFailure(t *testing.T) {
	dir := t.TempDir()
	valid := writeManifestFixture(t, dir, "valid.yaml", validPodManifest)
	broken := writeManifestFixture(t, dir, "broken.yaml", "apiVersion: v1\nmetadata: [unterminated\n")

	workloads, err := LoadResourcesFromFiles(context.Background(), dir, dir, nil)

	require.Error(t, err)
	require.Contains(t, workloads, valid)
	assert.Len(t, workloads[valid], 1)
	assert.Contains(t, err.Error(), broken)
}

func TestLoadResourcesFromKustomizeDirectoryPropagatesBuildFailure(t *testing.T) {
	dir := t.TempDir()
	writeManifestFixture(t, dir, "kustomization.yaml", `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - missing-deployment.yaml
`)

	workloads, name, err := LoadResourcesFromKustomizeDirectory(context.Background(), dir)

	require.Error(t, err)
	assert.Nil(t, workloads)
	assert.Equal(t, dir, name)
	assert.Contains(t, err.Error(), "failed to render Kustomize resources")
	assert.Contains(t, err.Error(), "missing-deployment.yaml")
}

func TestLoadResourcesFromKustomizeDirectoryNoopsForPlainDirectory(t *testing.T) {
	dir := t.TempDir()
	writeManifestFixture(t, dir, "pod.yaml", validPodManifest)

	workloads, name, err := LoadResourcesFromKustomizeDirectory(context.Background(), dir)

	require.NoError(t, err)
	assert.Nil(t, workloads)
	assert.Empty(t, name)
}
