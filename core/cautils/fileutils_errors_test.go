package cautils

import (
	"context"
	"errors"
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

	workloads, err := LoadResourcesFromFiles(context.Background(), broken, dir, nil)

	require.Error(t, err)
	assert.Empty(t, workloads)
	assert.Contains(t, err.Error(), broken)
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestLoadResourcesFromFilesReturnsYAMLDocumentNumber(t *testing.T) {
	dir := t.TempDir()
	manifest := validPodManifest + "---\nmetadata: [unterminated\n"
	path := writeManifestFixture(t, dir, "mixed.yaml", manifest)

	workloads, err := LoadResourcesFromFiles(context.Background(), path, dir, nil)

	require.Error(t, err)
	require.Contains(t, workloads, path)
	assert.Len(t, workloads[path], 1, "valid documents should remain available for diagnostics")
	assert.Contains(t, err.Error(), "document 2")
	assert.Contains(t, err.Error(), path)
}

func TestLoadResourcesFromFilesKeepsValidResourcesFromMixedDirectory(t *testing.T) {
	dir := t.TempDir()
	valid := writeManifestFixture(t, dir, "valid.yaml", validPodManifest)
	broken := writeManifestFixture(t, dir, "broken.yaml", "apiVersion: v1\nmetadata: [unterminated\n")

	workloads, err := LoadResourcesFromFiles(context.Background(), dir, dir, nil)

	require.NoError(t, err)
	require.Contains(t, workloads, valid)
	assert.Len(t, workloads[valid], 1)
	assert.NotContains(t, workloads, broken)
}

func TestLoadResourcesFromFilesKeepsFilesFoundBeforeDirectoryReadError(t *testing.T) {
	dir := t.TempDir()
	valid := writeManifestFixture(t, dir, "a-valid.yaml", validPodManifest)
	unreadable := filepath.Join(dir, "z-unreadable")
	require.NoError(t, os.Mkdir(unreadable, 0o700))
	writeManifestFixture(t, unreadable, "hidden.yaml", validPodManifest)
	require.NoError(t, os.Chmod(unreadable, 0))
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o700) })
	if _, err := os.ReadDir(unreadable); err == nil {
		t.Skip("filesystem permissions are not enforced for the test user")
	}

	workloads, err := LoadResourcesFromFiles(context.Background(), dir, dir, nil)

	require.NoError(t, err)
	require.Contains(t, workloads, valid)
	assert.Len(t, workloads[valid], 1)
}

func TestListHelmChartDirsReportsMetadataIOErrorsAndKeepsValidCharts(t *testing.T) {
	dir := t.TempDir()
	validChart := filepath.Join(dir, "a-valid")
	require.NoError(t, os.Mkdir(validChart, 0o700))
	writeManifestFixture(t, validChart, "Chart.yaml", "apiVersion: v2\nname: valid\nversion: 0.1.0\n")

	brokenChart := filepath.Join(dir, "z-broken")
	require.NoError(t, os.Mkdir(brokenChart, 0o700))
	chartFile := filepath.Join(brokenChart, "Chart.yaml")
	require.NoError(t, os.Symlink("Chart.yaml", chartFile))

	charts, errs := listHelmChartDirs(dir)

	assert.Contains(t, charts, validChart)
	require.NotEmpty(t, errs)
	assert.Contains(t, errors.Join(errs...).Error(), chartFile)
}

func TestHelmRenderedYAMLParseFailureMarksChartUnrendered(t *testing.T) {
	dir := t.TempDir()
	writeManifestFixture(t, dir, "Chart.yaml", "apiVersion: v2\nname: broken\nversion: 0.1.0\n")
	templates := filepath.Join(dir, "templates")
	require.NoError(t, os.Mkdir(templates, 0o700))
	writeManifestFixture(t, templates, "broken.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: [unterminated\n")

	chart, err := NewHelmChart(dir)
	require.NoError(t, err)
	workloads, renderErrs := chart.GetWorkloadsWithOptions(chart.GetDefaultValues(), HelmValueOptions{}.ReleaseOptions())

	assert.Empty(t, workloads)
	require.NotEmpty(t, renderErrs)
	assert.Contains(t, errors.Join(renderErrs...).Error(), "failed to parse rendered Helm template")

	_, _, renderedCharts, err := LoadResourcesFromHelmCharts(context.Background(), dir, HelmValueOptions{})
	require.NoError(t, err)
	assert.Empty(t, renderedCharts, "a chart with invalid rendered YAML must remain available to the plain-file fallback")
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
