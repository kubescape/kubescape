package cautils

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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

	workloads, _, err := LoadResourcesFromFiles(context.Background(), missing, missing, nil)

	require.Error(t, err)
	assert.Nil(t, workloads)
	assert.ErrorIs(t, err, ErrNoManifestFiles)
	assert.Contains(t, err.Error(), "no YAML or JSON manifest files")
	// The error formats the input with %q, which escapes the separators in a
	// Windows path, so the raw path is not a substring of it.
	assert.Contains(t, err.Error(), strconv.Quote(missing))
}

func TestLoadResourcesFromFilesReturnsErrorForEmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	workloads, _, err := LoadResourcesFromFiles(context.Background(), dir, dir, nil)

	require.Error(t, err)
	assert.Nil(t, workloads)
	assert.ErrorIs(t, err, ErrNoManifestFiles)
	assert.Equal(t, "no YAML or JSON manifest files found for input "+strconv.Quote(dir), err.Error())
	assert.Contains(t, err.Error(), "no YAML or JSON manifest files")
}

func TestLoadResourcesFromFilesTerraformOnlyDirectoryKeepsPlainLoaderContract(t *testing.T) {
	dir := t.TempDir()
	writeManifestFixture(t, dir, "main.tf", `resource "null_resource" "example" {}`)

	workloads, skips, err := LoadResourcesFromFiles(context.Background(), dir, dir, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoManifestFiles)
	assert.Nil(t, workloads)
	assert.Empty(t, skips)
	assert.Equal(t, "no YAML or JSON manifest files found for input "+strconv.Quote(dir), err.Error())
}

func TestLoadResourcesFromFilesReturnsJSONParseErrorWithPath(t *testing.T) {
	dir := t.TempDir()
	broken := writeManifestFixture(t, dir, "broken.json", `{"apiVersion":`)

	workloads, skips, err := LoadResourcesFromFiles(context.Background(), broken, dir, nil)

	require.Error(t, err)
	assert.Empty(t, workloads)
	require.Len(t, skips, 1)
	assert.Equal(t, broken, skips[0].Path)
	assert.Contains(t, skips[0].Reason, "parse error")
	assert.Contains(t, err.Error(), strconv.Quote(broken))
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestLoadResourcesFromFilesReturnsYAMLDocumentNumber(t *testing.T) {
	dir := t.TempDir()
	manifest := validPodManifest + "---\nmetadata: [unterminated\n"
	path := writeManifestFixture(t, dir, "mixed.yaml", manifest)

	workloads, skips, err := LoadResourcesFromFiles(context.Background(), path, dir, nil)

	require.Error(t, err)
	require.Contains(t, workloads, path)
	assert.Len(t, workloads[path], 1, "valid documents should remain available for diagnostics")
	require.Len(t, skips, 1)
	assert.Equal(t, path, skips[0].Path)
	assert.Contains(t, skips[0].Reason, "document 2")
	assert.Contains(t, err.Error(), "document 2")
	assert.Contains(t, err.Error(), strconv.Quote(path))
}

func TestLoadResourcesFromFilesKeepsValidResourcesFromMixedDirectory(t *testing.T) {
	dir := t.TempDir()
	valid := writeManifestFixture(t, dir, "valid.yaml", validPodManifest)
	broken := writeManifestFixture(t, dir, "broken.yaml", "apiVersion: v1\nmetadata: [unterminated\n")

	workloads, skips, err := LoadResourcesFromFiles(context.Background(), dir, dir, nil)

	require.NoError(t, err)
	require.Contains(t, workloads, valid)
	assert.Len(t, workloads[valid], 1)
	assert.NotContains(t, workloads, broken)
	require.Len(t, skips, 1)
	assert.Equal(t, broken, skips[0].Path)
	assert.Contains(t, skips[0].Reason, "parse error")
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

	workloads, _, err := LoadResourcesFromFiles(context.Background(), dir, dir, nil)

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
	if err := os.Symlink("Chart.yaml", chartFile); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

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

// TestLoadResourcesFromNestedKustomizeDirectories_DiscoveryErrorDoesNotAbortScan
// pins that a directory discovery error (e.g. an unreadable subdirectory hit
// during the tree walk) is logged as a warning, matching
// loadResourcesFromHelmCharts, rather than failing the whole broad scan. A
// Kustomize directory discovered before the unreadable one was hit must still
// be rendered.
func TestLoadResourcesFromNestedKustomizeDirectories_DiscoveryErrorDoesNotAbortScan(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not enforced the same way on windows")
	}

	root := t.TempDir()

	// "app" sorts before "unreadable" lexically, so the walk records it
	// before hitting the permission error.
	appDir := filepath.Join(root, "app")
	require.NoError(t, os.MkdirAll(appDir, 0o750))
	writeManifestFixture(t, appDir, "kustomization.yaml", `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml
`)
	writeManifestFixture(t, appDir, "deployment.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      containers:
        - name: app
          image: nginx:1.27
`)

	unreadableDir := filepath.Join(root, "unreadable")
	require.NoError(t, os.MkdirAll(unreadableDir, 0o000))
	t.Cleanup(func() { _ = os.Chmod(unreadableDir, 0o750) })

	sourceToWorkloads, renderedDirs := LoadResourcesFromNestedKustomizeDirectories(context.Background(), root)

	assert.Contains(t, renderedDirs, appDir, "a directory discovered before the permission error must still be rendered")
	assert.NotEmpty(t, sourceToWorkloads, "the successfully rendered directory's workloads must still be returned")
}

func TestLoadResourcesFromFilesSurfacesNoKindYamlDocument(t *testing.T) {
	dir := t.TempDir()
	writeManifestFixture(t, dir, "valid.yaml", validPodManifest)
	noKind := writeManifestFixture(t, dir, "no-kind.yaml", "apiVersion: v1\nmetadata:\n  name: test\nspec:\n  containers: []\n")

	workloads, skips, err := LoadResourcesFromFiles(context.Background(), dir, dir, nil)

	require.NoError(t, err)
	require.Contains(t, workloads, filepath.Join(dir, "valid.yaml"))
	require.Len(t, skips, 1)
	assert.Equal(t, noKind, skips[0].Path)
	assert.Contains(t, skips[0].Reason, "not a valid Kubernetes object")
}

func TestLoadResourcesFromFilesSurfacesNoKindJsonFile(t *testing.T) {
	dir := t.TempDir()
	writeManifestFixture(t, dir, "valid.yaml", validPodManifest)
	noKind := writeManifestFixture(t, dir, "no-kind.json", `{"apiVersion":"v1","metadata":{"name":"test"},"spec":{"containers":[]}}`)

	workloads, skips, err := LoadResourcesFromFiles(context.Background(), dir, dir, nil)

	require.NoError(t, err)
	require.Contains(t, workloads, filepath.Join(dir, "valid.yaml"))
	require.Len(t, skips, 1)
	assert.Equal(t, noKind, skips[0].Path)
	assert.Contains(t, skips[0].Reason, "not a valid Kubernetes object")
}

func TestLoadResourcesFromFiles_LoadsCustomResourceWithoutSkip(t *testing.T) {
	dir := t.TempDir()
	cr := writeManifestFixture(t, dir, "certificate.yaml", `apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-cert
  namespace: default
spec:
  secretName: my-cert-tls
  dnsNames: [example.com]
  issuerRef: {name: letsencrypt, kind: ClusterIssuer}
`)

	workloads, skips, err := LoadResourcesFromFiles(context.Background(), dir, dir, nil)

	require.NoError(t, err)
	require.Contains(t, workloads, cr)
	assert.Len(t, workloads[cr], 1)
	assert.Empty(t, skips)
}

func TestLoadResourcesFromFiles_NoSkipsForValidDirectory(t *testing.T) {
	dir := t.TempDir()
	writeManifestFixture(t, dir, "valid.yaml", validPodManifest)

	workloads, skips, err := LoadResourcesFromFiles(context.Background(), dir, dir, nil)

	require.NoError(t, err)
	assert.NotEmpty(t, workloads)
	assert.Empty(t, skips)
}

func TestLoadResourcesFromFiles_IgnoresChartMetadata(t *testing.T) {
	dir := t.TempDir()
	writeManifestFixture(t, dir, "valid.yaml", validPodManifest)
	writeManifestFixture(t, dir, "Chart.yaml", "apiVersion: v2\nname: mychart\nversion: 0.1.0\n")
	writeManifestFixture(t, dir, "Chart.lock", "dependencies: []\ndigest: sha256:abc\n")
	writeManifestFixture(t, dir, "values.yaml", "{}\n")

	workloads, skips, err := LoadResourcesFromFiles(context.Background(), dir, dir, nil)

	require.NoError(t, err)
	require.Contains(t, workloads, filepath.Join(dir, "valid.yaml"))
	assert.Empty(t, skips, "Chart.yaml, Chart.lock and values.yaml must not be reported as skipped manifests")
}

// A manifest that merely contains Go-template syntax must not have its parse
// failure silenced: "{{" in the content is not evidence that a file is a Helm
// template, only its location below a chart's templates/ directory is.
const corruptManifestWithTemplateSyntax = `apiVersion: v1
kind: Pod
metadata:
  name: corrupt
  annotations:
    owner: "{{ .Values.owner }}"
spec: [unterminated
`

func TestLoadResourcesFromFilesReportsCorruptManifestContainingTemplateSyntax(t *testing.T) {
	dir := t.TempDir()
	corrupt := writeManifestFixture(t, dir, "corrupt.yaml", corruptManifestWithTemplateSyntax)

	workloads, skips, err := LoadResourcesFromFiles(context.Background(), corrupt, dir, nil)

	require.Error(t, err)
	assert.Empty(t, workloads)
	require.Len(t, skips, 1)
	assert.Equal(t, corrupt, skips[0].Path)
	assert.Contains(t, skips[0].Reason, "parse error")
	assert.Contains(t, err.Error(), strconv.Quote(corrupt))
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestLoadResourcesFromFilesKeepsValidResourcesWhenCorruptManifestContainsTemplateSyntax(t *testing.T) {
	dir := t.TempDir()
	valid := writeManifestFixture(t, dir, "valid.yaml", validPodManifest)
	corrupt := writeManifestFixture(t, dir, "corrupt.yaml", corruptManifestWithTemplateSyntax)

	workloads, skips, err := LoadResourcesFromFiles(context.Background(), dir, dir, nil)

	require.NoError(t, err)
	require.Contains(t, workloads, valid)
	assert.Len(t, workloads[valid], 1)
	assert.NotContains(t, workloads, corrupt)
	require.Len(t, skips, 1)
	assert.Equal(t, corrupt, skips[0].Path)
	assert.Contains(t, skips[0].Reason, "parse error")
}

// A "templates" directory whose parent holds no Chart.yaml is not a Helm
// chart, so a parse failure below it is plain manifest corruption.
func TestLoadResourcesFromFilesTreatsTemplateSyntaxOutsideChartsAsCorruption(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "templates"), 0o700))
	corrupt := writeManifestFixture(t, dir, filepath.Join("templates", "corrupt.yaml"), corruptManifestWithTemplateSyntax)

	workloads, skips, err := LoadResourcesFromFiles(context.Background(), corrupt, dir, nil)

	require.Error(t, err)
	assert.Empty(t, workloads)
	require.Len(t, skips, 1)
	assert.Equal(t, corrupt, skips[0].Path)
	assert.Contains(t, skips[0].Reason, "parse error")
}

// The plain-file fallback for a chart whose render failed must keep its drops
// visible: templated templates are recorded as unrendered Helm templates,
// while static siblings are still scanned.
func TestLoadResourcesFromFilesRecordsUnrenderedChartTemplatesAsSkips(t *testing.T) {
	testDir := helmChartLayoutPath()

	workloads, skips, err := LoadResourcesFromFiles(context.Background(), testDir, testDir, nil)

	require.NoError(t, err)
	staticTemplate := filepath.Join(testDir, "mychart", "templates", "serviceaccount.yaml")
	require.Contains(t, workloads, staticTemplate, "static templates must still be scanned when their chart did not render")

	require.Len(t, skips, 2)
	for _, skip := range skips {
		assert.True(t, strings.HasPrefix(skip.Reason, "unrendered Helm template"), "unexpected skip reason %q", skip.Reason)
		assert.Contains(t, skip.Path, filepath.Join("templates"), "templated files outside templates/ must not be classified as unrendered")
	}
}

func TestIsUnrenderedHelmTemplate(t *testing.T) {
	dir := t.TempDir()
	chart := filepath.Join(dir, "mychart")
	require.NoError(t, os.MkdirAll(filepath.Join(chart, "templates", "sub"), 0o700))
	writeManifestFixture(t, chart, "Chart.yaml", "apiVersion: v2\nname: mychart\nversion: 0.1.0\n")

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"chart template", filepath.Join(chart, "templates", "deployment.yaml"), true},
		{"nested chart template", filepath.Join(chart, "templates", "sub", "role.yaml"), true},
		{"templates directory without Chart.yaml", filepath.Join(dir, "templates", "deployment.yaml"), false},
		{"sibling sharing the templates prefix", filepath.Join(chart, "templates-docs", "deployment.yaml"), false},
		{"chart file outside templates", filepath.Join(chart, "values.yaml"), false},
		{"chart root itself", chart, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isUnrenderedHelmTemplate(tc.path))
		})
	}
}
