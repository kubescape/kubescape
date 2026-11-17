package cautils

import (
	"context"
	"errors"
	"os"
	"os/exec"
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

	charts, errs := listHelmChartDirs(dir, nil)

	assert.Contains(t, charts, validChart)
	require.NotEmpty(t, errs)
	assert.Contains(t, errors.Join(errs...).Error(), chartFile)
}

func TestHelmRenderedYAMLParseFailureFailsLoad(t *testing.T) {
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

	_, _, _, err = LoadResourcesFromHelmCharts(context.Background(), dir, HelmValueOptions{})
	require.ErrorIs(t, err, ErrHelmRenderFailed)
	assert.Contains(t, err.Error(), `chart "broken"`)
}

// writeUnloadableChart writes a chart under dir whose values.yaml is a YAML list,
// which Helm refuses to load, so it is never rendered.
func writeUnloadableChart(t *testing.T, dir string) {
	t.Helper()
	writeManifestFixture(t, dir, "Chart.yaml", "apiVersion: v2\nname: unloadable\nversion: 0.1.0\n")
	writeManifestFixture(t, dir, "values.yaml", "- a\n- b\n")
	templates := filepath.Join(dir, "templates")
	require.NoError(t, os.Mkdir(templates, 0o700))
	writeManifestFixture(t, templates, "sa.yaml", "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: sa\n")
}

func TestHelmChartLoadFailureFailsLoad(t *testing.T) {
	dir := t.TempDir()
	writeUnloadableChart(t, dir)
	_, loadErr := NewHelmChart(dir)
	require.Error(t, loadErr)

	_, _, _, err := LoadResourcesFromHelmCharts(context.Background(), dir, HelmValueOptions{})

	require.ErrorIs(t, err, ErrHelmLoadFailed)
	assert.Contains(t, err.Error(), strconv.Quote(dir), "the error names the chart")
	assert.Contains(t, err.Error(), loadErr.Error(), "the error carries the cause")
}

func TestNestedHelmChartLoadFailureIsSkipped(t *testing.T) {
	dir := t.TempDir()
	chartDir := filepath.Join(dir, "chart")
	require.NoError(t, os.Mkdir(chartDir, 0o700))
	writeUnloadableChart(t, chartDir)

	workloads, _, renderedCharts, err := LoadResourcesFromHelmCharts(context.Background(), dir, HelmValueOptions{})

	require.NoError(t, err, "a broken chart inside a broader scan must not fail the scan")
	assert.Empty(t, workloads)
	assert.Empty(t, renderedCharts)
}

func TestLoadResourcesFromKustomizeDirectoryPropagatesBuildFailure(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
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
	assert.ErrorIs(t, err, ErrManifestsNotLoaded)
}

func TestLoadResourcesFromKustomizeDirectoryMissingHelmIsFatal(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	dir := filepath.Join(kustomizeTestdataPath(), "helm")

	_, _, err := LoadResourcesFromKustomizeDirectory(context.Background(), dir)

	require.Error(t, err)
	var executableError *exec.Error
	require.ErrorAs(t, err, &executableError)
	assert.NotErrorIs(t, err, ErrManifestsNotLoaded)
}

func TestLoadResourcesFromKustomizeDirectoryUnstartableHelmIsFatal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a missing shebang interpreter is a Unix executable-start failure")
	}
	bin := t.TempDir()
	interpreter := filepath.Join(bin, "missing-interpreter")
	helmPath := filepath.Join(bin, "helm")
	require.NoError(t, os.WriteFile(helmPath, []byte("#!"+interpreter+"\n"), 0o600))
	require.NoError(t, os.Chmod(helmPath, 0o700))
	t.Setenv("PATH", bin)

	_, _, err := LoadResourcesFromKustomizeDirectory(context.Background(), filepath.Join(kustomizeTestdataPath(), "helm"))

	require.Error(t, err)
	var pathError *os.PathError
	require.ErrorAs(t, err, &pathError)
	assert.Equal(t, "fork/exec", pathError.Op)
	assert.NotErrorIs(t, err, ErrManifestsNotLoaded)
}

func TestLoadResourcesFromKustomizeDirectoryHelmErrors(t *testing.T) {
	for _, layout := range []string{"root", "component", "generator", "component generator", "symlink configuration", "inline generator", "symlink generator", "List generator", "inline List generator", "symlink configuration generator", "directory generator"} {
		for _, tc := range []struct {
			name        string
			version     string
			versionExit bool
			missing     bool
			recoverable bool
		}{
			{name: "missing Helm", missing: true},
			{name: "unsupported Helm", version: "v2.17.0"},
			{name: "invalid version output", version: "not a version"},
			{name: "version command failed", versionExit: true},
			{name: "Helm v3 template error", version: "v3.15.0", recoverable: true},
			{name: "Helm v4 template error", version: "v4.0.0", recoverable: true},
		} {
			t.Run(layout+"/"+tc.name, func(t *testing.T) {
				bin := t.TempDir()
				t.Setenv("PATH", bin)
				if !tc.missing {
					installHelmFailureCommand(t, bin, tc.version, tc.versionExit)
				}
				dir := t.TempDir()
				chartRoot := dir
				kind := "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
				if strings.Contains(layout, "component") {
					writeManifestFixture(t, dir, "kustomization.yaml", kind+"components: [component]\n")
					chartRoot = filepath.Join(dir, "component")
					require.NoError(t, os.Mkdir(chartRoot, 0o700))
					kind = "apiVersion: kustomize.config.k8s.io/v1alpha1\nkind: Component\n"
				}
				config := "helmCharts:\n- name: test-chart\n"
				if strings.Contains(layout, "generator") {
					generator := "apiVersion: builtin\nkind: HelmChartInflationGenerator\nmetadata:\n  name: chart\nname: test-chart\n"
					if strings.Contains(layout, "List") {
						generator = "apiVersion: v1\nkind: List\nitems:\n- " + strings.ReplaceAll(strings.TrimSuffix(generator, "\n"), "\n", "\n  ") + "\n"
					}
					if strings.Contains(layout, "inline") {
						config = "generators:\n- |\n    " + strings.ReplaceAll(strings.TrimSuffix(generator, "\n"), "\n", "\n    ") + "\n"
					} else if layout == "directory generator" {
						config = "generators: [generator-dir]\n"
						genDir := filepath.Join(chartRoot, "generator-dir")
						require.NoError(t, os.Mkdir(genDir, 0o700))
						writeManifestFixture(t, genDir, "kustomization.yaml", "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: [helm.yaml]\n")
						writeManifestFixture(t, genDir, "helm.yaml", generator)
					} else {
						config = "generators: [helm.yaml]\n"
						file := "helm.yaml"
						if layout == "symlink generator" {
							file = "actual-generator.yaml"
							if runtime.GOOS == "windows" {
								t.Skip("symlink creation requires privileges on Windows")
							}
							require.NoError(t, os.Symlink(file, filepath.Join(chartRoot, "helm.yaml")))
						}
						writeManifestFixture(t, chartRoot, file, generator)
					}
				}
				file := "kustomization.yaml"
				if strings.HasPrefix(layout, "symlink configuration") {
					file = "config.yaml"
					if strings.Contains(layout, "generator") {
						// Generators remain relative to chartRoot, not this target directory.
						require.NoError(t, os.Mkdir(filepath.Join(chartRoot, "configuration"), 0o700))
						file = filepath.Join("configuration", "config.yaml")
					}
					if runtime.GOOS == "windows" {
						t.Skip("symlink creation requires privileges on Windows")
					}
					require.NoError(t, os.Symlink(file, filepath.Join(chartRoot, "kustomization.yaml")))
				}
				writeManifestFixture(t, chartRoot, file, kind+config)
				chart := filepath.Join(chartRoot, "charts", "test-chart")
				require.NoError(t, os.MkdirAll(chart, 0o700))
				writeManifestFixture(t, chart, "Chart.yaml", "apiVersion: v2\nname: test-chart\nversion: 0.1.0\n")
				writeManifestFixture(t, chart, "values.yaml", "{}\n")

				_, _, err := LoadResourcesFromKustomizeDirectory(context.Background(), dir)

				require.Error(t, err)
				if tc.recoverable {
					assert.ErrorIs(t, err, ErrManifestsNotLoaded)
					assert.Contains(t, err.Error(), "invalid chart template")
				} else {
					assert.ErrorIs(t, err, ErrKustomizeHelmSetup)
					assert.NotErrorIs(t, err, ErrManifestsNotLoaded)
				}
			})
		}
	}
}

func TestLoadResourcesFromKustomizeDirectoryDoesNotProbeHelmForPlainResource(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	dir := t.TempDir()
	writeManifestFixture(t, dir, "kustomization.yaml", "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: [helm.yaml, invalid.yaml]\n")
	writeManifestFixture(t, dir, "helm.yaml", "apiVersion: builtin\nkind: HelmChartInflationGenerator\nmetadata:\n  name: plain-resource\n")
	writeManifestFixture(t, dir, "invalid.yaml", "kind: [unclosed\n")

	_, _, err := LoadResourcesFromKustomizeDirectory(context.Background(), dir)

	require.ErrorIs(t, err, ErrManifestsNotLoaded)
	assert.NotErrorIs(t, err, ErrKustomizeHelmSetup)
}

func TestLoadResourcesFromKustomizeDirectoryNonHelmMissingResourceStaysRecoverable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	dir := filepath.Join(t.TempDir(), "helm-charts", "app")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	writeManifestFixture(t, dir, "kustomization.yaml", "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: [helm-values.yaml]\n")

	_, _, err := LoadResourcesFromKustomizeDirectory(context.Background(), dir)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrManifestsNotLoaded)
	assert.NotErrorIs(t, err, ErrKustomizeHelmSetup)
}

// The version probe can succeed independently of rendering the chart.
func installHelmFailureCommand(t *testing.T, bin, version string, versionExit bool) {
	t.Helper()
	versionCommand := "echo " + version
	if versionExit {
		versionCommand = "exit 1"
	}
	name := "helm"
	script := "#!/bin/sh\nif [ \"$1\" = \"version\" ]; then\n  " + versionCommand + "\nelse\n  echo 'invalid chart template' >&2\n  exit 1\nfi\n"
	if runtime.GOOS == "windows" {
		name = "helm.bat"
		if versionExit {
			versionCommand = "exit /b 1"
		}
		script = "@echo off\r\nif \"%1\"==\"version\" (\r\n  " + versionCommand + "\r\n) else (\r\n  echo invalid chart template 1>&2\r\n  exit /b 1\r\n)\r\n"
	}
	path := filepath.Join(bin, name)
	require.NoError(t, os.WriteFile(path, []byte(script), 0o600))
	require.NoError(t, os.Chmod(path, 0o700))
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

// Every template of a chart whose render failed is recorded as skipped, static
// or not, while plain manifests and CRDs around it are still scanned.
func TestLoadResourcesFromFilesRecordsUnrenderedChartTemplatesAsSkips(t *testing.T) {
	testDir := helmChartLayoutPath()

	workloads, skips, err := LoadResourcesFromFiles(context.Background(), testDir, testDir, nil)

	require.NoError(t, err)
	assert.Contains(t, workloads, filepath.Join(testDir, "plain-pod.yaml"))
	assert.Contains(t, workloads, filepath.Join(testDir, "mychart", "crds", "widget.yaml"))
	assert.NotContains(t, workloads, filepath.Join(testDir, "mychart", "templates", "serviceaccount.yaml"))

	require.Len(t, skips, 8)
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

func TestLoadResourcesFromFilesSkipsHostSensorEnvelopeThatDoesNotDecode(t *testing.T) {
	dir := t.TempDir()
	writeManifestFixture(t, dir, "valid.yaml", validPodManifest)
	envelope := writeManifestFixture(t, dir, "host-data.yaml", "apiVersion: hostdata.kubescape.cloud/v1\nkind: OsReleaseFile\nmetadata: \"node-1\"\n")

	workloads, skips, err := LoadResourcesFromFiles(context.Background(), dir, dir, nil)

	require.NoError(t, err)
	require.Contains(t, workloads, filepath.Join(dir, "valid.yaml"))
	require.Len(t, skips, 1)
	assert.Equal(t, envelope, skips[0].Path)
	assert.Contains(t, skips[0].Reason, "not a valid Kubernetes object")
}

func TestLoadResourcesFromFilesSkipsCloudDescribeEnvelopeThatDoesNotDecode(t *testing.T) {
	dir := t.TempDir()
	writeManifestFixture(t, dir, "valid.yaml", validPodManifest)
	envelope := writeManifestFixture(t, dir, "cluster-describe.json", `{"apiVersion":"eks.amazonaws.com/v1","kind":"ClusterDescribe","metadata":{"name":"c"},"data":[]}`)

	workloads, skips, err := LoadResourcesFromFiles(context.Background(), dir, dir, nil)

	require.NoError(t, err)
	require.Contains(t, workloads, filepath.Join(dir, "valid.yaml"))
	require.Len(t, skips, 1)
	assert.Equal(t, envelope, skips[0].Path)
	assert.Contains(t, skips[0].Reason, "not a valid Kubernetes object")
}
