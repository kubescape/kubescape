package cautils

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func onlineBoutiquePath() string {
	o, _ := os.Getwd()
	return filepath.Join(filepath.Dir(o), "..", "examples", "online-boutique")
}

func helmChartPath() string {
	o, _ := os.Getwd()
	return filepath.Join(filepath.Dir(o), "..", "examples", "helm_chart")
}

func TestListFiles(t *testing.T) {

	filesPath := onlineBoutiquePath()

	files, errs := listFiles(filesPath)
	assert.Equal(t, 0, len(errs))
	assert.Equal(t, 13, len(files))
}

func TestLoadResourcesFromFilesDoesNotSubstituteNestedBasenameForMissingExactPath(t *testing.T) {
	root := t.TempDir()
	nestedDir := filepath.Join(root, "nested")
	require.NoError(t, os.MkdirAll(nestedDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(nestedDir, "manifest.yaml"), []byte(`apiVersion: v1
kind: Pod
metadata:
  name: nested
`), 0o600))

	requestedPath := filepath.Join(root, "manifest.yaml")
	workloads, skipped, err := LoadResourcesFromFiles(context.Background(), requestedPath, root, nil)

	require.ErrorIs(t, err, ErrNoManifestFiles)
	assert.Empty(t, workloads)
	assert.Empty(t, skipped)

	workloads, _, err = LoadResourcesFromFiles(context.Background(), filepath.Join(root, "*.yaml"), root, nil)
	require.NoError(t, err)
	assert.Contains(t, workloads, filepath.Join(nestedDir, "manifest.yaml"), "explicit glob behavior must remain recursive")
}

func TestLoadResourcesFromFiles(t *testing.T) {
	workloads, _, err := LoadResourcesFromFiles(context.Background(), onlineBoutiquePath(), "", nil)
	require.NoError(t, err)
	assert.Equal(t, 12, len(workloads))

	for i, w := range workloads {
		switch filepath.Base(i) {
		case "adservice.yaml":
			assert.Equal(t, 2, len(w))
			assert.Equal(t, "apps/v1//Deployment/adservice", getRelativePath(w[0].GetID()))
			assert.Equal(t, "/v1//Service/adservice", getRelativePath(w[1].GetID()))
		}
	}
}

func TestLoadResourcesFromFiles_RejectsTrailingJSONInExplicitFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifests.json")
	data := []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"first"}}
{"apiVersion":"v1","kind":"Service","metadata":{"name":"second"}}`)
	require.NoError(t, os.WriteFile(path, data, 0o600))

	workloads, skipped, err := LoadResourcesFromFiles(context.Background(), path, filepath.Dir(path), nil)

	require.Error(t, err)
	assert.ErrorContains(t, err, "multiple top-level JSON values")
	assert.Empty(t, workloads)
	require.Len(t, skipped, 1)
	assert.Equal(t, path, skipped[0].Path)
}

func TestLoadResourcesFromFiles_SupportsMixedCaseExtensions(t *testing.T) {
	o, _ := os.Getwd()
	testDir := filepath.Join(o, "testdata", "mixed_extensions")
	workloads, _, err := LoadResourcesFromFiles(context.Background(), testDir, "", nil)
	require.NoError(t, err)
	assert.Equal(t, 2, len(workloads))

	expectedFiles := []string{
		filepath.Join(testDir, "pod.yaml"),
		filepath.Join(testDir, "service.YAML"),
	}

	for _, ef := range expectedFiles {
		_, ok := workloads[ef]
		assert.True(t, ok, "Expected workload for file %s", ef)
	}
}

// helmChartLayoutPath returns the fixture holding a chart with templates, crds and a subchart.
func helmChartLayoutPath() string {
	o, _ := os.Getwd()
	return filepath.Join(o, "testdata", "helm_chart_layout")
}

// TestLoadResourcesFromFiles_SkipsHelmTemplates asserts that, for a chart the render covered, the
// plain-YAML loader leaves the templates to the helm render and keeps loading the rest of the chart.
func TestLoadResourcesFromFiles_SkipsHelmTemplates(t *testing.T) {
	testDir := helmChartLayoutPath()
	renderedCharts := []string{
		filepath.Join(testDir, "mychart"),
		filepath.Join(testDir, "mychart", "charts", "mysubchart"),
	}
	workloads, _, err := LoadResourcesFromFiles(context.Background(), testDir, testDir, renderedCharts)
	require.NoError(t, err)

	expectedFiles := []string{
		filepath.Join(testDir, "plain-pod.yaml"),
		filepath.Join(testDir, "mychart", "crds", "widget.yaml"),
	}
	for _, ef := range expectedFiles {
		_, ok := workloads[ef]
		assert.Truef(t, ok, "expected workload for file %s", ef)
	}
	assert.Equal(t, len(expectedFiles), len(workloads))
}

// TestLoadResourcesFromFiles_SkipsHelmTemplatesOfScannedChart asserts that scanning a chart
// directly skips its templates too, since charts are detected recursively rather than at the input.
func TestLoadResourcesFromFiles_SkipsHelmTemplatesOfScannedChart(t *testing.T) {
	testDir := filepath.Join(helmChartLayoutPath(), "mychart")
	renderedCharts := []string{testDir, filepath.Join(testDir, "charts", "mysubchart")}
	workloads, _, err := LoadResourcesFromFiles(context.Background(), testDir, testDir, renderedCharts)
	require.NoError(t, err)

	expectedFile := filepath.Join(testDir, "crds", "widget.yaml")
	_, ok := workloads[expectedFile]
	assert.Truef(t, ok, "expected workload for file %s", expectedFile)
	assert.Equal(t, 1, len(workloads))
}

// TestLoadResourcesFromFiles_ScansTemplatesOfUnrenderedChart asserts the safety net: when a chart
// is absent from renderedCharts (its helm render failed), its templates are plainly scanned rather
// than dropped, so its static manifests still reach the scan.
func TestLoadResourcesFromFiles_ScansTemplatesOfUnrenderedChart(t *testing.T) {
	testDir := filepath.Join(helmChartLayoutPath(), "mychart")
	// no charts rendered successfully, so nothing may be excluded
	workloads, _, err := LoadResourcesFromFiles(context.Background(), testDir, testDir, nil)
	require.NoError(t, err)

	staticTemplate := filepath.Join(testDir, "templates", "serviceaccount.yaml")
	_, ok := workloads[staticTemplate]
	assert.Truef(t, ok, "expected the static template %s to be scanned when its chart did not render", staticTemplate)
}

// TestExcludeHelmTemplateFiles asserts that only the templates of a detected chart are excluded.
func TestExcludeHelmTemplateFiles(t *testing.T) {
	chart := filepath.Join("repo", "mychart")
	subchart := filepath.Join(chart, "charts", "mysubchart")
	helmDirectories := []string{chart, subchart}

	tests := []struct {
		name     string
		file     string
		excluded bool
	}{
		{
			name:     "chart template is excluded",
			file:     filepath.Join(chart, "templates", "deployment.yaml"),
			excluded: true,
		},
		{
			name:     "nested chart template is excluded",
			file:     filepath.Join(chart, "templates", "rbac", "role.yaml"),
			excluded: true,
		},
		{
			name:     "subchart template is excluded",
			file:     filepath.Join(subchart, "templates", "service.yaml"),
			excluded: true,
		},
		{
			name:     "crd is kept, helm does not render it",
			file:     filepath.Join(chart, "crds", "widget.yaml"),
			excluded: false,
		},
		{
			name:     "chart metadata is kept",
			file:     filepath.Join(chart, "values.yaml"),
			excluded: false,
		},
		{
			name:     "file outside a chart is kept",
			file:     filepath.Join("repo", "plain-pod.yaml"),
			excluded: false,
		},
		{
			name:     "directory sharing the templates prefix is kept",
			file:     filepath.Join(chart, "templates-docs", "example.yaml"),
			excluded: false,
		},
		{
			name:     "chart sharing a name prefix is kept",
			file:     filepath.Join("repo", "mychart-docs", "templates", "example.yaml"),
			excluded: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			remaining := excludeHelmTemplateFiles([]string{tt.file}, helmDirectories)
			if tt.excluded {
				assert.Empty(t, remaining)
			} else {
				assert.Equal(t, []string{tt.file}, remaining)
			}
		})
	}
}

// TestExcludeHelmTemplateFiles_NoCharts asserts that a scan without charts keeps every file.
func TestExcludeHelmTemplateFiles_NoCharts(t *testing.T) {
	files := []string{filepath.Join("repo", "templates", "pod.yaml")}
	assert.Equal(t, files, excludeHelmTemplateFiles(files, nil))
}

// TestExcludeHelmChartMetadataFiles asserts that the fixed Helm chart-metadata
// files are dropped by name while all other files survive, regardless of depth.
func TestExcludeHelmChartMetadataFiles(t *testing.T) {
	files := []string{
		filepath.Join("repo", "chart", "Chart.yaml"),
		filepath.Join("repo", "chart", "Chart.lock"),
		filepath.Join("repo", "chart", "values.yaml"),
		filepath.Join("repo", "chart", "templates", "deployment.yaml"),
		filepath.Join("repo", "chart-docs", "Chart.yaml.example"),
		filepath.Join("repo", "pod.yaml"),
	}
	remaining := excludeHelmChartMetadataFiles(files)
	assert.Equal(t, []string{
		filepath.Join("repo", "chart", "values.yaml"),
		filepath.Join("repo", "chart", "templates", "deployment.yaml"),
		filepath.Join("repo", "chart-docs", "Chart.yaml.example"),
		filepath.Join("repo", "pod.yaml"),
	}, remaining)
}

// TestIsUnderAnyDir asserts that containment is decided by canonical relative
// paths, not by string prefix equality: siblings that merely share a directory
// prefix must not be reported as contained, and a directory named "." must stay
// confined to its location (#2889).
func TestIsUnderAnyDir(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		dirs      []string
		contained bool
	}{
		{
			name:      "file directly inside directory",
			path:      "/repo/app/deployment.yaml",
			dirs:      []string{"/repo/app"},
			contained: true,
		},
		{
			name:      "file nested below directory",
			path:      "/repo/app/config/base/pod.yaml",
			dirs:      []string{"/repo/app"},
			contained: true,
		},
		{
			name:      "sibling sharing a prefix is outside",
			path:      "/repo/app-docs/deployment.yaml",
			dirs:      []string{"/repo/app"},
			contained: false,
		},
		{
			name:      "unrelated path is outside",
			path:      "/repo/other/pod.yaml",
			dirs:      []string{"/repo/app"},
			contained: false,
		},
		{
			name:      "every path is under the root directory",
			path:      "/repo/app/deployment.yaml",
			dirs:      []string{string(filepath.Separator)},
			contained: true,
		},
		{
			name:      "parent directory does not claim a sibling",
			path:      "/repo/app/deployment.yaml",
			dirs:      []string{"/repo"},
			contained: true,
		},
		{
			name:      "relative path is resolved against the working directory",
			path:      "app/deployment.yaml",
			dirs:      []string{"app"},
			contained: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.contained, IsUnderAnyDir(tt.path, tt.dirs))
		})
	}
}

// TestDirSetContains asserts that the ancestor walk decides containment exactly
// as the per-directory relative-path comparison it replaces, including for a
// sibling sharing a name prefix and for a directory absent from the set.
func TestDirSetContains(t *testing.T) {
	set := newDirSet([]string{"/repo/app", "/repo/charts/web/templates"})

	tests := []struct {
		name      string
		path      string
		contained bool
	}{
		{name: "the directory itself", path: "/repo/app", contained: true},
		{name: "file directly inside", path: "/repo/app/deployment.yaml", contained: true},
		{name: "file nested below", path: "/repo/app/config/base/pod.yaml", contained: true},
		{name: "second member of the set", path: "/repo/charts/web/templates/svc.yaml", contained: true},
		{name: "sibling sharing a prefix", path: "/repo/app-docs/deployment.yaml", contained: false},
		{name: "parent of a member", path: "/repo/charts/web/Chart.yaml", contained: false},
		{name: "unrelated path", path: "/other/pod.yaml", contained: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.contained, set.contains(tt.path))
		})
	}

	assert.False(t, newDirSet(nil).contains("/repo/app/deployment.yaml"), "an empty set contains nothing")
	assert.True(t, newDirSet([]string{string(filepath.Separator)}).contains("/repo/app/deployment.yaml"),
		"every absolute path is under the filesystem root")
}

// TestDirSetContains_UncleanDirs asserts that a member that is not lexically
// clean still claims the paths below it, matching the filepath.Rel comparison
// this lookup replaced, which cleaned its arguments itself.
func TestDirSetContains_UncleanDirs(t *testing.T) {
	for _, dir := range []string{"/repo/app/", "/repo/./app", "/repo//app", "/repo/other/../app"} {
		t.Run(dir, func(t *testing.T) {
			set := newDirSet([]string{dir})
			assert.True(t, set.contains("/repo/app/deployment.yaml"), "an unclean member must still claim files below it")
			assert.False(t, set.contains("/repo/app-docs/deployment.yaml"), "a prefix sibling stays outside")
		})
	}
}

// BenchmarkExcludeHelmTemplateFiles covers the repository-scan shape the lookup
// is built for: many files checked against many rendered chart directories.
func BenchmarkExcludeHelmTemplateFiles(b *testing.B) {
	root := b.TempDir()

	charts := make([]string, 0, 200)
	for i := range 200 {
		charts = append(charts, filepath.Join(root, "charts", strconv.Itoa(i)))
	}
	files := make([]string, 0, 2000)
	for i := range 2000 {
		files = append(files, filepath.Join(root, "manifests", strconv.Itoa(i), "deployment.yaml"))
	}

	b.ResetTimer()
	for range b.N {
		excludeHelmTemplateFiles(files, charts)
	}
}

// TestIsUnderAnyDir_CanonicalizesSymlinks asserts that a path reached through a
// symlinked parent is still reported contained when only the physical layout
// matches one of dirs.
func TestIsUnderAnyDir_CanonicalizesSymlinks(t *testing.T) {
	realParent := resolvedTempDir(t)
	dir := filepath.Join(realParent, "app")
	require.NoError(t, os.MkdirAll(dir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "deployment.yaml"), []byte("apiVersion: v1\n"), 0o600))

	linkedParent := filepath.Join(resolvedTempDir(t), "linked-parent")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	assert.True(t, IsUnderAnyDir(
		filepath.Join(linkedParent, "app", "deployment.yaml"), []string{dir},
	), "a symlinked copy of the directory must still be treated as contained")
}

func TestLoadResourcesFromHelmCharts(t *testing.T) {
	sourceToWorkloads, sourceToChartName, _, err := LoadResourcesFromHelmCharts(context.Background(), helmChartPath(), HelmValueOptions{})
	assert.NoError(t, err)
	assert.Equal(t, 6, len(sourceToWorkloads))

	for file, workloads := range sourceToWorkloads {

		assert.Equalf(t, 1, len(workloads), "expected 1 workload in file %s", file)

		w := workloads[0]
		assert.True(t, localworkload.IsTypeLocalWorkload(w.GetObject()), "Expected localworkload as object type")
		assert.Equal(t, "kubescape", sourceToChartName[file].Name)
		assert.Equal(t, helmChartPath(), sourceToChartName[file].Path)

		switch filepath.Base(file) {
		case "serviceaccount.yaml":
			assert.Equal(t, "/v1//ServiceAccount/kubescape-discovery", getRelativePath(w.GetID()))
		case "clusterrole.yaml":
			assert.Equal(t, "rbac.authorization.k8s.io/v1//ClusterRole/-kubescape", getRelativePath(w.GetID()))
		case "cronjob.yaml":
			assert.Equal(t, "batch/v1//CronJob/-kubescape", getRelativePath(w.GetID()))
		case "role.yaml":
			assert.Equal(t, "rbac.authorization.k8s.io/v1//Role/-kubescape", getRelativePath(w.GetID()))
		case "rolebinding.yaml":
			assert.Equal(t, "rbac.authorization.k8s.io/v1//RoleBinding/-kubescape", getRelativePath(w.GetID()))
		case "clusterrolebinding.yaml":
			assert.Equal(t, "rbac.authorization.k8s.io/v1//ClusterRoleBinding/-kubescape", getRelativePath(w.GetID()))
		default:
			assert.Failf(t, "missing case for file: %s", filepath.Base(file))
		}
	}
}

func writeTerraformFixture(t *testing.T, directory, resourceName string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(directory, 0o750))
	contents := `
resource "kubernetes_manifest" "` + resourceName + `" {
  manifest = {
    "apiVersion" = "v1"
    "kind"       = "ConfigMap"
    "metadata" = {
      "name"      = "` + resourceName + `"
      "namespace" = "default"
    }
  }
}
`
	require.NoError(t, os.WriteFile(filepath.Join(directory, "main.tf"), []byte(contents), 0o600))
}

// Regression for issue-3348: the Terraform loader used to only inspect the
// single directory it was pointed at, unlike the Helm/Kustomize loaders which
// both discover their configs recursively. A module living below the scan
// root (the extremely common modules/<name>/*.tf layout) was silently never
// scanned - no error, just 0 resources found for the top-level path.
func TestLoadResourcesFromTerraform_DiscoversNestedModuleDirectories(t *testing.T) {
	root := resolvedTempDir(t)
	writeTerraformFixture(t, filepath.Join(root, "modules", "foo"), "root-config")

	sourceToWorkloads, err := LoadResourcesFromTerraform(context.Background(), root)
	require.NoError(t, err)

	total := 0
	for _, wls := range sourceToWorkloads {
		total += len(wls)
	}
	require.Equal(t, 1, total, "resource defined only in modules/foo/main.tf must still be found when scanning the repo root")

	nestedFile := filepath.Join(root, "modules", "foo", "main.tf")
	require.Contains(t, sourceToWorkloads, nestedFile)
	assert.Equal(t, "root-config", sourceToWorkloads[nestedFile][0].GetName())
}

func TestLoadResourcesFromTerraform_MixedSuccessAndFailure(t *testing.T) {
	root := resolvedTempDir(t)
	writeTerraformFixture(t, filepath.Join(root, "modules", "good"), "good-config")

	// Create a malformed module
	badModuleDir := filepath.Join(root, "modules", "bad")
	require.NoError(t, os.MkdirAll(badModuleDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(badModuleDir, "main.tf"), []byte("this is not valid HCL"), 0o600))

	sourceToWorkloads, err := LoadResourcesFromTerraform(context.Background(), root)
	require.NoError(t, err, "a single bad module should not fail the whole scan")

	total := 0
	for _, wls := range sourceToWorkloads {
		total += len(wls)
	}
	require.Equal(t, 1, total, "the good module should still be discovered and rendered")

	goodFile := filepath.Join(root, "modules", "good", "main.tf")
	require.Contains(t, sourceToWorkloads, goodFile)
	assert.Equal(t, "good-config", sourceToWorkloads[goodFile][0].GetName())
}

// A directory with no .tf files anywhere must keep returning (nil, nil), the
// same "not a Terraform input" signal LoadResourcesFromTerraform always gave,
// so callers that branch on a nil map don't see a spurious behavior change.
func TestLoadResourcesFromTerraform_NoTerraformFilesReturnsNil(t *testing.T) {
	root := resolvedTempDir(t)
	require.NoError(t, os.WriteFile(filepath.Join(root, "not-terraform.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n"), 0o600))

	sourceToWorkloads, err := LoadResourcesFromTerraform(context.Background(), root)
	require.NoError(t, err)
	assert.Nil(t, sourceToWorkloads)
}

func writeHelmChartFixture(t *testing.T, directory, name string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(directory, "templates"), 0o750))
	writeManifestFixture(t, directory, "Chart.yaml", "apiVersion: v2\nname: "+name+"\nversion: 0.1.0\n")
	writeManifestFixture(t, directory, "values.yaml", "{}\n")
	writeManifestFixture(t, filepath.Join(directory, "templates"), "configmap.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: "+name+"\n")
}

func TestLoadResourcesFromHelmChartsExcludingKustomizeOwnedDirectories(t *testing.T) {
	root := resolvedTempDir(t)
	chartHome := filepath.Join(root, "charts")
	base := filepath.Join(root, "base")
	ownedChart := filepath.Join(base, "charts", "app")
	ownedSubchart := filepath.Join(ownedChart, "charts", "dependency")
	standaloneChart := filepath.Join(chartHome, "standalone")

	writeHelmChartFixture(t, ownedChart, "app")
	writeHelmChartFixture(t, ownedSubchart, "dependency")
	writeHelmChartFixture(t, standaloneChart, "standalone")
	writeManifestFixture(t, root, "kustomization.yaml", `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - base
`)
	writeManifestFixture(t, base, "kustomization.yaml", `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
helmCharts:
  - name: app
    releaseName: app
`)

	ownedDirectories, err := KustomizeHelmChartDirectories(context.Background(), root)
	require.NoError(t, err)
	require.Equal(t, []string{ownedChart, ownedSubchart}, ownedDirectories)

	standaloneTemplate := filepath.Join(standaloneChart, "templates", "configmap.yaml")
	remainingFiles := excludeHelmTemplateFiles([]string{
		filepath.Join(ownedChart, "templates", "configmap.yaml"),
		filepath.Join(ownedSubchart, "templates", "configmap.yaml"),
		standaloneTemplate,
	}, ownedDirectories)
	require.Equal(t, []string{standaloneTemplate}, remainingFiles)

	cwd, err := os.Getwd()
	require.NoError(t, err)
	relativeRoot, err := filepath.Rel(cwd, root)
	require.NoError(t, err)
	for _, tt := range []struct {
		name     string
		scanPath string
	}{
		{name: "absolute scan path", scanPath: root},
		{name: "relative scan path", scanPath: relativeRoot},
	} {
		t.Run(tt.name, func(t *testing.T) {
			workloads, charts, renderedDirectories, err := LoadResourcesFromHelmChartsExcludingDirectories(
				context.Background(), tt.scanPath, HelmValueOptions{}, ownedDirectories,
			)
			require.NoError(t, err)
			require.Equal(t, []string{standaloneChart}, renderedDirectories)
			require.Len(t, workloads, 1)
			require.Len(t, charts, 1)
			for source, sourceWorkloads := range workloads {
				require.Len(t, sourceWorkloads, 1)
				assert.Equal(t, "ConfigMap", sourceWorkloads[0].GetKind())
				assert.Equal(t, "standalone", sourceWorkloads[0].GetName())
				assert.Equal(t, standaloneChart, charts[source].Path)
			}
		})
	}
}

func TestLoadResourcesFromHelmChartsExcludingDirectories_CanonicalizesSymlinkedScanPath(t *testing.T) {
	realParent := resolvedTempDir(t)
	root := filepath.Join(realParent, "project")
	ownedChart := filepath.Join(root, "charts", "app")
	standaloneChart := filepath.Join(root, "charts", "standalone")
	writeHelmChartFixture(t, ownedChart, "app")
	writeHelmChartFixture(t, standaloneChart, "standalone")
	writeManifestFixture(t, root, "kustomization.yaml", `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
helmCharts:
  - name: app
    releaseName: app
`)

	linkedParent := filepath.Join(resolvedTempDir(t), "linked-parent")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	linkedRoot := filepath.Join(linkedParent, "project")
	ownedDirectories, err := KustomizeHelmChartDirectories(context.Background(), linkedRoot)
	require.NoError(t, err)
	require.Equal(t, []string{ownedChart}, ownedDirectories)

	workloads, _, renderedDirectories, err := LoadResourcesFromHelmChartsExcludingDirectories(
		context.Background(), linkedRoot, HelmValueOptions{}, ownedDirectories,
	)
	require.NoError(t, err)
	require.Equal(t, []string{filepath.Join(linkedRoot, "charts", "standalone")}, renderedDirectories)
	require.Len(t, workloads, 1)
	for _, sourceWorkloads := range workloads {
		require.Len(t, sourceWorkloads, 1)
		assert.Equal(t, "standalone", sourceWorkloads[0].GetName())
	}
}

func TestExcludeHelmTemplateFiles_PreservesLexicalOwnershipOfSymlinkedTemplate(t *testing.T) {
	root := resolvedTempDir(t)
	templateDir := filepath.Join(root, "chart", "templates")
	require.NoError(t, os.MkdirAll(templateDir, 0o750))

	externalTemplate := filepath.Join(resolvedTempDir(t), "configmap.yaml")
	require.NoError(t, os.WriteFile(externalTemplate, []byte("apiVersion: v1\nkind: ConfigMap\n"), 0o600))
	linkedTemplate := filepath.Join(templateDir, "configmap.yaml")
	if err := os.Symlink(externalTemplate, linkedTemplate); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	assert.Empty(t, excludeHelmTemplateFiles(
		[]string{linkedTemplate},
		[]string{filepath.Dir(templateDir)},
	), "Helm renders a template symlink by its lexical path below templates")
}

func TestLoadFiles(t *testing.T) {
	files, _ := listFiles(onlineBoutiquePath())
	_, _, errs := loadFiles("", files)
	assert.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "invalid.yaml")
}

func TestListDirs(t *testing.T) {
	dirs, _ := listDirs(filepath.Join(onlineBoutiquePath(), "adservice.yaml"))
	assert.Equal(t, 0, len(dirs))

	expectedDirs := []string{filepath.Join("examples", "helm_chart"), filepath.Join("examples", "helm_chart", "templates")}
	dirs, _ = listDirs(helmChartPath())
	assert.Equal(t, len(expectedDirs), len(dirs))
	for i := range expectedDirs {
		assert.Contains(t, dirs[i], expectedDirs[i])
	}
}

func TestLoadFile(t *testing.T) {
	files, _ := listFiles(filepath.Join(onlineBoutiquePath(), "adservice.yaml"))
	assert.Equal(t, 1, len(files))

	_, err := loadFile(files[0])
	assert.NoError(t, err)
}

func getRelativePath(p string) string {
	pp := strings.SplitAfter(p, "api=")
	return pp[1]
}

// Converts a YAML object to a JSON object
func TestConvertYamlToJson(t *testing.T) {
	tests := []struct {
		yamlObj map[any]any
		jsonObj map[string]any
	}{
		{
			yamlObj: map[any]any{
				"name": "John",
				"age":  30,
				"city": "New York",
			},
			jsonObj: map[string]any{
				"name": "John",
				"age":  30,
				"city": "New York",
			},
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			assert.Equal(t, tt.jsonObj, convertYamlToJson(tt.yamlObj))
		})
	}
}

// TestConvertYamlToJson_NestedNonStringKey guards against a nested mapping
// with a non-string key surviving conversion: yaml.v3 decodes such a mapping
// as map[interface{}]interface{} even under a string-keyed parent, and
// convertYamlToJson must recurse into map[string]any values so the result
// stays json.Marshal-able (issue #2833).
func TestConvertYamlToJson_NestedNonStringKey(t *testing.T) {
	input := map[string]any{"spec": map[any]any{"1": "enabled"}}

	got := convertYamlToJson(input)
	_, err := json.Marshal(got)
	require.NoError(t, err)

	spec, ok := got.(map[string]any)["spec"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "enabled", spec["1"])
}

// TestReadYamlFile_NestedNonStringKeyIsJSONMarshalable exercises the same bug
// through readYamlFile: a manifest with a nested non-string key must produce a
// workload whose object is JSON-serializable (OPA marshals these to build its
// input, so an unconverted map[interface{}]interface{} breaks evaluation).
func TestReadYamlFile_NestedNonStringKeyIsJSONMarshalable(t *testing.T) {
	manifest := []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test\ndata:\n  1: enabled\n")

	workloads, err := readYamlFile(manifest)
	require.NoError(t, err)
	require.Len(t, workloads, 1)

	_, err = json.Marshal(workloads[0].GetObject())
	assert.NoError(t, err)
}

func TestIsYaml(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{
			path: "temp.yaml",
			want: true,
		},
		{
			path: "temp.YAML",
			want: true,
		},
		{
			path: "temp.yml",
			want: true,
		},
		{
			path: "temp.Yml",
			want: true,
		},
		{
			path: "temp.Yaml",
			want: true,
		},
		{
			path: "temp.json",
			want: false,
		},
		{
			path: "temp.Json",
			want: false,
		},
		{
			path: "random.txt",
			want: false,
		},
		{
			path: "no-ext",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, IsYaml(tt.path))
		})
	}
}

func TestIsJson(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{
			path: "temp.yaml",
			want: false,
		},
		{
			path: "temp.yml",
			want: false,
		},
		{
			path: "temp.json",
			want: true,
		},
		{
			path: "temp.JSON",
			want: true,
		},
		{
			path: "temp.Json",
			want: true,
		},
		{
			path: "temp.Yaml",
			want: false,
		},
		{
			path: "random.txt",
			want: false,
		},
		{
			path: "no-ext",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, IsJson(tt.path))
		})
	}

}

func TestGetFileFormat(t *testing.T) {
	tests := []struct {
		path string
		want FileFormat
	}{
		{
			path: "temp.yaml",
			want: YAML_FILE_FORMAT,
		},
		{
			path: "temp.YAML",
			want: YAML_FILE_FORMAT,
		},
		{
			path: "temp.yml",
			want: YAML_FILE_FORMAT,
		},
		{
			path: "temp.Yml",
			want: YAML_FILE_FORMAT,
		},
		{
			path: "temp.Yaml",
			want: YAML_FILE_FORMAT,
		},
		{
			path: "temp.json",
			want: JSON_FILE_FORMAT,
		},
		{
			path: "temp.JSON",
			want: JSON_FILE_FORMAT,
		},
		{
			path: "temp.Json",
			want: JSON_FILE_FORMAT,
		},
		{
			path: "random.txt",
			want: "random.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, getFileFormat(tt.path))
		})
	}
}

func TestIsFileAndIsDir(t *testing.T) {
	tempDir := resolvedTempDir(t)
	tempFile := filepath.Join(tempDir, "test_file.txt")
	err := os.WriteFile(tempFile, []byte("test"), 0o600)
	require.NoError(t, err)

	assert.True(t, isDir(tempDir))
	assert.False(t, isFile(tempDir))

	assert.True(t, isFile(tempFile))
	assert.False(t, isDir(tempFile))

	missingPath := filepath.Join(tempDir, "missing-path")
	assert.False(t, isFile(missingPath))
	assert.False(t, isDir(missingPath))
}

func TestReadYamlFile(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantCount int
		wantErr   bool
	}{
		{
			name: "valid single Kubernetes object",
			content: `apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default`,
			wantCount: 1,
		},
		{
			name: "multi-document YAML with two valid objects",
			content: `apiVersion: v1
kind: Pod
metadata:
  name: pod-1
  namespace: default
---
apiVersion: v1
kind: Service
metadata:
  name: svc-1
  namespace: default`,
			wantCount: 2,
		},
		{
			name: "YAML list resource is expanded into items",
			content: `apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Pod
    metadata:
      name: pod-in-list
      namespace: default
  - apiVersion: v1
    kind: Service
    metadata:
      name: svc-in-list
      namespace: default`,
			wantCount: 2,
		},
		{
			name:      "empty content returns no objects",
			content:   "",
			wantCount: 0,
		},
		{
			name: "malformed YAML document is skipped",
			content: `apiVersion: v1
kind: Pod
metadata:
  name: good-pod
  namespace: default
---
{not: valid: yaml: [`,
			wantCount: 1, // the malformed doc is skipped, the good one is kept
			wantErr:   true,
		},
		{
			name:      "non-Kubernetes object (no kind) returns no results",
			content:   "foo: bar\nbaz: qux",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readYamlFile([]byte(tt.content))
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantCount, len(got))
		})
	}
}

func TestReadYamlFileValidatesAgainstScheme(t *testing.T) {
	tests := []struct {
		name          string
		content       string
		wantCount     int
		wantErrSubstr string
	}{
		{
			name: "valid Pod is accepted",
			content: `apiVersion: v1
kind: Pod
metadata:
  name: valid-pod
  namespace: default`,
			wantCount: 1,
		},
		{
			name: "valid custom resource is ignored",
			content: `apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: tls-cert
spec:
  secretName: tls-cert`,
			wantCount: 1,
		},
		{
			name: "wrong field type is surfaced",
			content: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad-deployment
spec:
  replicas: "not-a-number"`,
			wantCount:     1,
			wantErrSubstr: "structurally invalid",
		},
		{
			name: "typo'd kind in a built-in group is surfaced",
			content: `apiVersion: apps/v1
kind: Deplyment
metadata:
  name: typo-deployment`,
			wantCount:     1,
			wantErrSubstr: "is not a valid Kubernetes kind",
		},
		{
			name: "typo'd kind in the core group is surfaced",
			content: `apiVersion: v1
kind: Pods
metadata:
  name: typo-pod`,
			wantCount:     1,
			wantErrSubstr: "is not a valid Kubernetes kind",
		},
		{
			name: "known kind in a future apiVersion is ignored",
			content: `apiVersion: autoscaling/v99
kind: HorizontalPodAutoscaler
metadata:
  name: future-hpa
  namespace: default`,
			wantCount: 1,
		},
		{
			name: "removed-but-real kind is not flagged as a typo",
			content: `apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: legacy-psp
spec:
  privileged: false`,
			wantCount: 1,
		},
		{
			name: "invalid built-in kind inside a List is surfaced",
			content: `apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Pod
    metadata:
      name: good-pod
      namespace: default
  - apiVersion: apps/v1
    kind: Deplyment
    metadata:
      name: typo-deployment`,
			wantCount:     2,
			wantErrSubstr: "is not a valid Kubernetes kind",
		},
		{
			name: "valid List is accepted without errors",
			content: `apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Pod
    metadata:
      name: good-pod
      namespace: default
  - apiVersion: v1
    kind: Service
    metadata:
      name: good-svc
      namespace: default`,
			wantCount: 2,
		},
		{
			name: "non-manifest YAML without apiVersion is ignored",
			content: `foo: bar
baz: qux`,
			wantCount: 0,
		},
		{
			name: "multi-document manifest keeps valid docs and surfaces invalid ones",
			content: `apiVersion: v1
kind: Pod
metadata:
  name: good-pod
  namespace: default
---
apiVersion: apps/v1
kind: Deplyment
metadata:
  name: typo-deployment`,
			wantCount:     2,
			wantErrSubstr: "is not a valid Kubernetes kind",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readYamlFile([]byte(tt.content))
			if tt.wantErrSubstr != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErrSubstr)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantCount, len(got))
		})
	}
}

func TestReadJsonFile(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantCount int
		wantErr   bool
	}{
		{
			name: "valid single Kubernetes object",
			content: `{
				"apiVersion": "v1",
				"kind": "Pod",
				"metadata": {"name": "test-pod", "namespace": "default"}
			}`,
			wantCount: 1,
		},
		{
			name: "JSON array of Kubernetes objects",
			content: `[
				{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "pod-1", "namespace": "default"}},
				{"apiVersion": "v1", "kind": "Service", "metadata": {"name": "svc-1", "namespace": "default"}}
			]`,
			wantCount: 2,
		},
		{
			name:      "invalid JSON returns error",
			content:   `{not valid json`,
			wantCount: 0,
			wantErr:   true,
		},
		{
			name: "concatenated JSON objects are rejected instead of scanning only the first",
			content: `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"first"}}
				{"apiVersion":"v1","kind":"Service","metadata":{"name":"ignored-before-fix"}}`,
			wantCount: 0,
			wantErr:   true,
		},
		{
			name:      "valid manifest followed by malformed data is rejected",
			content:   `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"first"}} trailing`,
			wantCount: 0,
			wantErr:   true,
		},
		{
			name: "trailing whitespace remains valid",
			content: `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"whitespace"}}
				   `,
			wantCount: 1,
		},
		{
			name:      "empty JSON object (no kind) returns no workloads",
			content:   `{}`,
			wantCount: 0,
		},
		{
			name: "wrongly typed kind is an error, not a panic",
			content: `{
				"apiVersion": "v1",
				"kind": 123,
				"metadata": {"name": "test-pod", "namespace": "default"}
			}`,
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readJsonFile([]byte(tt.content))
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantCount, len(got))
		})
	}
}

func TestReadFileExpandsKubernetesListEnvelopes(t *testing.T) {
	tests := []struct {
		name      string
		read      func([]byte) ([]workloadinterface.IMetadata, error)
		content   string
		wantKinds []string
		wantAPIs  []string
	}{
		{
			name: "JSON generic List",
			read: readJsonFile,
			content: `{
				"apiVersion": "v1",
				"kind": "List",
				"items": [
					{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "pod-in-list", "namespace": "default"}},
					{"apiVersion": "v1", "kind": "Service", "metadata": {"name": "svc-in-list", "namespace": "default"}}
				]
			}`,
			wantKinds: []string{"Pod", "Service"},
			wantAPIs:  []string{"v1", "v1"},
		},
		{
			name: "JSON typed list inside an array",
			read: readJsonFile,
			content: `[
				{
					"apiVersion": "v1",
					"kind": "PodList",
					"items": [
						{"metadata": {"name": "pod-in-list", "namespace": "default"}}
					]
				},
				{"apiVersion": "v1", "kind": "Service", "metadata": {"name": "standalone-service", "namespace": "default"}}
			]`,
			wantKinds: []string{"Pod", "Service"},
			wantAPIs:  []string{"v1", "v1"},
		},
		{
			name: "YAML typed list inside a multi-document manifest",
			read: readYamlFile,
			content: `apiVersion: v1
kind: PodList
items:
  - apiVersion: v1
    kind: Pod
    metadata:
      name: pod-in-list
      namespace: default
---
apiVersion: v1
kind: Service
metadata:
  name: standalone-service
  namespace: default`,
			wantKinds: []string{"Pod", "Service"},
			wantAPIs:  []string{"v1", "v1"},
		},
		{
			name: "typed list fills a missing item kind",
			read: readJsonFile,
			content: `{
				"apiVersion": "v1",
				"kind": "PodList",
				"items": [
					{"apiVersion": "v1", "metadata": {"name": "missing-kind", "namespace": "default"}}
				]
			}`,
			wantKinds: []string{"Pod"},
			wantAPIs:  []string{"v1"},
		},
		{
			name: "typed list fills a missing item apiVersion",
			read: readYamlFile,
			content: `apiVersion: v1
kind: PodList
items:
  - kind: Pod
    metadata:
      name: missing-api-version
      namespace: default`,
			wantKinds: []string{"Pod"},
			wantAPIs:  []string{"v1"},
		},
		{
			name: "typed list preserves explicit item type metadata",
			read: readJsonFile,
			content: `{
				"apiVersion": "v1",
				"kind": "PodList",
				"items": [
					{"apiVersion": "example.com/v1", "kind": "Widget", "metadata": {"name": "explicit-type", "namespace": "default"}}
				]
			}`,
			wantKinds: []string{"Widget"},
			wantAPIs:  []string{"example.com/v1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.read([]byte(tt.content))
			require.NoError(t, err)
			require.Len(t, got, len(tt.wantKinds))
			for i, wantKind := range tt.wantKinds {
				assert.Equal(t, wantKind, got[i].GetKind())
				assert.Equal(t, tt.wantAPIs[i], got[i].GetApiVersion())
			}
		})
	}
}

func TestReadFileDoesNotTreatNamedCustomResourceAsListEnvelope(t *testing.T) {
	tests := []struct {
		name          string
		read          func([]byte) ([]workloadinterface.IMetadata, error)
		content       string
		identityField string
		identityValue string
	}{
		{
			name:          "JSON name",
			read:          readJsonFile,
			identityField: "name",
			identityValue: "production-allow-list",
			content: `{
				"apiVersion": "example.com/v1",
				"kind": "AllowList",
				"metadata": {"name": "production-allow-list"},
				"items": ["10.0.0.0/8"]
			}`,
		},
		{
			name:          "YAML generateName",
			read:          readYamlFile,
			identityField: "generateName",
			identityValue: "production-allow-list-",
			content: `apiVersion: example.com/v1
kind: AllowList
metadata:
  generateName: production-allow-list-
items:
  - 10.0.0.0/8`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.read([]byte(tt.content))
			require.NoError(t, err)
			require.Len(t, got, 1)
			assert.Equal(t, "AllowList", got[0].GetKind())
			metadata, ok := got[0].GetObject()["metadata"].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, tt.identityValue, metadata[tt.identityField])
		})
	}
}

func TestReadFileRejectsMalformedListEnvelope(t *testing.T) {
	tests := []struct {
		name    string
		read    func([]byte) ([]workloadinterface.IMetadata, error)
		content string
	}{
		{
			name:    "JSON generic List",
			read:    readJsonFile,
			content: `{"apiVersion":"v1","kind":"List","items":"not-an-array"}`,
		},
		{
			name:    "JSON typed list with null items",
			read:    readJsonFile,
			content: `{"apiVersion":"v1","kind":"PodList","items":null}`,
		},
		{
			name: "YAML typed list missing items",
			read: readYamlFile,
			content: `apiVersion: v1
kind: PodList`,
		},
		{
			name:    "JSON typed list with non-object item",
			read:    readJsonFile,
			content: `{"apiVersion":"v1","kind":"PodList","items":["not-an-object"]}`,
		},
		{
			name: "YAML generic List with non-Kubernetes item",
			read: readYamlFile,
			content: `apiVersion: v1
kind: List
items:
  - metadata:
      name: missing-kind`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.read([]byte(tt.content))
			assert.Error(t, err)
			assert.Empty(t, got)
		})
	}
}
