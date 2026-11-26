package cautils

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/pathcontainment"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/locationresolver"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	helmchartutil "helm.sh/helm/v3/pkg/chartutil"
)

type HelmChartTestSuite struct {
	suite.Suite
	helmChartPath         string
	expectedFiles         []string
	expectedDefaultValues map[string]any
}

func TestHelmChartTestSuite(t *testing.T) {
	suite.Run(t, new(HelmChartTestSuite))
}

func (s *HelmChartTestSuite) SetupSuite() {
	o, _ := os.Getwd()

	s.helmChartPath = filepath.Join(filepath.Dir(o), "..", "examples", "helm_chart")

	s.expectedFiles = []string{
		filepath.Join(s.helmChartPath, "templates", "clusterrolebinding.yaml"),
		filepath.Join(s.helmChartPath, "templates", "clusterrole.yaml"),
		filepath.Join(s.helmChartPath, "templates", "serviceaccount.yaml"),
		filepath.Join(s.helmChartPath, "templates", "rolebinding.yaml"),
		filepath.Join(s.helmChartPath, "templates", "role.yaml"),
		filepath.Join(s.helmChartPath, "templates", "cronjob.yaml"),
	}

	var obj any
	file, _ := os.ReadFile(filepath.Join("testdata", "helm_expected_default_values.json"))
	_ = json.Unmarshal([]byte(file), &obj)
	s.expectedDefaultValues = obj.(map[string]any)
}

func (s *HelmChartTestSuite) TestInvalidHelmDirectory() {
	_, err := NewHelmChart("/invalid_path")
	s.Error(err)
}

func (s *HelmChartTestSuite) TestValidHelmDirectory() {
	chart, err := NewHelmChart(s.helmChartPath)
	s.NoError(err)
	s.NotNil(chart)
}

func (s *HelmChartTestSuite) TestGetName() {
	chart, _ := NewHelmChart(s.helmChartPath)
	s.Equal("kubescape", chart.GetName())
}

func (s *HelmChartTestSuite) TestGetDefaultValues() {
	chart, _ := NewHelmChart(s.helmChartPath)

	values := chart.GetDefaultValues()

	valuesJson, _ := json.Marshal(values)
	expectedValuesJson, _ := json.Marshal(s.expectedDefaultValues)

	s.JSONEq(string(valuesJson), string(expectedValuesJson))
}

func (s *HelmChartTestSuite) TestGetWorkloadsWithOverride() {
	chart, err := NewHelmChart(s.helmChartPath)
	s.NoError(err, "Expected a valid helm chart")

	values := chart.GetDefaultValues()

	// Default pullPolicy value = Always
	pullPolicyValue := values["image"].(map[string]any)["pullPolicy"].(string)
	s.Equal(pullPolicyValue, "Always")

	// Override default value
	values["image"].(map[string]any)["pullPolicy"] = "Never"

	fileToWorkloads, errs := chart.GetWorkloads(values)
	s.Len(errs, 0)

	s.Lenf(fileToWorkloads, len(s.expectedFiles), "Expected %d files", len(s.expectedFiles))

	for _, expectedFile := range s.expectedFiles {
		s.Contains(fileToWorkloads, expectedFile)
		s.FileExists(expectedFile)
		s.GreaterOrEqualf(len(fileToWorkloads[expectedFile]), 1, "Expected at least one workload in %q", expectedFile)

		for i := range fileToWorkloads[expectedFile] {
			pathInWorkload := fileToWorkloads[expectedFile][i].(*localworkload.LocalWorkload).GetPath()
			// Every template in this chart uses "{{ include ... }}", so none of
			// them is static (see isStaticTemplate) and GetPath() must stay
			// index-free - the safe degradation, not a resolvable-but-possibly-
			// wrong line. TestGetWorkloadsWithOptions_StaticTemplateGetsIndex
			// covers the templated-and-static split this chart cannot exercise.
			s.Equal(expectedFile, pathInWorkload, "Expected GetPath() to return the bare path: every template here contains \"{{\", so none is provably safe to index")
		}

		if strings.Contains(expectedFile, "cronjob.yaml") {
			jsonBytes, _ := json.Marshal(fileToWorkloads[expectedFile][0].GetObject())
			s.Contains(string(jsonBytes), "\"imagePullPolicy\":\"Never\"", "Expected to overridden value of imagePullPolicy to be 'Never'")
		}
	}
}

func (s *HelmChartTestSuite) TestGetWorkloadsMissingValue() {
	chart, _ := NewHelmChart(s.helmChartPath)

	values := chart.GetDefaultValues()
	delete(values, "image")

	fileToWorkloads, errs := chart.GetWorkloads(values)
	s.Nil(fileToWorkloads)
	s.Len(errs, 1, "Expected an error due to missing value")

	expectedErrMsg := "<.Values.image.repository>: nil pointer"
	s.Containsf(errs[0].Error(), expectedErrMsg, "expected error containing %q, got %q", expectedErrMsg, errs[0])
}

// TestGetWorkloadsWithOptions_ReleaseName verifies that a custom release name passed via
// HelmReleaseName flows through to .Release.Name in the rendered manifests. The example
// chart's ClusterRoleBinding sets the subject namespace from .Release.Namespace, so we
// can use that to confirm the release options are honored.
func (s *HelmChartTestSuite) TestGetWorkloadsWithOptions_ReleaseName() {
	chart, err := NewHelmChart(s.helmChartPath)
	s.Require().NoError(err)

	releaseOpts := helmchartutil.ReleaseOptions{Name: "my-release", Namespace: "my-ns"}
	fileToWorkloads, errs := chart.GetWorkloadsWithOptions(chart.GetDefaultValues(), releaseOpts)
	s.Require().Len(errs, 0)

	crbPath := filepath.Join(s.helmChartPath, "templates", "clusterrolebinding.yaml")
	wls, ok := fileToWorkloads[crbPath]
	s.Require().True(ok, "ClusterRoleBinding should be rendered")
	s.Require().NotEmpty(wls)

	jsonBytes, _ := json.Marshal(wls[0].GetObject())
	s.Contains(string(jsonBytes), `"namespace":"my-ns"`, "release namespace should propagate to subject namespace")
}

// TestGetWorkloadsWithOptions_StaticTemplateGetsIndex is the regression matthyx's
// review asked for: a real chart render, not a hand-built session, proving the
// document index is only ever attached to a template proven static.
// testdata/helm_chart_layout/mychart carries all three shapes at once -
// templates/serviceaccount.yaml has no "{{" anywhere and must resolve to a
// line; templates/deployment.yaml uses ".Release.Name" and ".Values.*" and
// must not; its subchart's charts/mysubchart/templates/service.yaml templates
// too and must not, proving the check applies at every nesting depth, not
// just the parent chart's own templates/.
func (s *HelmChartTestSuite) TestGetWorkloadsWithOptions_StaticTemplateGetsIndex() {
	o, _ := os.Getwd()
	chartPath := filepath.Join(o, "testdata", "helm_chart_layout", "mychart")
	chart, err := NewHelmChart(chartPath)
	s.Require().NoError(err)

	fileToWorkloads, errs := chart.GetWorkloadsWithDefaultValues()
	s.Require().Len(errs, 0)

	staticPath := filepath.Join(chartPath, "templates", "serviceaccount.yaml")
	staticWls, ok := fileToWorkloads[staticPath]
	s.Require().True(ok, "static template should be rendered")
	s.Require().Len(staticWls, 1)
	s.Equal(staticPath+":0", staticWls[0].(*localworkload.LocalWorkload).GetPath(),
		"a template with no \"{{\" anywhere is unchanged by rendering, so its document index is safe to claim")

	templatedPath := filepath.Join(chartPath, "templates", "deployment.yaml")
	templatedWls, ok := fileToWorkloads[templatedPath]
	s.Require().True(ok, "templated file should still be rendered")
	s.Require().Len(templatedWls, 1)
	s.Equal(templatedPath, templatedWls[0].(*localworkload.LocalWorkload).GetPath(),
		"a template using \"{{ .Values }}\"/\"{{ .Release }}\" must keep the bare path: "+
			"the resolver would read the unrendered source, which is not valid YAML and "+
			"in general is not even the same document by the time it templates")

	subchartPath := filepath.Join(chartPath, "charts", "mysubchart", "templates", "service.yaml")
	subchartWls, ok := fileToWorkloads[subchartPath]
	s.Require().True(ok, "subchart template should still be rendered")
	s.Require().Len(subchartWls, 1)
	s.Equal(subchartPath, subchartWls[0].(*localworkload.LocalWorkload).GetPath(),
		"the static/templated check must apply to a subchart's templates too, not just the parent's")
}

// findWorkloadByName returns the workload named name from wls, failing the
// test if it is not present exactly once - the tests below rely on picking
// out a specific document's workload rather than assuming render order.
func findWorkloadByName(t *testing.T, wls []workloadinterface.IMetadata, name string) workloadinterface.IMetadata {
	t.Helper()
	var found workloadinterface.IMetadata
	for _, wl := range wls {
		if wl.GetName() == name {
			require.Nil(t, found, "expected exactly one workload named %q", name)
			found = wl
		}
	}
	require.NotNil(t, found, "expected a workload named %q", name)
	return found
}

// renderedChartWorkloads renders the layout fixture chart and returns the
// workloads for one of its templates.
func (s *HelmChartTestSuite) renderedChartWorkloads(template string) (string, []workloadinterface.IMetadata) {
	o, _ := os.Getwd()
	chartPath := filepath.Join(o, "testdata", "helm_chart_layout", "mychart")
	chart, err := NewHelmChart(chartPath)
	s.Require().NoError(err)

	fileToWorkloads, errs := chart.GetWorkloadsWithDefaultValues()
	s.Require().Len(errs, 0)

	path := filepath.Join(chartPath, "templates", template)
	wls, ok := fileToWorkloads[path]
	s.Require().Truef(ok, "%s should be rendered", template)
	return path, wls
}

// TestGetWorkloadsWithOptions_AlignedDocumentsGetOrdinalIndex is the positive
// case the two rules below carve exceptions out of: a static template whose
// documents are all plain single workloads, so each workload's raw document
// index and its workload ordinal are the same number and the suffix is
// correct however a consumer reads it. Resolving each one through
// locationresolver proves the index reaches that document and no other.
func (s *HelmChartTestSuite) TestGetWorkloadsWithOptions_AlignedDocumentsGetOrdinalIndex() {
	path, wls := s.renderedChartWorkloads("aligned-multidoc.yaml")
	s.Require().Len(wls, 3)

	resolver, err := locationresolver.NewPathLocationResolver(path)
	s.Require().NoError(err)

	// marker labels sit on lines 6, 13 and 20 of the fixture.
	for _, tc := range []struct {
		name  string
		index int
		line  int
	}{
		{"mychart-aligned-first", 0, 6},
		{"mychart-aligned-second", 1, 13},
		{"mychart-aligned-third", 2, 20},
	} {
		wl := findWorkloadByName(s.T(), wls, tc.name)
		s.Equal(fmt.Sprintf("%s:%d", path, tc.index), wl.(*localworkload.LocalWorkload).GetPath())

		location, err := resolver.ResolveLocation(".metadata.labels.marker", tc.index)
		s.Require().NoError(err)
		s.Equalf(tc.line, location.Line, "%s's marker label is on line %d", tc.name, tc.line)
	}
}

// TestGetWorkloadsWithOptions_SkippedDocumentLeavesPathsBare covers a static
// template whose first YAML document is empty (two consecutive "---"
// markers). readYamlFile drops that document, so both ConfigMaps sit one
// ordinal below their raw document index: mychart-static-a is raw document 1
// but workload 0, and mychart-static-b is raw document 2 but workload 1.
//
// There is no suffix that is right for both consumers here, which is why both
// paths stay bare. Emitting the raw index (this PR's second revision) makes
// SARIF remediation edit the wrong ConfigMap and puts the second one out of
// range of the compacted workload list; emitting the ordinal makes line
// resolution cite the preceding document. The assertions below resolve the
// raw indexes directly to pin that the two numberings really do disagree for
// this file, so the bare paths are a deliberate refusal rather than an
// accident of the fixture.
func (s *HelmChartTestSuite) TestGetWorkloadsWithOptions_SkippedDocumentLeavesPathsBare() {
	path, wls := s.renderedChartWorkloads("skipped-document.yaml")
	s.Require().Len(wls, 2, "the leading empty document must not become a phantom workload")

	for _, name := range []string{"mychart-static-a", "mychart-static-b"} {
		wl := findWorkloadByName(s.T(), wls, name)
		s.Equal(path, wl.(*localworkload.LocalWorkload).GetPath(),
			"a document dropped earlier in the file pushes raw index and workload ordinal apart, so neither is safe to write down")
	}

	resolver, err := locationresolver.NewPathLocationResolver(path)
	s.Require().NoError(err)

	locA, err := resolver.ResolveLocation(".metadata.labels.marker", 1)
	s.Require().NoError(err)
	s.Equal(8, locA.Line, "workload ordinal 0 is raw document 1, on line 8")

	locB, err := resolver.ResolveLocation(".metadata.labels.marker", 2)
	s.Require().NoError(err)
	s.Equal(15, locB.Line, "workload ordinal 1 is raw document 2, on line 15")
}

// TestGetWorkloadsWithOptions_ListEnvelopesStayUnindexed covers List
// envelopes, including the singleton ones matthyx's third review caught. A
// list's workloads are the objects under items[], while both consumers of the
// suffix address the document root - so the resolver would evaluate a
// resource's path against the wrapper (here the wrapper carries a deliberately
// conflicting "marker: wrapper" label, so a wrong answer would be visible
// rather than empty) and YAMLTreeEditor refuses a List wrapper outright.
//
// A one-item list is the interesting case: it produces exactly one workload,
// at an ordinal that does equal its raw document index, so it passes every
// other test and is only caught by classifying the document structurally.
func (s *HelmChartTestSuite) TestGetWorkloadsWithOptions_ListEnvelopesStayUnindexed() {
	for _, tc := range []struct {
		template string
		items    []string
	}{
		{"list-envelope.yaml", []string{"mychart-list-item-a", "mychart-list-item-b"}},
		{"singleton-list.yaml", []string{"mychart-singleton-list-item"}},
		{"singleton-podlist.yaml", []string{"mychart-singleton-podlist-item"}},
	} {
		path, wls := s.renderedChartWorkloads(tc.template)
		s.Require().Len(wls, len(tc.items))

		for _, name := range tc.items {
			wl := findWorkloadByName(s.T(), wls, name)
			s.Equalf(path, wl.(*localworkload.LocalWorkload).GetPath(),
				"%s: a List item lives under items[], not at the document root, so it may not claim the document's index", tc.template)
		}
	}
}

// TestHelmValueOptions_MergeValues exercises the helm-style value merger so we can be sure
// that --set / -f equivalents are parsed and merged the same way `helm install` would.
func TestHelmValueOptions_MergeValues(t *testing.T) {
	opts := HelmValueOptions{
		Values:       []string{"image.tag=v1.2.3", "replicaCount=5"},
		StringValues: []string{"image.repository=myrepo/app"},
	}
	merged, err := opts.MergeValues()
	assert.NoError(t, err)

	image, ok := merged["image"].(map[string]any)
	assert.True(t, ok, "expected image to be a nested map")
	assert.Equal(t, "v1.2.3", image["tag"])
	assert.Equal(t, "myrepo/app", image["repository"])
	assert.EqualValues(t, 5, merged["replicaCount"])

	t.Run("merges file values preserving protected path separators", func(t *testing.T) {
		tempDir := t.TempDir()
		valFile := filepath.Join(tempDir, "config.txt")
		err := os.WriteFile(valFile, []byte("custom-config-content"), 0600)
		assert.NoError(t, err)

		opts := HelmValueOptions{
			FileValues: []string{"custom=" + valFile},
		}
		merged, err := opts.MergeValues()
		assert.NoError(t, err)
		assert.Equal(t, "custom-config-content", merged["custom"])
	})

	t.Run("merges file values preserving key escapes and path separators", func(t *testing.T) {
		tempDir := t.TempDir()
		valFile := filepath.Join(tempDir, "config.txt")
		err := os.WriteFile(valFile, []byte("custom-config-content"), 0600)
		assert.NoError(t, err)

		opts := HelmValueOptions{
			FileValues: []string{`my\ key=` + valFile},
		}
		merged, err := opts.MergeValues()
		assert.NoError(t, err)
		assert.Equal(t, "custom-config-content", merged["my key"])
		assert.Nil(t, merged[`my\ key`])
	})
}

// TestLoadResourcesFromHelmCharts_WithOverrides confirms that user-supplied --set values
// are merged over chart defaults end-to-end via the public LoadResourcesFromHelmCharts entrypoint.
func TestLoadResourcesFromHelmCharts_WithOverrides(t *testing.T) {
	o, _ := os.Getwd()
	chartPath := filepath.Join(filepath.Dir(o), "..", "examples", "helm_chart")

	opts := HelmValueOptions{
		Values: []string{"image.pullPolicy=Never"},
	}
	sourceToWorkloads, _, _, err := LoadResourcesFromHelmCharts(context.Background(), chartPath, opts)
	assert.NoError(t, err)

	cronjobPath := filepath.Join(chartPath, "templates", "cronjob.yaml")
	wls, ok := sourceToWorkloads[cronjobPath]
	assert.True(t, ok, "cronjob should be rendered")
	assert.NotEmpty(t, wls)

	jsonBytes, _ := json.Marshal(wls[0].GetObject())
	assert.Contains(t, string(jsonBytes), `"imagePullPolicy":"Never"`, "user --set override should win over chart default")
}

// TestLoadResourcesFromHelmCharts_BadOverrideFailsFast verifies that an invalid user override
// (here: a -f path that does not exist) is reported as an error rather than silently swallowed
// and falling back to chart defaults. Scanning the wrong manifests would be worse than failing.
func TestLoadResourcesFromHelmCharts_BadOverrideFailsFast(t *testing.T) {
	o, _ := os.Getwd()
	chartPath := filepath.Join(filepath.Dir(o), "..", "examples", "helm_chart")

	opts := HelmValueOptions{
		ValueFiles: []string{"/nonexistent/values.yaml"},
	}
	_, _, _, err := LoadResourcesFromHelmCharts(context.Background(), chartPath, opts)
	assert.Error(t, err, "expected fail-fast on missing -f file")
	assert.Contains(t, err.Error(), "Helm value overrides")
}

// TestLoadResourcesFromHelmCharts_AttachesProvenance confirms that the
// helmprovenance package output is plumbed through LoadResourcesFromHelmCharts
// and lands on the per-source Chart entry. This is the wiring the fix command
// relies on to surface .Values guidance for Helm-rendered resources.
func TestLoadResourcesFromHelmCharts_AttachesProvenance(t *testing.T) {
	o, _ := os.Getwd()
	chartPath := filepath.Join(filepath.Dir(o), "..", "examples", "helm_chart")

	_, sourceToChart, _, err := LoadResourcesFromHelmCharts(context.TODO(), chartPath, HelmValueOptions{})
	assert.NoError(t, err)

	cronjobPath := filepath.Join(chartPath, "templates", "cronjob.yaml")
	c, ok := sourceToChart[cronjobPath]
	assert.True(t, ok, "expected provenance entry for cronjob.yaml")
	assert.Equal(t, "templates/cronjob.yaml", c.Provenance.TemplateFile)
	// cronjob.yaml uses .Values.schedule and .Values.image.* directly, plus
	// includes from _helpers.tpl that read .Values.nameOverride etc.
	assert.Contains(t, c.Provenance.ValuesPaths, "schedule")
	assert.Contains(t, c.Provenance.ValuesPaths, "image.repository")
	assert.Contains(t, c.Provenance.ValuesPaths, "image.tag")
	// Helper-derived ref should be folded in via include resolution.
	assert.Contains(t, c.Provenance.ValuesPaths, "nameOverride")
}

func TestMergeMaps_DeepMerge(t *testing.T) {
	base := map[string]any{
		"image": map[string]any{"repository": "base-repo", "tag": "default"},
		"keep":  "untouched",
	}
	override := map[string]any{
		"image": map[string]any{"tag": "overridden"},
		"new":   "added",
	}

	out := mergeMaps(base, override)

	img := out["image"].(map[string]any)
	assert.Equal(t, "base-repo", img["repository"], "non-overridden nested key should survive")
	assert.Equal(t, "overridden", img["tag"], "override should win on conflict")
	assert.Equal(t, "untouched", out["keep"])
	assert.Equal(t, "added", out["new"])

	// base should not be mutated by mergeMaps
	assert.Equal(t, "default", base["image"].(map[string]any)["tag"])
}

func (s *HelmChartTestSuite) TestIsHelmDirectory() {
	ok, err := IsHelmDirectory(s.helmChartPath)
	s.True(ok)
	s.NoError(err)

	o, _ := os.Getwd()
	nonHelmDir := filepath.Join(filepath.Dir(o), "../examples/online-boutique")
	ok, err = IsHelmDirectory(nonHelmDir)
	s.False(ok)
	s.Contains(err.Error(), "no Chart.yaml exists in directory")
}

func TestLoadResourcesFromHelmCharts_WorkspaceContainment(t *testing.T) {
	outsideDir := t.TempDir()
	outsideValues := filepath.Join(outsideDir, "values.yaml")
	require.NoError(t, os.WriteFile(outsideValues, []byte("replicaCount: 2\n"), 0o600))

	o, _ := os.Getwd()
	chartPath := filepath.Join(filepath.Dir(o), "..", "examples", "helm_chart")
	ws := filepath.Dir(chartPath)

	t.Run("values file outside workspace is rejected", func(t *testing.T) {
		valOpts := HelmValueOptions{ValueFiles: []string{outsideValues}}
		_, _, _, err := LoadResourcesFromHelmChartsFiltered(context.TODO(), chartPath, valOpts, nil, nil, ws)
		require.Error(t, err)
		assert.ErrorIs(t, err, pathcontainment.ErrPathEscapesWorkspace)
	})

	t.Run("file-values file outside workspace is rejected", func(t *testing.T) {
		valOpts := HelmValueOptions{FileValues: []string{"custom=" + outsideValues}}
		_, _, _, err := LoadResourcesFromHelmChartsFiltered(context.TODO(), chartPath, valOpts, nil, nil, ws)
		require.Error(t, err)
		assert.ErrorIs(t, err, pathcontainment.ErrPathEscapesWorkspace)
	})

	t.Run("file-values comma-separated with outside file is rejected", func(t *testing.T) {
		insideFile := filepath.Join(ws, "inside.yaml")
		require.NoError(t, os.WriteFile(insideFile, []byte("key: value\n"), 0o600))
		defer os.Remove(insideFile)

		valOpts := HelmValueOptions{FileValues: []string{"k1=" + insideFile + ",k2=" + outsideValues}}
		_, _, _, err := LoadResourcesFromHelmChartsFiltered(context.TODO(), chartPath, valOpts, nil, nil, ws)
		require.Error(t, err)
		assert.ErrorIs(t, err, pathcontainment.ErrPathEscapesWorkspace)
	})

	t.Run("file-values brace list with outside file is rejected", func(t *testing.T) {
		insideFile := filepath.Join(ws, "inside-brace.yaml")
		require.NoError(t, os.WriteFile(insideFile, []byte("key: value\n"), 0o600))
		defer os.Remove(insideFile)

		valOpts := HelmValueOptions{FileValues: []string{"custom={" + insideFile + "," + outsideValues + "}"}}
		_, _, _, err := LoadResourcesFromHelmChartsFiltered(context.TODO(), chartPath, valOpts, nil, nil, ws)
		require.Error(t, err)
		assert.ErrorIs(t, err, pathcontainment.ErrPathEscapesWorkspace)
	})

	t.Run("file-values exact path preserves whitespace and rejects outside symlink", func(t *testing.T) {
		insideFile := filepath.Join(ws, "val.yaml")
		require.NoError(t, os.WriteFile(insideFile, []byte("key: inside\n"), 0o600))
		defer os.Remove(insideFile)

		symlinkWithSpace := filepath.Join(ws, "val.yaml ")
		if err := os.Symlink(outsideValues, symlinkWithSpace); err == nil {
			defer os.Remove(symlinkWithSpace)
			valOpts := HelmValueOptions{FileValues: []string{"custom=" + symlinkWithSpace}}
			_, _, _, err := LoadResourcesFromHelmChartsFiltered(context.TODO(), chartPath, valOpts, nil, nil, ws)
			require.Error(t, err)
			assert.ErrorIs(t, err, pathcontainment.ErrPathEscapesWorkspace)
		}
	})

	t.Run("file-values empty subkey parse error is rejected", func(t *testing.T) {
		insideFile := filepath.Join(ws, "safe.yaml")
		require.NoError(t, os.WriteFile(insideFile, []byte("key: inside\n"), 0o600))
		defer os.Remove(insideFile)

		valOpts := HelmValueOptions{FileValues: []string{"a.=" + insideFile + ",b=" + outsideValues}}
		_, _, _, err := LoadResourcesFromHelmChartsFiltered(context.TODO(), chartPath, valOpts, nil, nil, ws)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed parsing --set-file data")
	})

	t.Run("file-values relative path escaping workspace is rejected", func(t *testing.T) {
		escapingRel := filepath.Join("..", "..", "outside.yaml")
		valOpts := HelmValueOptions{FileValues: []string{"custom=" + escapingRel}}
		_, _, _, err := LoadResourcesFromHelmChartsFiltered(context.TODO(), chartPath, valOpts, nil, nil, ws)
		require.Error(t, err)
		assert.ErrorIs(t, err, pathcontainment.ErrPathEscapesWorkspace)
	})

	t.Run("chart with escaping symlink is rejected", func(t *testing.T) {
		tempWS := t.TempDir()
		chartDir := filepath.Join(tempWS, "chart")
		require.NoError(t, os.MkdirAll(filepath.Join(chartDir, "templates"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte("apiVersion: v2\nname: testchart\nversion: 0.1.0\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(chartDir, "values.yaml"), []byte("{}\n"), 0o600))

		outsideFile := filepath.Join(outsideDir, "leak.yaml")
		require.NoError(t, os.WriteFile(outsideFile, []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: leak\n"), 0o600))

		leakSymlink := filepath.Join(chartDir, "templates", "leak.yaml")
		if err := os.Symlink(outsideFile, leakSymlink); err != nil {
			t.Skipf("skipping symlink test: %v", err)
		}

		_, _, _, err := LoadResourcesFromHelmChartsFiltered(context.TODO(), chartDir, HelmValueOptions{}, nil, nil, tempWS)
		require.Error(t, err)
		assert.ErrorIs(t, err, pathcontainment.ErrPathEscapesWorkspace)
	})
}

func TestReadHelmTemplateFile_OversizedFileRejected(t *testing.T) {
	t.Setenv(MaxFileSizeEnvVar, "") // empty falls back to DefaultMaxFileSize

	dir := t.TempDir()
	filePath := filepath.Join(dir, "template.yaml")
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(DefaultMaxFileSize+1))
	require.NoError(t, f.Close())

	_, err = readHelmTemplateFile(filePath)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrHelmTemplateTooLarge)
}

func TestReadHelmTemplateFile_NonRegularFileRejected(t *testing.T) {
	if _, err := os.Stat("/dev/null"); err == nil {
		_, err := readHelmTemplateFile("/dev/null")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHelmTemplateNotRegular)
	}
}

func TestReadHelmTemplateFile_DirectoryRejected(t *testing.T) {
	dir := t.TempDir()
	_, err := readHelmTemplateFile(dir)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrHelmTemplateNotRegular)
	assert.Contains(t, err.Error(), "is a directory, not a file")
}

func TestReadHelmTemplateFile_MaxFileSizeEnvVar(t *testing.T) {
	t.Run("lower override", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "100")

		dir := t.TempDir()
		overLimitFile := filepath.Join(dir, "template.yaml")
		require.NoError(t, os.WriteFile(overLimitFile, make([]byte, 200), 0o600))

		_, err := readHelmTemplateFile(overLimitFile)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHelmTemplateTooLarge)

		underLimitFile := filepath.Join(dir, "valid_template.yaml")
		require.NoError(t, os.WriteFile(underLimitFile, make([]byte, 50), 0o600))

		data, err := readHelmTemplateFile(underLimitFile)
		require.NoError(t, err)
		assert.Len(t, data, 50)
	})

	t.Run("higher override", func(t *testing.T) {
		raisedLimit := DefaultMaxFileSize + 1024
		t.Setenv(MaxFileSizeEnvVar, fmt.Sprintf("%d", raisedLimit))

		dir := t.TempDir()
		overDefaultFile := filepath.Join(dir, "template.yaml")
		f, err := os.OpenFile(overDefaultFile, os.O_CREATE|os.O_WRONLY, 0o600)
		require.NoError(t, err)
		require.NoError(t, f.Truncate(DefaultMaxFileSize+100))
		require.NoError(t, f.Close())

		data, err := readHelmTemplateFile(overDefaultFile)
		require.NoError(t, err)
		assert.Len(t, data, int(DefaultMaxFileSize+100))
	})
}

func TestIsStaticTemplate_OversizedFileTreatedAsNonStatic(t *testing.T) {
	t.Setenv(MaxFileSizeEnvVar, "") // empty falls back to DefaultMaxFileSize

	dir := t.TempDir()
	filePath := filepath.Join(dir, "oversized.yaml")
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(DefaultMaxFileSize+1))
	require.NoError(t, f.Close())

	static, err := isStaticTemplate(filePath)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrHelmTemplateTooLarge)
	assert.False(t, static)
}

func TestParseHelmFileValuePaths_WindowsPaths(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedPaths []string
		expectErr     bool
	}{
		{
			name:          "single Windows path with backslashes",
			input:         `valKey=C:\Users\runneradmin\AppData\Local\Temp\secret.txt`,
			expectedPaths: []string{`C:\Users\runneradmin\AppData\Local\Temp\secret.txt`},
		},
		{
			name:          "comma-separated Windows paths",
			input:         `k1=C:\dir\file1.txt,k2=C:\dir\file2.txt`,
			expectedPaths: []string{`C:\dir\file1.txt`, `C:\dir\file2.txt`},
		},
		{
			name:          "Windows path with escaped comma",
			input:         `custom=C:\dir\a\,b.txt`,
			expectedPaths: []string{`C:\dir\a,b.txt`},
		},
		{
			name:          "Windows path with trailing whitespace",
			input:         `custom=C:\dir\val.txt `,
			expectedPaths: []string{`C:\dir\val.txt `},
		},
		{
			name:          "Windows paths in brace list",
			input:         `custom={C:\dir\f1.txt,C:\dir\f2.txt}`,
			expectedPaths: []string{`C:\dir\f1.txt`, `C:\dir\f2.txt`},
		},
		{
			name:          "UNC Windows network path",
			input:         `unc=\\server\share\file.txt`,
			expectedPaths: []string{`\\server\share\file.txt`},
		},
		{
			name:          "Unix path without backslashes",
			input:         `k1=/ws/dir/file1.yaml,k2=/ws/dir/file2.yaml`,
			expectedPaths: []string{`/ws/dir/file1.yaml`, `/ws/dir/file2.yaml`},
		},
		{
			name:      "empty subkey parse error is rejected",
			input:     `a.=/ws/safe,b=C:\dir\report.txt`,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPaths []string
			err := ParseHelmFileValuePaths(tt.input, func(p string) error {
				gotPaths = append(gotPaths, p)
				return nil
			})
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedPaths, gotPaths)
			}
		})
	}
}

func TestProtectHelmPathSeparators(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "key escape with space is preserved",
			input:    `my\ key=/tmp/value`,
			expected: `my\ key=/tmp/value`,
		},
		{
			name:     "key escape with space and Windows value path",
			input:    `my\ key=C:\dir\file.txt`,
			expected: `my\ key=C:\\dir\\file.txt`,
		},
		{
			name:     "key escape with comma",
			input:    `my\,key=C:\dir\file.txt`,
			expected: `my\,key=C:\\dir\\file.txt`,
		},
		{
			name:     "key escape with equal",
			input:    `my\=key=C:\dir\file.txt`,
			expected: `my\=key=C:\\dir\\file.txt`,
		},
		{
			name:     "multiple comma-separated entries with key escapes and Windows paths",
			input:    `k1=C:\a\b.txt,k2\ key=C:\c\d.txt`,
			expected: `k1=C:\\a\\b.txt,k2\ key=C:\\c\\d.txt`,
		},
		{
			name:     "brace list with Windows paths and subsequent key escape",
			input:    `k1={C:\a\b.txt,C:\e\f.txt},k2\ key=C:\c\d.txt`,
			expected: `k1={C:\\a\\b.txt,C:\\e\\f.txt},k2\ key=C:\\c\\d.txt`,
		},
		{
			name:     "escaped comma in value is preserved",
			input:    `k1=C:\dir\a\,b.txt,k2=C:\dir\c.txt`,
			expected: `k1=C:\\dir\\a\,b.txt,k2=C:\\dir\\c.txt`,
		},
		{
			name:     "UNC network path",
			input:    `unc=\\server\share\file.txt`,
			expected: `unc=\\\\server\\share\\file.txt`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ProtectHelmPathSeparators(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func buildTestHelmArchiveBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o600,
			Size: int64(len(content)),
		}
		require.NoError(t, tw.WriteHeader(hdr))
		_, err := tw.Write(content)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	return buf.Bytes()
}

func buildTestHelmArchive(t *testing.T, files map[string]string) string {
	t.Helper()
	raw := make(map[string][]byte, len(files))
	for name, content := range files {
		raw[name] = []byte(content)
	}
	archivePath := filepath.Join(t.TempDir(), "test-chart-0.1.0.tgz")
	require.NoError(t, os.WriteFile(archivePath, buildTestHelmArchiveBytes(t, raw), 0o600))
	return archivePath
}

func TestNewHelmChart_BoundsAndIgnoreValidation(t *testing.T) {
	t.Run("oversized template rejected", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "256")
		dir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "templates"), 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte("apiVersion: v2\nname: app\nversion: 0.1.0\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "templates", "cm.yaml"), []byte(strings.Repeat("# pad\n", 60)), 0o600))

		_, err := NewHelmChart(dir)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHelmTemplateTooLarge)
	})

	t.Run("oversized helmignore rejected", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "64")
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte("apiVersion: v2\nname: app\nversion: 0.1.0\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".helmignore"), []byte(strings.Repeat("*.tmp\n", 20)), 0o600))

		_, err := NewHelmChart(dir)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHelmTemplateTooLarge)
	})

	t.Run("helmignore excluded oversized file allows valid chart", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "256")
		dir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "templates"), 0o750))
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "fixtures"), 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte("apiVersion: v2\nname: app\nversion: 0.1.0\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".helmignore"), []byte("fixtures/\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "templates", "cm.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: ok\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "fixtures", "large.bin"), bytes.Repeat([]byte("x"), 512), 0o600))

		chart, err := NewHelmChart(dir)
		require.NoError(t, err)
		assert.Equal(t, "app", chart.GetName())
	})

	t.Run("oversized tgz archive rejected", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "100")
		archivePath := buildTestHelmArchive(t, map[string]string{
			"app/Chart.yaml":           "apiVersion: v2\nname: app\nversion: 0.1.0\n",
			"app/templates/large.yaml": strings.Repeat("a", 2000),
		})

		_, err := NewHelmChart(archivePath)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHelmTemplateTooLarge)
	})

	t.Run("tgz archive bomb within compressed limit but oversized entry rejected", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "512")
		archivePath := buildTestHelmArchive(t, map[string]string{
			"app/Chart.yaml":           "apiVersion: v2\nname: app\nversion: 0.1.0\n",
			"app/templates/notes.yaml": "# " + strings.Repeat("A", 4096) + "\n",
		})
		info, err := os.Stat(archivePath)
		require.NoError(t, err)
		require.LessOrEqual(t, info.Size(), int64(512), "compressed archive must stay under compressed limit to exercise decompression cap")

		_, err = NewHelmChart(archivePath)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHelmTemplateTooLarge)
	})

	t.Run("valid tgz archive within limit loads cleanly", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "4096")
		archivePath := buildTestHelmArchive(t, map[string]string{
			"app/Chart.yaml":        "apiVersion: v2\nname: app\nversion: 0.1.0\n",
			"app/templates/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: ok\n",
		})

		chart, err := NewHelmChart(archivePath)
		require.NoError(t, err)
		assert.Equal(t, "app", chart.GetName())
	})

	t.Run("symlink cycle inside chart directory does not infinite loop", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "templates"), 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte("apiVersion: v2\nname: app\nversion: 0.1.0\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "templates", "cm.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: ok\n"), 0o600))
		if err := os.Symlink(dir, filepath.Join(dir, "templates", "loop")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}

		done := make(chan error, 1)
		go func() {
			_, loadErr := NewHelmChart(dir)
			done <- loadErr
		}()

		select {
		case loadErr := <-done:
			require.Error(t, loadErr)
			assert.Contains(t, loadErr.Error(), "symlink cycle")
		case <-time.After(5 * time.Second):
			t.Fatal("NewHelmChart hung on symlink cycle inside chart directory")
		}
	})

	t.Run("directory-mode TypeReg tar entry exceeding limit rejected", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "512")

		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gw)
		for _, item := range []struct {
			name     string
			typeflag byte
			mode     int64
			body     []byte
		}{
			{
				name:     "app/templates/",
				typeflag: tar.TypeDir,
				mode:     0o040755,
			},
			{
				name:     "app/Chart.yaml",
				typeflag: tar.TypeReg,
				mode:     0o600,
				body:     []byte("apiVersion: v2\nname: app\nversion: 0.1.0\n"),
			},
			{
				name:     "app/templates/disguised.yaml",
				typeflag: tar.TypeReg,
				mode:     0o040755,
				body:     bytes.Repeat([]byte("D"), 4096),
			},
		} {
			require.NoError(t, tw.WriteHeader(&tar.Header{
				Name:     item.name,
				Typeflag: item.typeflag,
				Mode:     item.mode,
				Size:     int64(len(item.body)),
			}))
			if len(item.body) > 0 {
				_, err := tw.Write(item.body)
				require.NoError(t, err)
			}
		}
		require.NoError(t, tw.Close())
		require.NoError(t, gw.Close())

		archivePath := filepath.Join(t.TempDir(), "disguised-0.1.0.tgz")
		require.LessOrEqual(t, buf.Len(), 512)
		require.NoError(t, os.WriteFile(archivePath, buf.Bytes(), 0o600))

		_, err := NewHelmChart(archivePath)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHelmTemplateTooLarge)
	})

	t.Run("nested packaged dependency with oversized decompressed entry rejected", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "4096")
		childBytes := buildTestHelmArchiveBytes(t, map[string][]byte{
			"child/Chart.yaml":           []byte("apiVersion: v2\nname: child\nversion: 0.1.0\n"),
			"child/templates/large.yaml": []byte("# " + strings.Repeat("Z", 64<<10) + "\n"),
		})
		require.Less(t, len(childBytes), 4096, "compressed child package must be smaller than outer limit")

		parentPath := filepath.Join(t.TempDir(), "parent-0.1.0.tgz")
		parentBytes := buildTestHelmArchiveBytes(t, map[string][]byte{
			"parent/Chart.yaml":       []byte("apiVersion: v2\nname: parent\nversion: 0.1.0\n"),
			"parent/charts/child.tgz": childBytes,
		})
		require.Less(t, len(parentBytes), 4096)
		require.NoError(t, os.WriteFile(parentPath, parentBytes, 0o600))

		_, err := NewHelmChart(parentPath)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHelmTemplateTooLarge)
	})

	t.Run("included symlink alias to ignored directory is still validated under its own path", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "256")
		dir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "templates"), 0o750))
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "a"), 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte("apiVersion: v2\nname: app\nversion: 0.1.0\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".helmignore"), []byte("a/large.yaml\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "templates", "cm.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: ok\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "a", "large.yaml"), bytes.Repeat([]byte("a"), 354), 0o600))
		if err := os.Symlink(filepath.Join(dir, "a"), filepath.Join(dir, "b")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}

		_, err := NewHelmChart(dir)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHelmTemplateTooLarge)
	})

	t.Run("tgz asset inside unpacked dependency files directory is not parsed as subchart", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "4096")
		dir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "templates"), 0o750))
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "charts", "child", "files"), 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte("apiVersion: v2\nname: app\nversion: 0.1.0\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "templates", "cm.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: ok\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "charts", "child", "Chart.yaml"), []byte("apiVersion: v2\nname: child\nversion: 0.1.0\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "charts", "child", "files", "data.tgz"), []byte("not-a-chart-archive"), 0o600))

		chart, err := NewHelmChart(dir)
		require.NoError(t, err)
		assert.Equal(t, "app", chart.GetName())
	})

	t.Run("chained PAX metadata records exceeding stream budget rejected", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "1048576")

		// Generate one valid TypeXHeader + payload block via tar.Writer, then strip
		// the trailing dummy file header so we can repeat consecutive PAX records.
		var templateBuf bytes.Buffer
		ptw := tar.NewWriter(&templateBuf)
		require.NoError(t, ptw.WriteHeader(&tar.Header{
			Name:       "x",
			Typeflag:   tar.TypeReg,
			Mode:       0o600,
			Size:       0,
			Format:     tar.FormatPAX,
			PAXRecords: map[string]string{"comment": strings.Repeat("A", 900000)},
		}))
		paxRecordBytes := templateBuf.Bytes()[:templateBuf.Len()-512]

		var buf bytes.Buffer
		gw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
		require.NoError(t, err)
		for i := 0; i < 120; i++ {
			_, err = gw.Write(paxRecordBytes)
			require.NoError(t, err)
		}
		tw := tar.NewWriter(gw)
		chartYAML := []byte("apiVersion: v2\nname: app\nversion: 0.1.0\n")
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     "app/Chart.yaml",
			Typeflag: tar.TypeReg,
			Mode:     0o600,
			Size:     int64(len(chartYAML)),
		}))
		_, err = tw.Write(chartYAML)
		require.NoError(t, err)
		require.NoError(t, tw.Close())
		require.NoError(t, gw.Close())

		archivePath := filepath.Join(t.TempDir(), "pax-bomb-0.1.0.tgz")
		require.Less(t, buf.Len(), 1<<20, "compressed PAX chain must stay below compressed file limit")
		require.NoError(t, os.WriteFile(archivePath, buf.Bytes(), 0o600))

		_, err = NewHelmChart(archivePath)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHelmTemplateTooLarge)
	})

	t.Run("near-MaxInt64 tar entry rejected before totalDecompressed overflow", func(t *testing.T) {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gw)
		chartYAML := []byte("apiVersion: v2\nname: app\nversion: 0.1.0\n")
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     "app/Chart.yaml",
			Typeflag: tar.TypeReg,
			Mode:     0o600,
			Size:     int64(len(chartYAML)),
		}))
		_, err := tw.Write(chartYAML)
		require.NoError(t, err)
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     "app/templates/huge.yaml",
			Typeflag: tar.TypeReg,
			Format:   tar.FormatPAX,
			Mode:     0o600,
			Size:     math.MaxInt64 - 1,
		}))
		require.NoError(t, gw.Close())

		_, err = loadBoundedHelmArchiveFiles(bytes.NewReader(buf.Bytes()), "overflow.tgz", math.MaxInt64)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decompressed chart is larger than the maximum file size")
	})
}
