package cautils

import (
	"context"
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	helmchartutil "helm.sh/helm/v3/pkg/chartutil"
)

type HelmChartTestSuite struct {
	suite.Suite
	helmChartPath         string
	expectedFiles         []string
	expectedDefaultValues map[string]interface{}
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

	var obj interface{}
	file, _ := os.ReadFile(filepath.Join("testdata", "helm_expected_default_values.json"))
	_ = json.Unmarshal([]byte(file), &obj)
	s.expectedDefaultValues = obj.(map[string]interface{})
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
	pullPolicyValue := values["image"].(map[string]interface{})["pullPolicy"].(string)
	s.Equal(pullPolicyValue, "Always")

	// Override default value
	values["image"].(map[string]interface{})["pullPolicy"] = "Never"

	fileToWorkloads, errs := chart.GetWorkloads(values)
	s.Len(errs, 0)

	s.Lenf(fileToWorkloads, len(s.expectedFiles), "Expected %d files", len(s.expectedFiles))

	for _, expectedFile := range s.expectedFiles {
		s.Contains(fileToWorkloads, expectedFile)
		s.FileExists(expectedFile)
		s.GreaterOrEqualf(len(fileToWorkloads[expectedFile]), 1, "Expected at least one workload in %q", expectedFile)

		for i := range fileToWorkloads[expectedFile] {
			pathInWorkload := fileToWorkloads[expectedFile][i].(*localworkload.LocalWorkload).GetPath()
			s.Equal(pathInWorkload, expectedFile, "Expected GetPath() to return a valid path on workload")
		}

		if strings.Contains(expectedFile, "cronjob.yaml") {
			jsonBytes, _ := json.Marshal(fileToWorkloads[expectedFile][0].GetObject())
			s.Contains(string(jsonBytes), "\"imagePullPolicy\":\"Never\"", "Expected to overriden value of imagePullPolicy to be 'Never'")
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

// TestHelmValueOptions_MergeValues exercises the helm-style value merger so we can be sure
// that --set / -f equivalents are parsed and merged the same way `helm install` would.
func TestHelmValueOptions_MergeValues(t *testing.T) {
	opts := HelmValueOptions{
		Values:       []string{"image.tag=v1.2.3", "replicaCount=5"},
		StringValues: []string{"image.repository=myrepo/app"},
	}
	merged, err := opts.MergeValues()
	assert.NoError(t, err)

	image, ok := merged["image"].(map[string]interface{})
	assert.True(t, ok, "expected image to be a nested map")
	assert.Equal(t, "v1.2.3", image["tag"])
	assert.Equal(t, "myrepo/app", image["repository"])
	assert.EqualValues(t, 5, merged["replicaCount"])
}

// TestLoadResourcesFromHelmCharts_WithOverrides confirms that user-supplied --set values
// are merged over chart defaults end-to-end via the public LoadResourcesFromHelmCharts entrypoint.
func TestLoadResourcesFromHelmCharts_WithOverrides(t *testing.T) {
	o, _ := os.Getwd()
	chartPath := filepath.Join(filepath.Dir(o), "..", "examples", "helm_chart")

	opts := HelmValueOptions{
		Values: []string{"image.pullPolicy=Never"},
	}
	sourceToWorkloads, _, err := LoadResourcesFromHelmCharts(context.TODO(), chartPath, opts)
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
	_, _, err := LoadResourcesFromHelmCharts(context.TODO(), chartPath, opts)
	assert.Error(t, err, "expected fail-fast on missing -f file")
	assert.Contains(t, err.Error(), "Helm value overrides")
}

func TestMergeMaps_DeepMerge(t *testing.T) {
	base := map[string]interface{}{
		"image": map[string]interface{}{"repository": "base-repo", "tag": "default"},
		"keep":  "untouched",
	}
	override := map[string]interface{}{
		"image": map[string]interface{}{"tag": "overridden"},
		"new":   "added",
	}

	out := mergeMaps(base, override)

	img := out["image"].(map[string]interface{})
	assert.Equal(t, "base-repo", img["repository"], "non-overridden nested key should survive")
	assert.Equal(t, "overridden", img["tag"], "override should win on conflict")
	assert.Equal(t, "untouched", out["keep"])
	assert.Equal(t, "added", out["new"])

	// base should not be mutated by mergeMaps
	assert.Equal(t, "default", base["image"].(map[string]interface{})["tag"])
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
