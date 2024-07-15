package cautils

import (
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/stretchr/testify/suite"
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

	fileToWorkloads, _, errs := chart.GetWorkloads(values)
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

	fileToWorkloads, _, errs := chart.GetWorkloads(values)
	s.Nil(fileToWorkloads)
	s.Len(errs, 1, "Expected an error due to missing value")

	expectedErrMsg := "<.Values.image.repository>: nil pointer"
	s.Containsf(errs[0].Error(), expectedErrMsg, "expected error containing %q, got %q", expectedErrMsg, errs[0])
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
