package cautils

import (
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"reflect"

	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/stretchr/testify/suite"
)

type HelmChartTestSuite struct {
	suite.Suite
	helmChartPath         string
	expectedFiles         []string
	expectedDefaultValues map[string]interface{}
	pathToValueFiles      []string
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
	_, err := NewHelmChart("/invalid_path", s.pathToValueFiles)
	s.Error(err)
}

func (s *HelmChartTestSuite) TestValidHelmDirectory() {
	chart, err := NewHelmChart(s.helmChartPath, s.pathToValueFiles)
	s.NoError(err)
	s.NotNil(chart)
}

func (s *HelmChartTestSuite) TestGetName() {
	chart, _ := NewHelmChart(s.helmChartPath, s.pathToValueFiles)
	s.Equal("kubescape", chart.GetName())
}

func (s *HelmChartTestSuite) TestGetDefaultValues() {
	chart, _ := NewHelmChart(s.helmChartPath, s.pathToValueFiles)

	values := chart.GetDefaultValues()

	valuesJson, _ := json.Marshal(values)
	expectedValuesJson, _ := json.Marshal(s.expectedDefaultValues)

	s.JSONEq(string(valuesJson), string(expectedValuesJson))
}

func (s *HelmChartTestSuite) TestGetWorkloadsWithOverride() {
	o, _ := os.Getwd()

	path := filepath.Join(filepath.Dir(o), "..", "examples", "helm_chart", "newvalues.yaml")
	s.pathToValueFiles = append(s.pathToValueFiles, path)
	chart, err := NewHelmChart(s.helmChartPath, s.pathToValueFiles)
	s.NoError(err, "Expected a valid helm chart")

	values := chart.GetDefaultValues()

	// Overriden test value = pass
	testValue := values["override"].(map[string]interface{})["test"].(string)
	s.Equal(testValue, "pass")

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
	chart, _ := NewHelmChart(s.helmChartPath, s.pathToValueFiles)

	values := chart.GetDefaultValues()
	delete(values, "image")

	fileToWorkloads, errs := chart.GetWorkloads(values)
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

func TestMergeValues(t *testing.T) {
	nestedMap := map[string]interface{}{
		"foo": "bar",
		"baz": map[string]string{
			"cool": "stuff",
		},
	}
	anotherNestedMap := map[string]interface{}{
		"foo": "bar",
		"baz": map[string]string{
			"cool":    "things",
			"awesome": "stuff",
		},
	}
	flatMap := map[string]interface{}{
		"foo": "bar",
		"baz": "stuff",
	}
	anotherFlatMap := map[string]interface{}{
		"testing": "fun",
	}

	testMap := mergeMaps(flatMap, nestedMap)
	equal := reflect.DeepEqual(testMap, nestedMap)
	if !equal {
		t.Errorf("Expected a nested map to overwrite a flat value. Expected: %v, got %v", nestedMap, testMap)
	}

	testMap = mergeMaps(nestedMap, flatMap)
	equal = reflect.DeepEqual(testMap, flatMap)
	if !equal {
		t.Errorf("Expected a flat value to overwrite a map. Expected: %v, got %v", flatMap, testMap)
	}

	testMap = mergeMaps(nestedMap, anotherNestedMap)
	equal = reflect.DeepEqual(testMap, anotherNestedMap)
	if !equal {
		t.Errorf("Expected a nested map to overwrite another nested map. Expected: %v, got %v", anotherNestedMap, testMap)
	}

	testMap = mergeMaps(anotherFlatMap, anotherNestedMap)
	expectedMap := map[string]interface{}{
		"testing": "fun",
		"foo":     "bar",
		"baz": map[string]string{
			"cool":    "things",
			"awesome": "stuff",
		},
	}
	equal = reflect.DeepEqual(testMap, expectedMap)
	if !equal {
		t.Errorf("Expected a map with different keys to merge properly with another map. Expected: %v, got %v", expectedMap, testMap)
	}
}

