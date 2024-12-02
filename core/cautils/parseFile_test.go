package cautils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/suite"
	helmchartutil "helm.sh/helm/v3/pkg/chartutil"
	helmengine "helm.sh/helm/v3/pkg/engine"
)

type HelmChartGetMappingSuite struct {
	suite.Suite
	helmChartPath string
	expectedFiles []string
	fileContent   map[string]string
}

func TestHelmChartGetMappingSuite(t *testing.T) {
	suite.Run(t, new(HelmChartGetMappingSuite))
}

func (s *HelmChartGetMappingSuite) SetupSuite() {
	o, _ := os.Getwd()

	s.helmChartPath = filepath.Join(filepath.Dir(o), "..", "examples", "helm_chart_mapping_node")

	s.expectedFiles = []string{
		filepath.Join(s.helmChartPath, "templates", "clusterrolebinding.yaml"),
		filepath.Join(s.helmChartPath, "templates", "clusterrole.yaml"),
		filepath.Join(s.helmChartPath, "templates", "serviceaccount.yaml"),
		filepath.Join(s.helmChartPath, "templates", "rolebinding.yaml"),
		filepath.Join(s.helmChartPath, "templates", "role.yaml"),
		filepath.Join(s.helmChartPath, "templates", "cronjob.yaml"),
	}

	s.fileContent = make(map[string]string)

	hc, _ := NewHelmChart(s.helmChartPath)

	values := hc.GetDefaultValues()

	vals, _ := helmchartutil.ToRenderValues(hc.chart, values, helmchartutil.ReleaseOptions{}, nil)

	sourceToFile, _ := helmengine.Render(hc.chart, vals)

	s.fileContent = sourceToFile

}

func (s *HelmChartGetMappingSuite) TestGetMapping() {
	fileNodes, err := GetMapping("rolebinding.yaml", s.fileContent["kubescape/templates/rolebinding.yaml"])
	s.NoError(err, "Get Mapping nodes correctly")
	s.Equal(fileNodes.TemplateFileName, "rolebinding.yaml")
	s.Len(fileNodes.Nodes, 1)
	s.Len(fileNodes.Nodes[0], 13)
}

func (s *HelmChartGetMappingSuite) TestGetMappingFromFileContainsMultipleSubFiles() {
	fileNodes, err := GetMapping("serviceaccount.yaml", s.fileContent["kubescape/templates/serviceaccount.yaml"])
	s.NoError(err, "Get Mapping nodes correctly")
	s.Equal(fileNodes.TemplateFileName, "serviceaccount.yaml")
	s.Len(fileNodes.Nodes, 2)
	s.Len(fileNodes.Nodes[0], 8)
	s.Len(fileNodes.Nodes[1], 2)
}

func (s *HelmChartGetMappingSuite) TestGetMappingFromFileCWithoutKindOrApiVersion() {
	fileNodes, err := GetMapping("clusterrole.yaml", s.fileContent["kubescape/templates/clusterrole.yaml"])
	s.Contains(err.Error(), "there is no enough objectID info")
	s.Nil(fileNodes)
}

func (s *HelmChartGetMappingSuite) TestGetMappingFromFileCWithoutApiVersion() {
	fileNodes, err := GetMapping("clusterrolebinding.yaml", s.fileContent["kubescape/templates/clusterrolebinding.yaml"])
	s.Contains(err.Error(), "there is no enough objectID info")
	s.Nil(fileNodes)
}
