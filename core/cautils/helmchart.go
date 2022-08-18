package cautils

import (
	"path/filepath"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"

	helmchart "helm.sh/helm/v3/pkg/chart"
	helmloader "helm.sh/helm/v3/pkg/chart/loader"
	helmchartutil "helm.sh/helm/v3/pkg/chartutil"
	helmengine "helm.sh/helm/v3/pkg/engine"
)

type HelmChart struct {
	chart *helmchart.Chart
	path  string
}

func IsHelmDirectory(path string) (bool, error) {
	return helmchartutil.IsChartDir(path)
}

func NewHelmChart(path string) (*HelmChart, error) {
	chart, err := helmloader.Load(path)
	if err != nil {
		return nil, err
	}

	return &HelmChart{
		chart: chart,
		path:  path,
	}, nil
}

func (hc *HelmChart) GetName() string {
	return hc.chart.Name()
}

func (hc *HelmChart) GetDefaultValues() map[string]interface{} {
	return hc.chart.Values
}

// GetWorkloads renders chart template using the default values and returns a map of source file to its workloads
func (hc *HelmChart) GetWorkloadsWithDefaultValues() (map[string][]workloadinterface.IMetadata, []error) {
	return hc.GetWorkloads(hc.GetDefaultValues())
}

// GetWorkloads renders chart template using the provided values and returns a map of source (absolute) file path to its workloads
func (hc *HelmChart) GetWorkloads(values map[string]interface{}) (map[string][]workloadinterface.IMetadata, []error) {
	vals, err := helmchartutil.ToRenderValues(hc.chart, values, helmchartutil.ReleaseOptions{}, nil)
	if err != nil {
		return nil, []error{err}
	}

	sourceToFile, err := helmengine.Render(hc.chart, vals)
	if err != nil {
		return nil, []error{err}
	}

	workloads := make(map[string][]workloadinterface.IMetadata, 0)
	errs := []error{}

	for path, renderedYaml := range sourceToFile {
		if !IsYaml(strings.ToLower(path)) {
			continue
		}

		wls, e := ReadFile([]byte(renderedYaml), YAML_FILE_FORMAT)
		if e != nil {
			logger.L().Debug("failed to read rendered yaml file", helpers.String("file", path), helpers.Error(e))
		}
		if len(wls) == 0 {
			continue
		}
		// separate base path and file name. We do not use the os.Separator because the paths returned from the helm engine are not OS specific (e.g. mychart/templates/myfile.yaml)
		if firstPathSeparatorIndex := strings.Index(path, string("/")); firstPathSeparatorIndex != -1 {
			absPath := filepath.Join(hc.path, path[firstPathSeparatorIndex:])

			workloads[absPath] = []workloadinterface.IMetadata{}
			for i := range wls {
				lw := localworkload.NewLocalWorkload(wls[i].GetObject())
				lw.SetPath(absPath)
				workloads[absPath] = append(workloads[absPath], lw)
			}
		}
	}
	return workloads, errs
}
