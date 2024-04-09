package cautils

import (
	"path/filepath"
	"strconv"
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
func (hc *HelmChart) GetWorkloadsWithDefaultValues() (map[string][]workloadinterface.IMetadata, map[string]MappingNodes, []error) {
	return hc.GetWorkloads(hc.GetDefaultValues())
}

// GetWorkloads renders chart template using the provided values and returns a map of source (absolute) file path to its workloads
func (hc *HelmChart) GetWorkloads(values map[string]interface{}) (map[string][]workloadinterface.IMetadata, map[string]MappingNodes, []error) {
	vals, err := helmchartutil.ToRenderValues(hc.chart, values, helmchartutil.ReleaseOptions{}, nil)
	if err != nil {
		return nil, nil, []error{err}
	}

	// change the chart to template with comment, only is template(.yaml added otherwise no)
	hc.AddCommentToTemplate()

	sourceToFile, err := helmengine.Render(hc.chart, vals)
	if err != nil {
		return nil, nil, []error{err}
	}

	// get the resouse and analysis and store it to the struct
	fileMapping := make(map[string]MappingNodes)
	GetTemplateMapping(sourceToFile, fileMapping)

	// delete the comment from chart and from sourceToFile
	RemoveComment(sourceToFile)

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
		if firstPathSeparatorIndex := strings.Index(path, string("/")); firstPathSeparatorIndex != -1 {
			absPath := filepath.Join(hc.path, path[firstPathSeparatorIndex:])

			if nodes, ok := fileMapping[path]; ok {
				fileMapping[absPath] = nodes
				delete(fileMapping, path)
			}
			workloads[absPath] = []workloadinterface.IMetadata{}
			for i := range wls {
				lw := localworkload.NewLocalWorkload(wls[i].GetObject())
				lw.SetPath(absPath)
				workloads[absPath] = append(workloads[absPath], lw)
			}
		}
	}
	return workloads, fileMapping, errs
}

func (hc *HelmChart) AddCommentToTemplate() {
	for index, t := range hc.chart.Templates {
		if IsYaml(strings.ToLower(t.Name)) {
			var newLines []string
			originalTemplate := string(t.Data)
			lines := strings.Split(originalTemplate, "\n")

			for index, line := range lines {
				comment := " #This is the " + strconv.Itoa(index+1) + " line"
				newLines = append(newLines, line+comment)
			}
			templateWithComment := strings.Join(newLines, "\n")
			hc.chart.Templates[index].Data = []byte(templateWithComment)
		}
	}
}

func RemoveComment(sourceToFile map[string]string) {
	// commentRe := regexp.MustCompile(CommentFormat)
	for fileName, file := range sourceToFile {
		if !IsYaml(strings.ToLower((fileName))) {
			continue
		}
		sourceToFile[fileName] = commentRe.ReplaceAllLiteralString(file, "")
	}
}

func GetTemplateMapping(sourceToFile map[string]string, fileMapping map[string]MappingNodes) {
	for fileName, fileContent := range sourceToFile {
		mappingNodes, err := GetMapping(fileName, fileContent)
		if err != nil {
			// if one file cannot get mapping nodes, generate error, then ignore it
			logger.L().Warning("Failed to get File Mapping nodes", helpers.String("file name", fileName), helpers.Error(err))
			continue
		}
		if len(mappingNodes.Nodes) != 0 {
			fileMapping[fileName] = *mappingNodes
		}
	}
}
