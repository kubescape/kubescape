package resourcehandler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/k8s-interface/workloadinterface"
	"k8s.io/apimachinery/pkg/version"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/opa-utils/objectsenvelopes"
	"github.com/armosec/opa-utils/reporthandling"

	"gopkg.in/yaml.v2"
)

var (
	YAML_PREFIX = []string{".yaml", ".yml"}
	JSON_PREFIX = []string{".json"}
)

type FileFormat string

const (
	YAML_FILE_FORMAT FileFormat = "yaml"
	JSON_FILE_FORMAT FileFormat = "json"
)

// FileResourceHandler handle resources from files and URLs
type FileResourceHandler struct {
	inputPatterns []string
}

func NewFileResourceHandler(inputPatterns []string) *FileResourceHandler {
	k8sinterface.InitializeMapResourcesMock() // initialize the resource map
	return &FileResourceHandler{
		inputPatterns: inputPatterns,
	}
}

func (fileHandler *FileResourceHandler) GetResources(frameworks []reporthandling.Framework, designator *armotypes.PortalDesignator) (*cautils.K8SResources, map[string]workloadinterface.IMetadata, error) {

	// build resources map
	// map resources based on framework required resources: map["/group/version/kind"][]<k8s workloads ids>
	k8sResources := setResourceMap(frameworks)
	allResources := map[string]workloadinterface.IMetadata{}

	workloads := []workloadinterface.IMetadata{}

	// load resource from local file system
	w, err := loadResourcesFromFiles(fileHandler.inputPatterns)
	if err != nil {
		return nil, allResources, err
	}
	if w != nil {
		workloads = append(workloads, w...)
	}

	// load resources from url
	w, err = loadResourcesFromUrl(fileHandler.inputPatterns)
	if err != nil {
		return nil, allResources, err
	}
	if w != nil {
		workloads = append(workloads, w...)
	}

	if len(workloads) == 0 {
		return nil, allResources, fmt.Errorf("empty list of workloads - no workloads found")
	}

	// map all resources: map["/group/version/kind"][]<k8s workloads>
	mappedResources := mapResources(workloads)

	// save only relevant resources
	for i := range mappedResources {
		if _, ok := (*k8sResources)[i]; ok {
			ids := []string{}
			for j := range mappedResources[i] {
				ids = append(ids, mappedResources[i][j].GetID())
				allResources[mappedResources[i][j].GetID()] = mappedResources[i][j]
			}
			(*k8sResources)[i] = ids
		}
	}

	return k8sResources, allResources, nil

}

func (fileHandler *FileResourceHandler) GetClusterAPIServerInfo() *version.Info {
	return nil
}

func loadResourcesFromFiles(inputPatterns []string) ([]workloadinterface.IMetadata, error) {
	files, errs := listFiles(inputPatterns)
	if len(errs) > 0 {
		cautils.ErrorDisplay(fmt.Sprintf("%v", errs)) // TODO - print error
	}
	if len(files) == 0 {
		return nil, nil
	}

	workloads, errs := loadFiles(files)
	if len(errs) > 0 {
		cautils.ErrorDisplay(fmt.Sprintf("%v", errs)) // TODO - print error
	}
	return workloads, nil
}

// build resources map
func mapResources(workloads []workloadinterface.IMetadata) map[string][]workloadinterface.IMetadata {

	allResources := map[string][]workloadinterface.IMetadata{}
	for i := range workloads {
		groupVersionResource, err := k8sinterface.GetGroupVersionResource(workloads[i].GetKind())
		if err != nil {
			// TODO - print warning
			continue
		}

		if k8sinterface.IsTypeWorkload(workloads[i].GetObject()) {
			w := workloadinterface.NewWorkloadObj(workloads[i].GetObject())
			if groupVersionResource.Group != w.GetGroup() || groupVersionResource.Version != w.GetVersion() {
				// TODO - print warning
				continue
			}
		}
		resourceTriplets := k8sinterface.JoinResourceTriplets(groupVersionResource.Group, groupVersionResource.Version, groupVersionResource.Resource)
		if r, ok := allResources[resourceTriplets]; ok {
			allResources[resourceTriplets] = append(r, workloads[i])
		} else {
			allResources[resourceTriplets] = []workloadinterface.IMetadata{workloads[i]}
		}
	}
	return allResources

}

func loadFiles(filePaths []string) ([]workloadinterface.IMetadata, []error) {
	workloads := []workloadinterface.IMetadata{}
	errs := []error{}
	for i := range filePaths {
		f, err := loadFile(filePaths[i])
		if err != nil {
			errs = append(errs, err)
			continue
		}
		w, e := readFile(f, getFileFormat(filePaths[i]))
		errs = append(errs, e...)
		if w != nil {
			workloads = append(workloads, w...)
		}
	}
	return workloads, errs
}

func loadFile(filePath string) ([]byte, error) {
	return os.ReadFile(filePath)
}
func readFile(fileContent []byte, fileFromat FileFormat) ([]workloadinterface.IMetadata, []error) {

	switch fileFromat {
	case YAML_FILE_FORMAT:
		return readYamlFile(fileContent)
	case JSON_FILE_FORMAT:
		return readJsonFile(fileContent)
	default:
		return nil, nil // []error{fmt.Errorf("file extension %s not supported", fileFromat)}
	}

}

func listFiles(patterns []string) ([]string, []error) {
	files := []string{}
	errs := []error{}
	for i := range patterns {
		if strings.HasPrefix(patterns[i], "http") {
			continue
		}
		if !filepath.IsAbs(patterns[i]) {
			o, _ := os.Getwd()
			patterns[i] = filepath.Join(o, patterns[i])
		}
		f, err := glob(filepath.Split(patterns[i])) //filepath.Glob(patterns[i])
		if err != nil {
			errs = append(errs, err)
		} else {
			files = append(files, f...)
		}
	}
	return files, errs
}

func readYamlFile(yamlFile []byte) ([]workloadinterface.IMetadata, []error) {
	errs := []error{}

	r := bytes.NewReader(yamlFile)
	dec := yaml.NewDecoder(r)
	yamlObjs := []workloadinterface.IMetadata{}

	var t interface{}
	for dec.Decode(&t) == nil {
		j := convertYamlToJson(t)
		if j == nil {
			continue
		}
		if obj, ok := j.(map[string]interface{}); ok {
			if o := objectsenvelopes.NewObject(obj); o != nil {
				if o.GetKind() == "List" {
					yamlObjs = append(yamlObjs, handleListObject(o)...)
				} else {
					yamlObjs = append(yamlObjs, o)
				}
			}
		} else {
			errs = append(errs, fmt.Errorf("failed to convert yaml file to map[string]interface, file content: %v", j))
		}
	}

	return yamlObjs, errs
}

func readJsonFile(jsonFile []byte) ([]workloadinterface.IMetadata, []error) {
	workloads := []workloadinterface.IMetadata{}
	var jsonObj interface{}
	if err := json.Unmarshal(jsonFile, &jsonObj); err != nil {
		return workloads, []error{err}
	}

	convertJsonToWorkload(jsonObj, &workloads)

	return workloads, nil
}
func convertJsonToWorkload(jsonObj interface{}, workloads *[]workloadinterface.IMetadata) {

	switch x := jsonObj.(type) {
	case map[string]interface{}:
		if o := objectsenvelopes.NewObject(x); o != nil {
			(*workloads) = append(*workloads, o)
		}
	case []interface{}:
		for i := range x {
			convertJsonToWorkload(x[i], workloads)
		}
	}
}
func convertYamlToJson(i interface{}) interface{} {
	switch x := i.(type) {
	case map[interface{}]interface{}:
		m2 := map[string]interface{}{}
		for k, v := range x {
			if s, ok := k.(string); ok {
				m2[s] = convertYamlToJson(v)
			}
		}
		return m2
	case []interface{}:
		for i, v := range x {
			x[i] = convertYamlToJson(v)
		}
	}
	return i
}

func glob(root, pattern string) ([]string, error) {
	var matches []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if matched, err := filepath.Match(pattern, filepath.Base(path)); err != nil {
			return err
		} else if matched {
			matches = append(matches, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return matches, nil
}
func isYaml(filePath string) bool {
	return cautils.StringInSlice(YAML_PREFIX, filepath.Ext(filePath)) != cautils.ValueNotFound
}

func isJson(filePath string) bool {
	return cautils.StringInSlice(YAML_PREFIX, filepath.Ext(filePath)) != cautils.ValueNotFound
}

func getFileFormat(filePath string) FileFormat {
	if isYaml(filePath) {
		return YAML_FILE_FORMAT
	} else if isJson(filePath) {
		return JSON_FILE_FORMAT
	} else {
		return FileFormat(filePath)
	}
}

// handleListObject handle a List manifest
func handleListObject(obj workloadinterface.IMetadata) []workloadinterface.IMetadata {
	yamlObjs := []workloadinterface.IMetadata{}
	if i, ok := workloadinterface.InspectMap(obj.GetObject(), "items"); ok && i != nil {
		if items, ok := i.([]interface{}); ok && items != nil {
			for item := range items {
				if m, ok := items[item].(map[string]interface{}); ok && m != nil {
					if o := objectsenvelopes.NewObject(m); o != nil {
						yamlObjs = append(yamlObjs, o)
					}
				}
			}
		}
	}
	return yamlObjs
}
