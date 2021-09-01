package policyhandler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/k8sinterface"
	"github.com/armosec/kubescape/cautils/opapolicy"

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

func (policyHandler *PolicyHandler) loadResources(frameworks []opapolicy.Framework, scanInfo *cautils.ScanInfo) (*cautils.K8SResources, error) {
	workloads := []k8sinterface.IWorkload{}

	// load resource from local file system
	w, err := loadResourcesFromFiles(scanInfo.InputPatterns)
	if err != nil {
		return nil, err
	}
	if w != nil {
		workloads = append(workloads, w...)
	}

	// load resources from url
	w, err = loadResourcesFromUrl(scanInfo.InputPatterns)
	if err != nil {
		return nil, err
	}
	if w != nil {
		workloads = append(workloads, w...)
	}

	if len(workloads) == 0 {
		return nil, fmt.Errorf("empty list of workloads - no workloads found")
	}

	// map all resources: map["/group/version/kind"][]<k8s workloads>
	allResources := mapResources(workloads)

	// build resources map
	// map resources based on framework required resources: map["/group/version/kind"][]<k8s workloads>
	k8sResources := setResourceMap(frameworks)

	// save only relevant resources
	for i := range allResources {
		if _, ok := (*k8sResources)[i]; ok {
			(*k8sResources)[i] = allResources[i]
		}
	}

	return k8sResources, nil

}

func loadResourcesFromFiles(inputPatterns []string) ([]k8sinterface.IWorkload, error) {
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
func mapResources(workloads []k8sinterface.IWorkload) map[string][]map[string]interface{} {
	allResources := map[string][]map[string]interface{}{}
	for i := range workloads {
		groupVersionResource, err := k8sinterface.GetGroupVersionResource(workloads[i].GetKind())
		if err != nil {
			// TODO - print warning
			continue
		}
		if groupVersionResource.Group != workloads[i].GetGroup() || groupVersionResource.Version != workloads[i].GetVersion() {
			// TODO - print warning
			continue
		}
		resourceTriplets := k8sinterface.JoinResourceTriplets(groupVersionResource.Group, groupVersionResource.Version, groupVersionResource.Resource)
		if r, ok := allResources[resourceTriplets]; ok {
			r = append(r, workloads[i].GetWorkload())
			allResources[resourceTriplets] = r
		} else {
			allResources[resourceTriplets] = []map[string]interface{}{workloads[i].GetWorkload()}
		}
	}
	return allResources

}

func loadFiles(filePaths []string) ([]k8sinterface.IWorkload, []error) {
	workloads := []k8sinterface.IWorkload{}
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
	return ioutil.ReadFile(filePath)
}
func readFile(fileContent []byte, fileFromat FileFormat) ([]k8sinterface.IWorkload, []error) {

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

func readYamlFile(yamlFile []byte) ([]k8sinterface.IWorkload, []error) {
	errs := []error{}

	r := bytes.NewReader(yamlFile)
	dec := yaml.NewDecoder(r)
	yamlObjs := []k8sinterface.IWorkload{}

	var t interface{}
	for dec.Decode(&t) == nil {
		j := convertYamlToJson(t)
		if j == nil {
			continue
		}
		if obj, ok := j.(map[string]interface{}); ok {
			yamlObjs = append(yamlObjs, k8sinterface.NewWorkloadObj(obj))
		} else {
			errs = append(errs, fmt.Errorf("failed to convert yaml file to map[string]interface, file content: %v", j))
		}
	}

	return yamlObjs, errs
}

func readJsonFile(jsonFile []byte) ([]k8sinterface.IWorkload, []error) {
	workloads := []k8sinterface.IWorkload{}
	var jsonObj interface{}
	if err := json.Unmarshal(jsonFile, &jsonObj); err != nil {
		return workloads, []error{err}
	}

	convertJsonToWorkload(jsonObj, &workloads)

	return workloads, nil
}
func convertJsonToWorkload(jsonObj interface{}, workloads *[]k8sinterface.IWorkload) {

	switch x := jsonObj.(type) {
	case map[string]interface{}:
		(*workloads) = append(*workloads, k8sinterface.NewWorkloadObj(x))
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
