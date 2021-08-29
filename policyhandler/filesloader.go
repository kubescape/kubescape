package policyhandler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"kubescape/cautils"
	"kubescape/cautils/k8sinterface"
	"kubescape/cautils/opapolicy"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

var (
	YAML_PREFIX = []string{".yaml", ".yml"}
	JSON_PREFIX = []string{".json"}
)

func (policyHandler *PolicyHandler) loadResources(frameworks []opapolicy.Framework, scanInfo *opapolicy.ScanInfo) (*cautils.K8SResources, error) {

	workloads, err := loadResourcesFromFiles(scanInfo.InputPatterns)
	if err != nil {
		return nil, err
	}

	// TODO - load resource from url

	// map all resources: map["/group/version/kind"][]<k8s workloads>
	allResources := mapResources(workloads)

	// build resources map
	// map resources based on framework requrid resources: map["/group/version/kind"][]<k8s workloads>
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
		return nil, fmt.Errorf("empty list of files - no files found")
	}

	workloads, errs := loadFiles(files)
	if len(errs) > 0 {
		cautils.ErrorDisplay(fmt.Sprintf("%v", errs)) // TODO - print error
	}
	if len(workloads) == 0 {
		return workloads, fmt.Errorf("empty list of workloads - no workloads valid workloads found")
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
		w, e := loadFile(filePaths[i])
		errs = append(errs, e...)
		workloads = append(workloads, w...)
	}
	return workloads, errs
}

func loadFile(filePath string) ([]k8sinterface.IWorkload, []error) {
	if isYaml(filePath) {
		return loadYamlFile(filePath)
	} else if isJson(filePath) {
		return loadJsonFile(filePath)
	}
	return nil, []error{fmt.Errorf("file extension %s not supported, file name: %s", filepath.Ext(filePath), filePath)}
}
func listFiles(patterns []string) ([]string, []error) {
	files := []string{}
	errs := []error{}
	for i := range patterns {
		f, err := filepath.Glob(patterns[i])
		if err != nil {
			errs = append(errs, err)
		} else {
			files = append(files, f...)
		}
	}
	return files, errs
}

func loadYamlFile(filePath string) ([]k8sinterface.IWorkload, []error) {
	errs := []error{}
	yamlFile, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, []error{err}
	}

	r := bytes.NewReader(yamlFile)
	dec := yaml.NewDecoder(r)
	yamlObjs := []k8sinterface.IWorkload{}

	var t interface{}
	for dec.Decode(&t) == nil {
		j := convertYamlToJson(t)
		if obj, ok := j.(map[string]interface{}); ok {
			yamlObjs = append(yamlObjs, k8sinterface.NewWorkloadObj(obj))
		} else {
			errs = append(errs, fmt.Errorf("failed to convert yaml file %s file to map[string]interface", filePath))
		}
	}

	return yamlObjs, errs
}

func loadJsonFile(filePath string) ([]k8sinterface.IWorkload, []error) {
	workloads := []k8sinterface.IWorkload{}
	jsonFile, err := ioutil.ReadFile(filePath)
	if err != nil {
		return workloads, []error{err}
	}
	var jsonObj interface{}
	if err = json.Unmarshal(jsonFile, &jsonObj); err != nil {
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
			m2[k.(string)] = convertYamlToJson(v)
		}
		return m2
	case []interface{}:
		for i, v := range x {
			x[i] = convertYamlToJson(v)
		}
	}
	return i
}

func isYaml(filePath string) bool {
	return cautils.StringInSlice(YAML_PREFIX, filepath.Ext(filePath)) != cautils.ValueNotFound
}

func isJson(filePath string) bool {
	return cautils.StringInSlice(YAML_PREFIX, filepath.Ext(filePath)) != cautils.ValueNotFound
}
