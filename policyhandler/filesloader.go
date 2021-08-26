package policyhandler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"kube-escape/cautils"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

var (
	YAML_PREFIX = []string{".yaml", ".yml"}
	JSON_PREFIX = []string{".json"}
)

// // build resources map
// k8sResourcesMap := setResourceMap(frameworks)
func loadFiles(filePaths []string) {

	for i := range filePaths {
		loadFile(filePaths[i])
	}
}

func loadFile(filePath string) (interface{}, error) {
	var obj interface{}
	var err error
	if isYaml(filePath) {
		obj, err = loadYamlFile(filePath)
	} else if isJson(filePath) {
		obj, err = loadJsonFile(filePath)
	} else {
		return nil, fmt.Errorf("Unknown file format")
	}
	if err != nil {
		return obj, err
	}
	if _, ok := obj.([]interface{}); ok {
		return obj, nil
	}
	return []interface{}{obj}, nil
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
func loadYamlFile(filePath string) (interface{}, error) {
	yamlFile, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(yamlFile)
	dec := yaml.NewDecoder(r)
	var t interface{}
	yamlObjs := []interface{}{}
	for dec.Decode(&t) == nil {
		var yamlObj interface{}
		if err := yaml.Unmarshal(yamlFile, &yamlObj); err != nil {
			return yamlObj, err
		}
		yamlObjs = append(yamlObjs, t)
	}

	return convertYamlToJson(yamlObjs), nil
}

func loadJsonFile(filePath string) (interface{}, error) {
	var jsonObj interface{}
	jsonFile, err := ioutil.ReadFile(filePath)
	if err != nil {
		return jsonObj, err
	}
	if err = json.Unmarshal(jsonFile, &jsonObj); err != nil {
		return jsonObj, err
	}
	return jsonObj, nil
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
