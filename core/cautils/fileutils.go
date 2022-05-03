package cautils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/v2/core/cautils/logger"
	"github.com/armosec/opa-utils/objectsenvelopes"
	"gopkg.in/yaml.v2"
)

var (
	YAML_PREFIX = []string{"yaml", "yml"}
	JSON_PREFIX = []string{"json"}
)

type FileFormat string

const (
	YAML_FILE_FORMAT FileFormat = "yaml"
	JSON_FILE_FORMAT FileFormat = "json"
)

func LoadResourcesFromFiles(inputPatterns []string) (map[string][]workloadinterface.IMetadata, error) {
	files, errs := listFiles(inputPatterns)
	if len(errs) > 0 {
		logger.L().Error(fmt.Sprintf("%v", errs))
	}
	if len(files) == 0 {
		return nil, nil
	}

	workloads, errs := loadFiles(files)
	if len(errs) > 0 {
		logger.L().Error(fmt.Sprintf("%v", errs))
	}
	return workloads, nil
}

func loadFiles(filePaths []string) (map[string][]workloadinterface.IMetadata, []error) {
	workloads := make(map[string][]workloadinterface.IMetadata, 0)
	errs := []error{}
	for i := range filePaths {
		f, err := loadFile(filePaths[i])
		if err != nil {
			errs = append(errs, err)
			continue
		}
		w, e := ReadFile(f, GetFileFormat(filePaths[i]))
		errs = append(errs, e...)
		if w != nil {
			if _, ok := workloads[filePaths[i]]; !ok {
				workloads[filePaths[i]] = []workloadinterface.IMetadata{}
			}
			wSlice := workloads[filePaths[i]]
			wSlice = append(wSlice, w...)
			workloads[filePaths[i]] = wSlice
		}
	}
	return workloads, errs
}

func loadFile(filePath string) ([]byte, error) {
	return os.ReadFile(filePath)
}
func ReadFile(fileContent []byte, fileFromat FileFormat) ([]workloadinterface.IMetadata, []error) {

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
		if IsFile(patterns[i]) {
			files = append(files, patterns[i])
		} else {
			f, err := glob(filepath.Split(patterns[i])) //filepath.Glob(patterns[i])
			if err != nil {
				errs = append(errs, err)
			} else {
				files = append(files, f...)
			}
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

func IsYaml(filePath string) bool {
	return StringInSlice(YAML_PREFIX, strings.ReplaceAll(filepath.Ext(filePath), ".", "")) != ValueNotFound
}

func IsJson(filePath string) bool {
	return StringInSlice(JSON_PREFIX, strings.ReplaceAll(filepath.Ext(filePath), ".", "")) != ValueNotFound
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
func IsFile(name string) bool {
	if fi, err := os.Stat(name); err == nil {
		if fi.Mode().IsRegular() {
			return true
		}
	}
	return false
}

func GetFileFormat(filePath string) FileFormat {
	if IsYaml(filePath) {
		return YAML_FILE_FORMAT
	} else if IsJson(filePath) {
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
