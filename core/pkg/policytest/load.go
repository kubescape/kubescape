package policytest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
)

// LoadCaseInput reads every YAML and JSON manifest in dir/input and returns
// the parsed Kubernetes resources. Like a scan of local files, it tells the
// two formats apart by extension.
func LoadCaseInput(dir string) ([]workloadinterface.IMetadata, error) {
	inputDir := filepath.Join(dir, "input")
	entries, err := os.ReadDir(inputDir)
	if err != nil {
		return nil, fmt.Errorf("read input dir: %w", err)
	}

	var resources []workloadinterface.IMetadata
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		var format cautils.FileFormat
		switch {
		case cautils.IsYaml(e.Name()):
			format = cautils.YAML_FILE_FORMAT
		case cautils.IsJson(e.Name()):
			format = cautils.JSON_FILE_FORMAT
		default:
			continue
		}
		raw, err := os.ReadFile(filepath.Join(inputDir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		objs, err := cautils.ReadFile(raw, format)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", e.Name(), err)
		}
		resources = append(resources, objs...)
	}
	return resources, nil
}

// LoadCaseExpected reads dir/expected.json as the RuleResponse list the rule
// must produce for this case's input.
func LoadCaseExpected(dir string) ([]reporthandling.RuleResponse, error) {
	raw, err := os.ReadFile(filepath.Join(dir, expectedFileName))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", expectedFileName, err)
	}
	var expected []reporthandling.RuleResponse
	if err := json.Unmarshal(raw, &expected); err != nil {
		return nil, fmt.Errorf("parse %s: %w", expectedFileName, err)
	}
	return expected, nil
}
