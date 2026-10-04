package fixhandler

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// kustomizePatchOp is one JSON 6902 operation in a patch file.
// See https://datatracker.ietf.org/doc/html/rfc6902
type kustomizePatchOp struct {
	Op    string      `yaml:"op"`
	Path  string      `yaml:"path"`
	Value interface{} `yaml:"value,omitempty"`
}

// kustomizeTarget identifies which Kubernetes resources a patch applies to.
type kustomizeTarget struct {
	Kind string `yaml:"kind"`
	Name string `yaml:"name"`
}

// kustomizePatchEntry is a single entry in kustomization.yaml patches list.
type kustomizePatchEntry struct {
	Path   string          `yaml:"path"`
	Target kustomizeTarget `yaml:"target"`
}

// kustomizationDoc is the document written as kustomization.yaml.
type kustomizationDoc struct {
	APIVersion string                `yaml:"apiVersion"`
	Kind       string                `yaml:"kind"`
	Patches    []kustomizePatchEntry `yaml:"patches"`
}

// fixPathToJSONPointer converts a dot-notation fix path such as
// "spec.containers[0].securityContext.privileged" to a JSON Pointer
// "/spec/containers/0/securityContext/privileged" per RFC 6901, suitable
// for use as the "path" field in a JSON 6902 patch operation.
func fixPathToJSONPointer(path string) string {
	// Replace array notation [N] or [*] with /N or /*
	re := regexp.MustCompile(`\[(\d+|\*)\]`)
	path = re.ReplaceAllString(path, "/$1")
	// Replace dot separators with slashes
	path = strings.ReplaceAll(path, ".", "/")
	return "/" + path
}

// EmitKustomizePatch writes a kustomization.yaml and one JSON 6902 patch
// file per Helm resource into dir. It is a machine-applicable companion to
// PrintHelmSuggestions: where that function prints human guidance for editing
// values.yaml, this produces patch files that can be applied directly to
// Helm-rendered manifests without modifying the original chart.
//
// Usage after generation:
//
//	kustomize build <dir> | kubectl apply -f -
//	helm install my-release ./chart --post-renderer kustomize
//
// Patch files are named <Kind>-<name>.yaml. The kustomization.yaml lists all
// of them with their kind/name target selectors. Nothing is written when
// suggestions is empty.
func EmitKustomizePatch(suggestions []HelmFixSuggestion, dir string) error {
	if len(suggestions) == 0 {
		return nil
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create kustomize output dir %q: %w", dir, err)
	}

	kust := kustomizationDoc{
		APIVersion: "kustomize.config.k8s.io/v1beta1",
		Kind:       "Kustomization",
	}

	for _, s := range suggestions {
		if len(s.FixPaths) == 0 {
			continue
		}

		kind := s.Resource.GetKind()
		name := s.Resource.GetName()

		var ops []kustomizePatchOp
		for _, fp := range s.FixPaths {
			if fp.Path == "" {
				continue
			}
			pointer := fixPathToJSONPointer(fp.Path)
			op := "replace"
			if fp.Value == "" {
				op = "remove"
			}

			var val interface{}
			if op != "remove" {
				// Parse value to its natural type so YAML/JSON patch is correctly typed.
				if b, err := strconv.ParseBool(fp.Value); err == nil {
					val = b
				} else if i, err := strconv.Atoi(fp.Value); err == nil {
					val = i
				} else {
					val = fp.Value
				}
			}

			ops = append(ops, kustomizePatchOp{Op: op, Path: pointer, Value: val})
		}

		if len(ops) == 0 {
			continue
		}

		// Patch file named <Kind>-<name>.yaml, e.g. "Deployment-nginx.yaml"
		patchFileName := fmt.Sprintf("%s-%s.yaml", kind, name)
		patchBytes, err := yaml.Marshal(ops)
		if err != nil {
			return fmt.Errorf("failed to marshal patch for %s/%s: %w", kind, name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, patchFileName), patchBytes, 0644); err != nil {
			return fmt.Errorf("failed to write patch file %q: %w", patchFileName, err)
		}

		kust.Patches = append(kust.Patches, kustomizePatchEntry{
			Path:   patchFileName,
			Target: kustomizeTarget{Kind: kind, Name: name},
		})
	}

	if len(kust.Patches) == 0 {
		return nil
	}

	kustBytes, err := yaml.Marshal(kust)
	if err != nil {
		return fmt.Errorf("failed to marshal kustomization.yaml: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, "kustomization.yaml"), kustBytes, 0644)
}
