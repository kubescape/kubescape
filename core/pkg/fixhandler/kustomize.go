package fixhandler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"gopkg.in/yaml.v3"
)

// kustomizePatchOp is one JSON 6902 operation in a patch file.
// See https://datatracker.ietf.org/doc/html/rfc6902
type kustomizePatchOp struct {
	Op    string      `yaml:"op"`
	Path  string      `yaml:"path"`
	Value interface{} `yaml:"value"`
}

// kustomizeTarget identifies which Kubernetes resources a patch applies to.
type kustomizeTarget struct {
	Group     string `yaml:"group,omitempty"`
	Version   string `yaml:"version,omitempty"`
	Kind      string `yaml:"kind,omitempty"`
	Name      string `yaml:"name,omitempty"`
	Namespace string `yaml:"namespace,omitempty"`
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
	Resources  []string              `yaml:"resources,omitempty"`
	Patches    []kustomizePatchEntry `yaml:"patches,omitempty"`
}

// resourceKey uniquely identifies a Kubernetes resource across namespace/group/version/kind/name.
type resourceKey struct {
	Group     string
	Version   string
	Kind      string
	Namespace string
	Name      string
}

// resourceGroup holds all fixes and the base resource for a unique resourceKey.
type resourceGroup struct {
	key      resourceKey
	resource *reporthandling.Resource
	fixPaths []armotypes.FixPath
}

// fixPathToJSONPointer converts a dot-notation fix path such as
// "spec.containers[0].securityContext.privileged" to a JSON Pointer
// "/spec/containers/0/securityContext/privileged" per RFC 6901, suitable
// for use as the "path" field in a JSON 6902 patch operation.
func fixPathToJSONPointer(path string) string {
	path = strings.TrimPrefix(path, ".")
	// Replace array notation [N] or [*] with /N or /*
	re := regexp.MustCompile(`\[(\d+|\*)\]`)
	path = re.ReplaceAllString(path, "/$1")
	// Replace dot separators with slashes
	path = strings.ReplaceAll(path, ".", "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

// sanitizeFilenamePart strips path separators and replaces unsafe characters with underscores.
func sanitizeFilenamePart(s string) string {
	s = filepath.Base(s)
	re := regexp.MustCompile(`[^a-zA-Z0-9_.-]`)
	res := re.ReplaceAllString(s, "_")
	res = strings.Trim(res, "._-")
	if res == "" {
		return "resource"
	}
	return res
}

// ensureSubpath verifies that targetPath is cleanly contained inside dir to prevent path traversal attacks.
func ensureSubpath(dir, filename string) (string, error) {
	cleanDir := filepath.Clean(dir)
	targetPath := filepath.Clean(filepath.Join(cleanDir, filename))
	rel, err := filepath.Rel(cleanDir, targetPath)
	if err != nil || strings.HasPrefix(rel, "..") || rel == ".." {
		return "", fmt.Errorf("path traversal attempt detected: %q escapes directory %q", filename, dir)
	}
	return targetPath, nil
}

// parseFixValue parses raw string fix values into their natural Go types (bool, int, float, slice, map, string, nil).
func parseFixValue(raw string) interface{} {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if trimmed == "null" {
		return nil
	}

	var jsonVal interface{}
	if err := json.Unmarshal([]byte(trimmed), &jsonVal); err == nil {
		if f, ok := jsonVal.(float64); ok {
			if f == float64(int64(f)) {
				return int64(f)
			}
		}
		return jsonVal
	}

	if b, err := strconv.ParseBool(trimmed); err == nil {
		return b
	}

	if i, err := strconv.Atoi(trimmed); err == nil {
		return i
	}

	return raw
}

// parseGroupVersion splits an apiVersion such as "apps/v1" or "v1" into group and version.
func parseGroupVersion(apiVersion string) (group, version string) {
	parts := strings.Split(apiVersion, "/")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", apiVersion
}

// checkPathInfo returns whether fixPath exists in obj, whether its parent exists, and how many levels are missing.
func checkPathInfo(obj map[string]interface{}, fixPath string) (exists bool, parentExists bool, missingDepth int) {
	if obj == nil {
		return false, false, 99
	}

	parts, err := parseYAMLPath(fixPath)
	if err != nil || len(parts) == 0 {
		return false, false, 99
	}

	var current interface{} = obj
	for i, part := range parts {
		if current == nil {
			return false, i == len(parts)-1, len(parts) - i
		}

		if part.sequence {
			slice, ok := current.([]interface{})
			if !ok {
				return false, i == len(parts)-1, len(parts) - i
			}
			if part.wildcard {
				if len(slice) == 0 {
					return false, i == len(parts)-1, len(parts) - i
				}
				current = slice[0]
			} else {
				if part.index < 0 || part.index >= len(slice) {
					return false, i == len(parts)-1, len(parts) - i
				}
				current = slice[part.index]
			}
		} else {
			m, ok := current.(map[string]interface{})
			if !ok {
				return false, i == len(parts)-1, len(parts) - i
			}
			val, found := m[part.key]
			if !found {
				return false, i == len(parts)-1, len(parts) - i
			}
			current = val
		}
	}

	return true, true, 0
}

// buildMissingParentValue handles cases where parent objects do not exist (e.g. securityContext missing on container 0).
func buildMissingParentValue(obj map[string]interface{}, fixPath string, val interface{}) (ancestorPointer string, nestedVal interface{}, ok bool) {
	if obj == nil {
		return "", nil, false
	}
	parts, err := parseYAMLPath(fixPath)
	if err != nil || len(parts) == 0 {
		return "", nil, false
	}

	var current interface{} = obj
	lastExistingIdx := -1

	for i, part := range parts {
		if current == nil {
			break
		}
		if part.sequence {
			slice, ok := current.([]interface{})
			if !ok || part.index < 0 || part.index >= len(slice) {
				break
			}
			current = slice[part.index]
			lastExistingIdx = i
		} else {
			m, ok := current.(map[string]interface{})
			if !ok {
				break
			}
			v, found := m[part.key]
			if !found {
				break
			}
			current = v
			lastExistingIdx = i
		}
	}

	if lastExistingIdx < 0 || lastExistingIdx >= len(parts)-1 {
		return "", nil, false
	}

	missingStartIdx := lastExistingIdx + 1

	var ancestorPathParts []string
	for k := 0; k <= missingStartIdx; k++ {
		p := parts[k]
		if p.sequence {
			ancestorPathParts = append(ancestorPathParts, fmt.Sprintf("%d", p.index))
		} else {
			ancestorPathParts = append(ancestorPathParts, p.key)
		}
	}
	ancestorPointer = "/" + strings.Join(ancestorPathParts, "/")

	currVal := val
	for k := len(parts) - 1; k > missingStartIdx; k-- {
		p := parts[k]
		if p.sequence {
			currVal = []interface{}{currVal}
		} else {
			currVal = map[string]interface{}{
				p.key: currVal,
			}
		}
	}

	return ancestorPointer, currVal, true
}

// resolvePatchOp determines whether to use "replace" or "add" for a given fixPath based on base object contents.
func resolvePatchOp(obj map[string]interface{}, fixPath string, val interface{}) (op string, pointer string, finalVal interface{}) {
	pointer = fixPathToJSONPointer(fixPath)
	finalVal = val

	isArrayElementTarget := regexp.MustCompile(`\[\d+\]$`).MatchString(fixPath)
	exists, parentExists, missingDepth := checkPathInfo(obj, fixPath)

	if exists || isArrayElementTarget {
		return "replace", pointer, finalVal
	}

	if parentExists || missingDepth <= 1 {
		return "add", pointer, finalVal
	}

	ancestorPointer, nestedVal, ok := buildMissingParentValue(obj, fixPath, val)
	if ok {
		return "add", ancestorPointer, nestedVal
	}

	return "add", pointer, finalVal
}

// EmitKustomizePatch writes a kustomization.yaml, base.yaml, and one JSON 6902 patch
// file per Helm resource into dir. It is a machine-applicable companion to
// PrintHelmSuggestions: where that function prints human guidance for editing
// values.yaml, this produces patch files and base manifests that can be applied directly to
// Helm-rendered manifests without modifying the original chart.
//
// Usage after generation:
//
//	kustomize build <dir> | kubectl apply -f -
//	helm install my-release ./chart --post-renderer kustomize
//
// Patch files are named <Kind>-[<Namespace>-]<Name>.yaml. The kustomization.yaml lists all
// of them with their kind/name/namespace target selectors and base resources. Nothing is written when
// suggestions is empty.
func EmitKustomizePatch(suggestions []HelmFixSuggestion, dir string) error {
	if len(suggestions) == 0 {
		return nil
	}

	// 1. Group suggestions by unique resourceKey to merge multiple suggestions for the same workload,
	// and prevent overwriting between resources with same kind/name in different namespaces.
	groups := make(map[resourceKey]*resourceGroup)
	var keysInOrder []resourceKey

	for _, s := range suggestions {
		if s.Resource == nil || len(s.FixPaths) == 0 {
			continue
		}

		group, version := parseGroupVersion(s.Resource.GetApiVersion())
		key := resourceKey{
			Group:     group,
			Version:   version,
			Kind:      s.Resource.GetKind(),
			Namespace: s.Resource.GetNamespace(),
			Name:      s.Resource.GetName(),
		}

		rg, exists := groups[key]
		if !exists {
			rg = &resourceGroup{
				key:      key,
				resource: s.Resource,
			}
			groups[key] = rg
			keysInOrder = append(keysInOrder, key)
		}

		rg.fixPaths = append(rg.fixPaths, s.FixPaths...)
	}

	if len(groups) == 0 {
		return nil
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create kustomize output dir %q: %w", dir, err)
	}

	kust := kustomizationDoc{
		APIVersion: "kustomize.config.k8s.io/v1beta1",
		Kind:       "Kustomization",
	}

	// 2. Build base.yaml containing all rendered resources so `kustomize build <dir>` works out of the box.
	var baseYamlParts [][]byte
	for _, key := range keysInOrder {
		rg := groups[key]
		if rg.resource != nil && rg.resource.GetObject() != nil {
			objBytes, err := yaml.Marshal(rg.resource.GetObject())
			if err == nil && len(objBytes) > 0 {
				baseYamlParts = append(baseYamlParts, objBytes)
			}
		}
	}

	if len(baseYamlParts) > 0 {
		baseFilePath, err := ensureSubpath(dir, "base.yaml")
		if err != nil {
			return err
		}
		var baseContent []byte
		for i, part := range baseYamlParts {
			if i > 0 {
				baseContent = append(baseContent, []byte("---\n")...)
			}
			baseContent = append(baseContent, part...)
		}
		if err := os.WriteFile(baseFilePath, baseContent, 0644); err != nil {
			return fmt.Errorf("failed to write base.yaml: %w", err)
		}
		kust.Resources = append(kust.Resources, "base.yaml")
	}

	// 3. Generate one patch file per unique resource
	for _, key := range keysInOrder {
		rg := groups[key]

		var ops []kustomizePatchOp
		for _, fp := range rg.fixPaths {
			if fp.Path == "" {
				continue
			}
			val := parseFixValue(fp.Value)
			var baseObj map[string]interface{}
			if rg.resource != nil {
				baseObj = rg.resource.GetObject()
			}
			op, pointer, adjustedVal := resolvePatchOp(baseObj, fp.Path, val)
			ops = append(ops, kustomizePatchOp{Op: op, Path: pointer, Value: adjustedVal})
		}

		if len(ops) == 0 {
			continue
		}

		sanitizedKind := sanitizeFilenamePart(rg.key.Kind)
		sanitizedName := sanitizeFilenamePart(rg.key.Name)

		var patchFileName string
		if rg.key.Namespace != "" {
			sanitizedNs := sanitizeFilenamePart(rg.key.Namespace)
			patchFileName = fmt.Sprintf("%s-%s-%s.yaml", sanitizedKind, sanitizedNs, sanitizedName)
		} else {
			patchFileName = fmt.Sprintf("%s-%s.yaml", sanitizedKind, sanitizedName)
		}

		patchFilePath, err := ensureSubpath(dir, patchFileName)
		if err != nil {
			return err
		}

		patchBytes, err := yaml.Marshal(ops)
		if err != nil {
			return fmt.Errorf("failed to marshal patch for %s/%s: %w", rg.key.Kind, rg.key.Name, err)
		}
		if err := os.WriteFile(patchFilePath, patchBytes, 0644); err != nil {
			return fmt.Errorf("failed to write patch file %q: %w", patchFileName, err)
		}

		kust.Patches = append(kust.Patches, kustomizePatchEntry{
			Path: patchFileName,
			Target: kustomizeTarget{
				Group:     rg.key.Group,
				Version:   rg.key.Version,
				Kind:      rg.key.Kind,
				Name:      rg.key.Name,
				Namespace: rg.key.Namespace,
			},
		})
	}

	if len(kust.Patches) == 0 {
		return nil
	}

	kustFilePath, err := ensureSubpath(dir, "kustomization.yaml")
	if err != nil {
		return err
	}

	kustBytes, err := yaml.Marshal(kust)
	if err != nil {
		return fmt.Errorf("failed to marshal kustomization.yaml: %w", err)
	}
	return os.WriteFile(kustFilePath, kustBytes, 0644)
}
