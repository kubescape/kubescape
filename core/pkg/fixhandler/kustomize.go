package fixhandler

import (
	"crypto/sha256"
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

// escapeJSONPointerToken escapes '~' to '~0' and '/' to '~1' per RFC 6901.
func escapeJSONPointerToken(token string) string {
	token = strings.ReplaceAll(token, "~", "~0")
	token = strings.ReplaceAll(token, "/", "~1")
	return token
}

// fixPathToJSONPointer converts a dot-notation or quoted-key fix path such as
// "spec.containers[0].securityContext.privileged" or
// "metadata.labels.\"app.kubernetes.io/name\""
// to an RFC 6901 compliant JSON Pointer suitable for JSON 6902 patch operations.
// Wildcards are not valid in RFC 6901 JSON Pointers and will return an error.
func fixPathToJSONPointer(path string) (string, error) {
	parts, err := parseYAMLPath(path)
	if err != nil {
		return "", fmt.Errorf("invalid fix path %q: %w", path, err)
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("empty fix path %q", path)
	}

	var tokens []string
	for _, part := range parts {
		if part.sequence {
			if part.wildcard {
				return "", fmt.Errorf("wildcard in path %q cannot be represented as JSON Pointer without concrete index", path)
			}
			tokens = append(tokens, strconv.Itoa(part.index))
		} else {
			tokens = append(tokens, escapeJSONPointerToken(part.key))
		}
	}

	return "/" + strings.Join(tokens, "/"), nil
}

// computeResourceHash returns a deterministic short hex hash representing the full resource identity.
func computeResourceHash(key resourceKey) string {
	h := sha256.New()
	h.Write([]byte(key.Group))
	h.Write([]byte{0})
	h.Write([]byte(key.Version))
	h.Write([]byte{0})
	h.Write([]byte(key.Kind))
	h.Write([]byte{0})
	h.Write([]byte(key.Namespace))
	h.Write([]byte{0})
	h.Write([]byte(key.Name))
	return fmt.Sprintf("%x", h.Sum(nil))[:8]
}

// resourcePatchFilename generates an unambiguous patch filename encoding the full resource identity.
func resourcePatchFilename(key resourceKey) string {
	hash := computeResourceHash(key)
	var parts []string
	if key.Group != "" {
		parts = append(parts, sanitizeFilenamePart(key.Group))
	}
	parts = append(parts, sanitizeFilenamePart(key.Kind))
	if key.Namespace != "" {
		parts = append(parts, sanitizeFilenamePart(key.Namespace))
	}
	parts = append(parts, sanitizeFilenamePart(key.Name))
	parts = append(parts, hash)
	return fmt.Sprintf("%s.yaml", strings.Join(parts, "-"))
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

// deepCopyMap creates an isolated deep copy of a resource map object.
func deepCopyMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	var res map[string]interface{}
	if err := json.Unmarshal(b, &res); err != nil {
		return nil
	}
	return res
}

// expandWildcardFixPaths expands wildcard fix paths such as
// "spec.template.spec.containers[*].securityContext.privileged" into concrete index paths
// using the rendered resource object.
func expandWildcardFixPaths(obj map[string]interface{}, fp armotypes.FixPath) []armotypes.FixPath {
	parts, err := parseYAMLPath(fp.Path)
	if err != nil || len(parts) == 0 {
		return []armotypes.FixPath{fp}
	}

	wildcardIdx := -1
	for i, part := range parts {
		if part.sequence && part.wildcard {
			wildcardIdx = i
			break
		}
	}
	if wildcardIdx == -1 {
		return []armotypes.FixPath{fp}
	}

	var current interface{} = obj
	for i := 0; i < wildcardIdx; i++ {
		if current == nil {
			return nil
		}
		p := parts[i]
		if p.sequence {
			slice, ok := current.([]interface{})
			if !ok || p.index < 0 || p.index >= len(slice) {
				return nil
			}
			current = slice[p.index]
		} else {
			m, ok := current.(map[string]interface{})
			if !ok {
				return nil
			}
			current = m[p.key]
		}
	}

	slice, ok := current.([]interface{})
	if !ok || len(slice) == 0 {
		return nil
	}

	var expanded []armotypes.FixPath
	for idx := range slice {
		var newParts []string
		for i, p := range parts {
			if i == wildcardIdx {
				newParts = append(newParts, fmt.Sprintf("[%d]", idx))
			} else if p.sequence {
				if p.wildcard {
					newParts = append(newParts, "[*]")
				} else {
					newParts = append(newParts, fmt.Sprintf("[%d]", p.index))
				}
			} else {
				if strings.ContainsAny(p.key, "./\"[]") {
					newParts = append(newParts, fmt.Sprintf("%q", p.key))
				} else {
					newParts = append(newParts, p.key)
				}
			}
		}
		var b strings.Builder
		for j, np := range newParts {
			if strings.HasPrefix(np, "[") {
				b.WriteString(np)
			} else {
				if j > 0 {
					b.WriteByte('.')
				}
				b.WriteString(np)
			}
		}
		childFP := armotypes.FixPath{
			Path:  b.String(),
			Value: fp.Value,
		}
		expanded = append(expanded, expandWildcardFixPaths(obj, childFP)...)
	}

	return expanded
}

// resolveFixPathOps resolves a concrete FixPath against an evolving working copy of the resource.
// If intermediate ancestor maps are missing, it emits an "add" op creating the ancestor as {}
// once, updates the evolving copy, and resolves child fields so sibling fixes sharing a missing
// parent are both preserved.
func resolveFixPathOps(workingObj map[string]interface{}, fp armotypes.FixPath) []kustomizePatchOp {
	parts, err := parseYAMLPath(fp.Path)
	if err != nil || len(parts) == 0 {
		return nil
	}

	parsedVal := parseFixValue(fp.Value)
	var ops []kustomizePatchOp
	var pointerTokens []string
	var current interface{} = workingObj

	for i, part := range parts {
		isLast := i == len(parts)-1

		if !isLast {
			if part.sequence {
				pointerTokens = append(pointerTokens, strconv.Itoa(part.index))
				slice, ok := current.([]interface{})
				if !ok || part.index < 0 || part.index >= len(slice) {
					return nil
				}
				current = slice[part.index]
			} else {
				pointerTokens = append(pointerTokens, escapeJSONPointerToken(part.key))
				m, ok := current.(map[string]interface{})
				if !ok {
					return nil
				}
				nextVal, exists := m[part.key]
				if !exists || nextVal == nil {
					newMap := make(map[string]interface{})
					ancestorPtr := "/" + strings.Join(pointerTokens, "/")
					ops = append(ops, kustomizePatchOp{
						Op:    "add",
						Path:  ancestorPtr,
						Value: newMap,
					})
					m[part.key] = newMap
					current = newMap
				} else {
					current = nextVal
				}
			}
		} else {
			if part.sequence {
				pointerTokens = append(pointerTokens, strconv.Itoa(part.index))
				targetPtr := "/" + strings.Join(pointerTokens, "/")
				slice, ok := current.([]interface{})
				if ok && part.index >= 0 && part.index < len(slice) {
					ops = append(ops, kustomizePatchOp{
						Op:    "replace",
						Path:  targetPtr,
						Value: parsedVal,
					})
					slice[part.index] = parsedVal
				} else {
					ops = append(ops, kustomizePatchOp{
						Op:    "add",
						Path:  targetPtr,
						Value: parsedVal,
					})
				}
			} else {
				pointerTokens = append(pointerTokens, escapeJSONPointerToken(part.key))
				targetPtr := "/" + strings.Join(pointerTokens, "/")
				m, ok := current.(map[string]interface{})
				if !ok {
					return nil
				}
				op := "add"
				if _, exists := m[part.key]; exists {
					op = "replace"
				}
				ops = append(ops, kustomizePatchOp{
					Op:    op,
					Path:  targetPtr,
					Value: parsedVal,
				})
				m[part.key] = parsedVal
			}
		}
	}

	return ops
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
//
// Patch files are named unambiguously to encode the full resource identity and prevent
// collisions. The saved base.yaml acts as a snapshot of rendered resources with suggestions.
// Output directory and files are written with restricted permissions (0700/0600) to protect
// rendered manifests that may contain sensitive data.
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

	// Restrict permissions on the output directory containing rendered manifests.
	if err := os.MkdirAll(dir, 0700); err != nil {
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
		// Write base.yaml with mode 0600 to protect potentially sensitive rendered resources.
		if err := os.WriteFile(baseFilePath, baseContent, 0600); err != nil {
			return fmt.Errorf("failed to write base.yaml: %w", err)
		}
		kust.Resources = append(kust.Resources, "base.yaml")
	}

	// 3. Generate one patch file per unique resource
	writtenFiles := make(map[string]resourceKey)

	for _, key := range keysInOrder {
		rg := groups[key]

		var baseObj map[string]interface{}
		if rg.resource != nil {
			baseObj = rg.resource.GetObject()
		}
		workingObj := deepCopyMap(baseObj)

		// Expand any wildcard paths into concrete indices
		var concreteFixPaths []armotypes.FixPath
		for _, fp := range rg.fixPaths {
			if fp.Path == "" {
				continue
			}
			expanded := expandWildcardFixPaths(workingObj, fp)
			concreteFixPaths = append(concreteFixPaths, expanded...)
		}

		var ops []kustomizePatchOp
		for _, fp := range concreteFixPaths {
			patchOps := resolveFixPathOps(workingObj, fp)
			ops = append(ops, patchOps...)
		}

		if len(ops) == 0 {
			continue
		}

		patchFileName := resourcePatchFilename(rg.key)
		if existingKey, exists := writtenFiles[patchFileName]; exists {
			return fmt.Errorf("filename collision detected: patch file %q for resource %s/%s collides with %s/%s",
				patchFileName, rg.key.Kind, rg.key.Name, existingKey.Kind, existingKey.Name)
		}
		writtenFiles[patchFileName] = rg.key

		patchFilePath, err := ensureSubpath(dir, patchFileName)
		if err != nil {
			return err
		}

		patchBytes, err := yaml.Marshal(ops)
		if err != nil {
			return fmt.Errorf("failed to marshal patch for %s/%s: %w", rg.key.Kind, rg.key.Name, err)
		}
		if err := os.WriteFile(patchFilePath, patchBytes, 0600); err != nil {
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
	return os.WriteFile(kustFilePath, kustBytes, 0600)
}
