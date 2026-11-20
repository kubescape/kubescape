package cautils

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling"
	"gopkg.in/yaml.v3"
	"sigs.k8s.io/kustomize/api/types"
)

// TraceKustomizePatch inspects the Kustomize directory that rendered resource to
// determine if any of the finding paths were introduced or modified by an overlay patch.
// If an identifiable patch is found, it returns the patch file's path relative to
// the scan root (e.g. "overlay/patch.yaml" or "overlay/kustomization.yaml").
// If no patch modifies the given paths, it returns "".
func TraceKustomizePatch(resource workloadinterface.IMetadata, paths []string, source reporthandling.Source) string {
	if resource == nil || len(paths) == 0 {
		return ""
	}
	if source.FileType != reporthandling.SourceTypeKustomizeDirectory || source.KustomizeDirectoryName == "" {
		return ""
	}

	cleanPaths := make([]string, 0, len(paths))
	for _, p := range paths {
		cp := CleanFindingPath(p)
		if cp != "" {
			cleanPaths = append(cleanPaths, cp)
		}
	}
	if len(cleanPaths) == 0 {
		return ""
	}

	kustFile := selectedKustomizationFile(source.KustomizeDirectoryName)
	if kustFile == "" {
		return ""
	}
	contents, err := readKustomizationFile(kustFile)
	if err != nil {
		return ""
	}
	var kustomization types.Kustomization
	if err := kustomization.Unmarshal(contents); err != nil {
		return ""
	}

	// 1. Check kustomization.Patches
	for _, patch := range kustomization.Patches {
		if !matchKustomizeTarget(patch.Target, resource) {
			continue
		}
		var patchData []byte
		var patchPath string
		if patch.Path != "" {
			patchPath = filepath.Clean(filepath.Join(source.KustomizeDirectoryName, filepath.FromSlash(patch.Path)))
			data, err := os.ReadFile(patchPath)
			if err != nil {
				continue
			}
			patchData = data
		} else if patch.Patch != "" {
			patchPath = kustFile
			patchData = []byte(patch.Patch)
		} else {
			continue
		}

		if patchMatchesPaths(patchData, patch.Target, resource, cleanPaths) {
			return formatRelativePatchPath(source.Path, patchPath)
		}
	}

	// 2. Check kustomization.PatchesStrategicMerge
	for _, smp := range kustomization.PatchesStrategicMerge {
		pStr := string(smp)
		var patchData []byte
		var patchPath string
		candidate := filepath.Clean(filepath.Join(source.KustomizeDirectoryName, filepath.FromSlash(pStr)))
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			patchPath = candidate
			data, err := os.ReadFile(candidate)
			if err != nil {
				continue
			}
			patchData = data
		} else {
			patchPath = kustFile
			patchData = []byte(pStr)
		}

		if patchMatchesPaths(patchData, nil, resource, cleanPaths) {
			return formatRelativePatchPath(source.Path, patchPath)
		}
	}

	// 3. Check kustomization.PatchesJson6902
	for _, patch := range kustomization.PatchesJson6902 {
		if !matchKustomizeTarget(patch.Target, resource) {
			continue
		}
		var patchData []byte
		var patchPath string
		if patch.Path != "" {
			patchPath = filepath.Clean(filepath.Join(source.KustomizeDirectoryName, filepath.FromSlash(patch.Path)))
			data, err := os.ReadFile(patchPath)
			if err != nil {
				continue
			}
			patchData = data
		} else if patch.Patch != "" {
			patchPath = kustFile
			patchData = []byte(patch.Patch)
		} else {
			continue
		}

		if patchMatchesPaths(patchData, patch.Target, resource, cleanPaths) {
			return formatRelativePatchPath(source.Path, patchPath)
		}
	}

	return ""
}

// CleanFindingPath extracts the raw dot-notation field path from an evidence entry,
// stripping current value markers, container names, line numbers, or assignment values.
func CleanFindingPath(p string) string {
	p = strings.TrimSpace(p)
	if strings.HasPrefix(p, "@ ") {
		return ""
	}
	if idx := strings.Index(p, " (current: "); idx >= 0 {
		p = p[:idx]
	}
	if idx := strings.Index(p, " ("); idx >= 0 {
		p = p[:idx]
	}
	if idx := strings.Index(p, "="); idx >= 0 {
		p = p[:idx]
	}
	return strings.TrimSpace(p)
}

func matchKustomizeTarget(target *types.Selector, resource workloadinterface.IMetadata) bool {
	if target == nil {
		return true
	}
	if target.Gvk.Kind != "" && !strings.EqualFold(target.Gvk.Kind, resource.GetKind()) {
		return false
	}
	if target.Name != "" && target.Name != resource.GetName() {
		return false
	}
	if target.Namespace != "" && resource.GetNamespace() != "" && target.Namespace != resource.GetNamespace() {
		return false
	}
	apiVersion := resource.GetApiVersion()
	parts := strings.Split(apiVersion, "/")
	var group, version string
	if len(parts) > 1 {
		group = parts[0]
		version = parts[1]
	} else {
		version = parts[0]
	}
	if target.Gvk.Group != "" && !strings.EqualFold(target.Gvk.Group, group) {
		return false
	}
	if target.Gvk.Version != "" && !strings.EqualFold(target.Gvk.Version, version) {
		return false
	}
	return true
}

func patchMatchesPaths(patchData []byte, target *types.Selector, resource workloadinterface.IMetadata, cleanPaths []string) bool {
	var ops []struct {
		Op   string `json:"op" yaml:"op"`
		Path string `json:"path" yaml:"path"`
	}
	if err := yaml.Unmarshal(patchData, &ops); err == nil && len(ops) > 0 && ops[0].Path != "" {
		for _, op := range ops {
			jsonPath := jsonPointerToDotPath(op.Path)
			for _, cp := range cleanPaths {
				if pathMatches(jsonPath, cp) {
					return true
				}
			}
		}
		return false
	}

	var yamlObj map[string]any
	if err := yaml.Unmarshal(patchData, &yamlObj); err == nil && len(yamlObj) > 0 {
		if target == nil {
			if k, ok := yamlObj["kind"].(string); ok && k != "" && !strings.EqualFold(k, resource.GetKind()) {
				return false
			}
			if meta, ok := yamlObj["metadata"].(map[string]any); ok {
				if n, ok := meta["name"].(string); ok && n != "" && n != resource.GetName() {
					return false
				}
				if ns, ok := meta["namespace"].(string); ok && ns != "" && resource.GetNamespace() != "" && ns != resource.GetNamespace() {
					return false
				}
			}
		}
		for _, cp := range cleanPaths {
			if yamlDefinesField(yamlObj, cp) {
				return true
			}
		}
	}
	return false
}

func jsonPointerToDotPath(ptr string) string {
	ptr = strings.TrimPrefix(ptr, "/")
	if ptr == "" {
		return ""
	}
	segments := strings.Split(ptr, "/")
	var parts []string
	for _, seg := range segments {
		seg = strings.ReplaceAll(seg, "~1", "/")
		seg = strings.ReplaceAll(seg, "~0", "~")
		if _, err := strconv.Atoi(seg); err == nil && len(parts) > 0 {
			parts[len(parts)-1] = fmt.Sprintf("%s[%s]", parts[len(parts)-1], seg)
		} else {
			parts = append(parts, seg)
		}
	}
	return strings.Join(parts, ".")
}

func pathMatches(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	normA := strings.ReplaceAll(a, "[0]", "")
	normB := strings.ReplaceAll(b, "[0]", "")
	if normA == normB {
		return true
	}
	if strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a) {
		return true
	}
	return false
}

func yamlDefinesField(obj map[string]any, dotPath string) bool {
	if len(obj) == 0 || dotPath == "" {
		return false
	}
	tokens := splitDotPath(dotPath)
	if len(tokens) == 0 {
		return false
	}
	if walkObject(obj, tokens) {
		return true
	}
	if len(tokens) >= 3 && tokens[0] == "spec" && tokens[1] == "template" && tokens[2] == "spec" {
		shorter := append([]string{"spec"}, tokens[3:]...)
		if walkObject(obj, shorter) {
			return true
		}
	}
	if len(tokens) >= 2 && tokens[0] == "spec" && tokens[1] != "template" {
		longer := append([]string{"spec", "template", "spec"}, tokens[1:]...)
		if walkObject(obj, longer) {
			return true
		}
	}
	return false
}

func splitDotPath(p string) []string {
	parts := strings.Split(p, ".")
	var tokens []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			tokens = append(tokens, part)
		}
	}
	return tokens
}

func walkObject(curr any, tokens []string) bool {
	if len(tokens) == 0 {
		return curr != nil
	}
	token := tokens[0]
	switch val := curr.(type) {
	case map[string]any:
		if idx := strings.Index(token, "["); idx >= 0 && strings.HasSuffix(token, "]") {
			fieldName := token[:idx]
			subVal, ok := val[fieldName]
			if !ok {
				return false
			}
			indexStr := token[idx+1 : len(token)-1]
			arrIndex, err := strconv.Atoi(indexStr)
			if err != nil {
				return false
			}
			return walkObject(subVal, append([]string{fmt.Sprintf("[%d]", arrIndex)}, tokens[1:]...))
		}
		subVal, ok := val[token]
		if !ok {
			return false
		}
		return walkObject(subVal, tokens[1:])
	case []any:
		if strings.HasPrefix(token, "[") && strings.HasSuffix(token, "]") {
			indexStr := token[1 : len(token)-1]
			arrIndex, err := strconv.Atoi(indexStr)
			if err == nil && arrIndex >= 0 && arrIndex < len(val) {
				return walkObject(val[arrIndex], tokens[1:])
			}
			for _, item := range val {
				if walkObject(item, tokens[1:]) {
					return true
				}
			}
			return false
		}
		for _, item := range val {
			if walkObject(item, tokens) {
				return true
			}
		}
		return false
	}
	return false
}

func formatRelativePatchPath(repoRoot, patchPath string) string {
	if repoRoot == "" {
		return filepath.ToSlash(filepath.Clean(patchPath))
	}
	rel, err := filepath.Rel(repoRoot, patchPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(filepath.Clean(patchPath))
	}
	return filepath.ToSlash(filepath.Clean(rel))
}
