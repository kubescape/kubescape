package cautils

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/labels"
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

	// Unify all patches in Kustomize application order:
	// 1. patchesStrategicMerge (legacy)
	// 2. patchesJson6902 (legacy)
	// 3. patches (modern)
	var allPatches []types.Patch

	for _, smp := range kustomization.PatchesStrategicMerge { //nolint:staticcheck // SA1019: legacy patchesStrategicMerge must still be traced for backwards compatibility
		pStr := string(smp)
		candidate := filepath.Clean(filepath.Join(source.KustomizeDirectoryName, filepath.FromSlash(pStr)))
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			allPatches = append(allPatches, types.Patch{Path: pStr})
		} else {
			allPatches = append(allPatches, types.Patch{Patch: pStr})
		}
	}

	allPatches = append(allPatches, kustomization.PatchesJson6902...) //nolint:staticcheck // SA1019: legacy patchesJson6902 must still be traced for backwards compatibility

	allPatches = append(allPatches, kustomization.Patches...)

	var effectivePatch string
	for _, patch := range allPatches {
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
			effectivePatch = formatRelativePatchPath(source.Path, patchPath)
		}
	}

	return effectivePatch
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

func getMetadataMap(resource workloadinterface.IMetadata, key string) map[string]string {
	if resource == nil {
		return nil
	}
	obj := resource.GetObject()
	if obj == nil {
		return nil
	}
	meta, ok := obj["metadata"].(map[string]any)
	if !ok {
		return nil
	}
	raw, ok := meta[key].(map[string]any)
	if !ok {
		return nil
	}
	res := make(map[string]string, len(raw))
	for k, v := range raw {
		if s, ok := v.(string); ok {
			res[k] = s
		}
	}
	return res
}

func matchKustomizeTarget(target *types.Selector, resource workloadinterface.IMetadata) bool {
	if target == nil {
		return true
	}
	if target.Kind != "" && !strings.EqualFold(target.Kind, resource.GetKind()) {
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
	if target.Group != "" && !strings.EqualFold(target.Group, group) {
		return false
	}
	if target.Version != "" && !strings.EqualFold(target.Version, version) {
		return false
	}
	if target.LabelSelector != "" {
		sel, err := labels.Parse(target.LabelSelector)
		if err != nil || !sel.Matches(labels.Set(getMetadataMap(resource, "labels"))) {
			return false
		}
	}
	if target.AnnotationSelector != "" {
		sel, err := labels.Parse(target.AnnotationSelector)
		if err != nil || !sel.Matches(labels.Set(getMetadataMap(resource, "annotations"))) {
			return false
		}
	}
	return true
}

func matchYamlHeader(yamlObj map[string]any, resource workloadinterface.IMetadata) bool {
	if k, ok := yamlObj["kind"].(string); ok && k != "" && !strings.EqualFold(k, resource.GetKind()) {
		return false
	}
	if apiVer, ok := yamlObj["apiVersion"].(string); ok && apiVer != "" {
		if !strings.EqualFold(apiVer, resource.GetApiVersion()) {
			return false
		}
	}
	if meta, ok := yamlObj["metadata"].(map[string]any); ok {
		if n, ok := meta["name"].(string); ok && n != "" && n != resource.GetName() {
			return false
		}
		if ns, ok := meta["namespace"].(string); ok && ns != "" && resource.GetNamespace() != "" && ns != resource.GetNamespace() {
			return false
		}
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
			if strings.EqualFold(op.Op, "test") {
				continue
			}
			jsonPath := jsonPointerToDotPath(op.Path)
			for _, cp := range cleanPaths {
				if pathMatches(jsonPath, cp) {
					return true
				}
			}
		}
		return false
	}

	dec := yaml.NewDecoder(bytes.NewReader(patchData))
	for {
		var yamlObj map[string]any
		err := dec.Decode(&yamlObj)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(yamlObj) == 0 {
			continue
		}
		if target == nil {
			if !matchYamlHeader(yamlObj, resource) {
				continue
			}
		}
		for _, cp := range cleanPaths {
			if yamlDefinesField(yamlObj, cp, resource) {
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

func yamlDefinesField(obj map[string]any, dotPath string, resource workloadinterface.IMetadata) bool {
	if len(obj) == 0 || dotPath == "" {
		return false
	}
	tokens := splitDotPath(dotPath)
	if len(tokens) == 0 {
		return false
	}
	if walkObject(obj, tokens, resource, nil) {
		return true
	}
	if len(tokens) >= 3 && tokens[0] == "spec" && tokens[1] == "template" && tokens[2] == "spec" {
		shorter := append([]string{"spec"}, tokens[3:]...)
		if walkObject(obj, shorter, resource, []string{"spec", "template"}) {
			return true
		}
	}
	if len(tokens) >= 2 && tokens[0] == "spec" && tokens[1] != "template" {
		longer := append([]string{"spec", "template", "spec"}, tokens[1:]...)
		if walkObject(obj, longer, resource, nil) {
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

func getRenderedElementName(resource workloadinterface.IMetadata, prefixTokens []string) string {
	if resource == nil {
		return ""
	}
	var curr any = resource.GetObject()
	for _, tok := range prefixTokens {
		if curr == nil {
			return ""
		}
		if idx := strings.Index(tok, "["); idx >= 0 && strings.HasSuffix(tok, "]") {
			fieldName := tok[:idx]
			m, ok := curr.(map[string]any)
			if !ok {
				return ""
			}
			arr, ok := m[fieldName].([]any)
			if !ok {
				return ""
			}
			indexStr := tok[idx+1 : len(tok)-1]
			i, err := strconv.Atoi(indexStr)
			if err != nil || i < 0 || i >= len(arr) {
				return ""
			}
			curr = arr[i]
		} else {
			m, ok := curr.(map[string]any)
			if !ok {
				return ""
			}
			curr = m[tok]
		}
	}
	if elemMap, ok := curr.(map[string]any); ok {
		if n, ok := elemMap["name"].(string); ok {
			return n
		}
	}
	return ""
}

func walkObject(curr any, tokens []string, resource workloadinterface.IMetadata, traversed []string) bool {
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
			prefix := append(traversed, token)
			targetName := getRenderedElementName(resource, prefix)
			if subSlice, ok := subVal.([]any); ok {
				if targetName != "" {
					for _, item := range subSlice {
						if itemMap, ok := item.(map[string]any); ok {
							if n, ok := itemMap["name"].(string); ok && n == targetName {
								return walkObject(item, tokens[1:], resource, prefix)
							}
						}
					}
					return false
				}
				if arrIndex >= 0 && arrIndex < len(subSlice) {
					return walkObject(subSlice[arrIndex], tokens[1:], resource, prefix)
				}
				return false
			}
			return false
		}
		subVal, ok := val[token]
		if !ok {
			return false
		}
		return walkObject(subVal, tokens[1:], resource, append(traversed, token))
	case []any:
		if strings.HasPrefix(token, "[") && strings.HasSuffix(token, "]") {
			indexStr := token[1 : len(token)-1]
			arrIndex, err := strconv.Atoi(indexStr)
			if err != nil {
				return false
			}
			targetName := getRenderedElementName(resource, traversed)
			if targetName != "" {
				for _, item := range val {
					if itemMap, ok := item.(map[string]any); ok {
						if n, ok := itemMap["name"].(string); ok && n == targetName {
							return walkObject(item, tokens[1:], resource, traversed)
						}
					}
				}
				return false
			}
			if arrIndex >= 0 && arrIndex < len(val) {
				return walkObject(val[arrIndex], tokens[1:], resource, traversed)
			}
			return false
		}
		for _, item := range val {
			if walkObject(item, tokens, resource, traversed) {
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
