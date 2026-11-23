package cautils

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/pathcontainment"
	"github.com/kubescape/opa-utils/reporthandling"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/kustomize/api/konfig"
	"sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/resid"
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
	// 2. patches (modern), before name, label and annotation transformers
	// 3. patchesJson6902 (legacy), after those transformers
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

	allPatches = append(allPatches, kustomization.Patches...)
	beforeTransformers := len(allPatches)
	allPatches = append(allPatches, kustomization.PatchesJson6902...) //nolint:staticcheck // trace legacy patches

	// Walk backwards. Once a possible writer cannot be resolved, reporting an
	// earlier writer would be just as misleading as reporting the uncertain one.
	if len(kustomization.Replacements) != 0 || len(kustomization.Transformers) != 0 {
		return ""
	}
	// The replica transformer runs after every patch and matches any name the
	// resource ever had, so a rendered count equal to an entry may be its own.
	tracesReplicas := slices.ContainsFunc(cleanPaths, func(p string) bool { return pathMatches(p, "spec.replicas") })
	spec, _ := resource.GetObject()["spec"].(map[string]any)
	for _, r := range kustomization.Replicas {
		if tracesReplicas && fmt.Sprint(spec["replicas"]) == strconv.FormatInt(r.Count, 10) {
			return ""
		}
	}
	// Patches also select by the name and namespace a nested base or component
	// gave the resource first, which this directory alone cannot reveal.
	hiddenOrigin := len(kustomization.Components) != 0
	inputs := append(slices.Clone(kustomization.Resources), kustomization.Bases...) //nolint:staticcheck // Legacy bases are still nested inputs.
	for _, entry := range inputs {
		path, err := pathcontainment.ResolveContainedPath(source.KustomizeDirectoryName, entry)
		if err != nil {
			hiddenOrigin = true
			continue
		}
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			hiddenOrigin = true
		}
	}
	legacyLabels := len(kustomization.CommonLabels) != 0 //nolint:staticcheck // Legacy commonLabels still changes patch selection metadata.
	metadataKnown := true
	identityKnown := true
	originalName := resource.GetName()
	if kustomization.NamePrefix != "" || kustomization.NameSuffix != "" {
		switch {
		case resource.GetKind() == "Namespace", resource.GetKind() == "CustomResourceDefinition", resource.GetKind() == "APIService" && strings.HasPrefix(resource.GetApiVersion(), "apiregistration.k8s.io/"):
			// Kustomize skips these built-in identities when adding affixes.
		default:
			name, ok := strings.CutPrefix(originalName, kustomization.NamePrefix)
			if !ok {
				return ""
			}
			originalName, ok = strings.CutSuffix(name, kustomization.NameSuffix)
			if !ok || originalName == "" {
				return ""
			}
		}
	}
	orgName, orgNamespace := originalName, ""
	if hiddenOrigin {
		if org := recordedOrigin(source, resource, originalName); org != nil {
			// The recorded file gives the first name and the rendered one the
			// last. A base chain that renames twice keeps a middle name that
			// only merge patches select, and that case is still not traced.
			hiddenOrigin = false
			orgName, orgNamespace = org.GetName(), org.GetNamespace()
		}
	}
	for i := len(allPatches) - 1; i >= 0; i-- {
		patch := allPatches[i]
		if i == beforeTransformers-1 && (len(kustomization.Labels) != 0 || legacyLabels || len(kustomization.CommonAnnotations) != 0) {
			metadataKnown = false
		}
		data := []byte(patch.Patch)
		path := kustFile
		if patch.Path != "" {
			path, err = pathcontainment.ResolveContainedPath(source.KustomizeDirectoryName, filepath.FromSlash(patch.Path))
			if err != nil {
				return ""
			}
			data, err = readKustomizationFile(path)
			path = filepath.Join(source.KustomizeDirectoryName, filepath.FromSlash(patch.Path))
			if err != nil {
				return ""
			}
		}

		docs, err := splitYAMLDocuments(data)
		if err != nil {
			return ""
		}
		matched, maybe := false, false
		for _, doc := range docs {
			if len(docs) > 1 {
				// Kustomize reads JSON operations from the first document only.
				// Only strategic-merge mappings can be traced across documents.
				var mapping map[string]any
				if err := yaml.Unmarshal(doc, &mapping); err != nil || mapping == nil {
					return ""
				}
			}
			if !isPatchDocumentProvablySafe(doc) || (patch.Options != nil && (patch.Options.AllowNameChange || patch.Options.AllowKindChange)) {
				identityKnown = false
				metadataKnown = false
			}
			match, err := patchMatchesPaths(doc, patch.Target, resource, originalName, cleanPaths)
			if err != nil {
				return ""
			}
			if !match && patch.Target == nil && orgName != originalName {
				// Merge patches select by any name the resource has had.
				match, _ = patchMatchesPaths(doc, nil, resource, orgName, cleanPaths)
			}
			if !match && hiddenOrigin && patch.Target == nil {
				// It may name an original identity we cannot see.
				anyName, _ := patchMatchesPaths(doc, nil, resource, "", cleanPaths)
				maybe = maybe || anyName
			}
			matched = matched || match
		}
		if !matched {
			if maybe {
				return ""
			}
			continue
		}
		selection := resource
		target := patch.Target
		if target == nil && !identityKnown {
			return ""
		}
		if target != nil && target.Namespace != "" && i < beforeTransformers && kustomization.Namespace != "" {
			// The rendered namespace may differ from the one used for selection.
			return ""
		}
		if target != nil && (!identityKnown || (!metadataKnown && (target.LabelSelector != "" || target.AnnotationSelector != ""))) {
			// A direct resource is exactly the input to the first overlay patch.
			// For intermediate or composed resources we cannot reconstruct the
			// selection metadata reliably from either end of the build.
			if i != 0 || i >= beforeTransformers || len(kustomization.Components) != 0 {
				return ""
			}
			selection = directPatchInput(kustomization.Resources, source, resource, originalName)
			if selection == nil {
				return ""
			}
		}
		if target != nil && len(kustomization.BuildMetadata) != 0 && selectsBuildMetadata(target) {
			return ""
		}
		if target != nil && orgNamespace != "" && target.Namespace == orgNamespace {
			// Kustomize also accepts the namespace the resource started with.
			original := *target
			original.Namespace = ""
			target = &original
		}
		if matchKustomizeTarget(target, selection, originalName) ||
			(target != nil && orgName != originalName && matchKustomizeTarget(target, selection, orgName)) ||
			(i >= beforeTransformers && matchKustomizeTarget(target, selection, resource.GetName())) {
			return formatRelativePatchPath(source.Path, path)
		}
		if hiddenOrigin && target != nil {
			anyIdentity := *target
			anyIdentity.Name, anyIdentity.Namespace = "", ""
			if matchKustomizeTarget(&anyIdentity, selection, originalName) {
				return ""
			}
		}
	}
	return ""
}

// recordedOrigin reads the resource as written in its recorded origin file,
// before any kustomization renamed it. It needs a single plausible document.
func recordedOrigin(source reporthandling.Source, rendered workloadinterface.IMetadata, name string) workloadinterface.IMetadata {
	if source.Path == "" || source.RelativePath == "" {
		return nil
	}
	origin, err := pathcontainment.ResolveContainedPath(source.Path, source.RelativePath)
	if err != nil {
		return nil
	}
	data, err := readKustomizationFile(origin)
	if err != nil {
		return nil
	}
	docs, err := splitYAMLDocuments(data)
	if err != nil {
		return nil
	}
	var candidates []workloadinterface.IMetadata
	for _, doc := range docs {
		var obj map[string]any
		if err := yaml.Unmarshal(doc, &obj); err != nil || obj == nil {
			continue
		}
		input := workloadinterface.NewWorkloadObj(obj)
		if input.GetKind() != rendered.GetKind() || input.GetApiVersion() != rendered.GetApiVersion() {
			continue
		}
		if input.GetName() == name {
			return input
		}
		candidates = append(candidates, input)
	}
	if len(candidates) == 1 {
		return candidates[0]
	}
	return nil
}

// kustomizeTransformationsAnnotation is where buildMetadata: [transformerAnnotations]
// records the transformers that changed a resource.
const kustomizeTransformationsAnnotation = "alpha.config.kubernetes.io/transformations"

// selectsBuildMetadata reports whether a selector reads metadata that Kustomize
// writes after the whole build or tracks internally, so the rendered value
// says nothing about what the patch saw. An unparsable selector counts as one.
func selectsBuildMetadata(target *types.Selector) bool {
	reads := func(selector string, keys ...string) bool {
		if selector == "" {
			return false
		}
		sel, err := labels.Parse(selector)
		if err != nil {
			return true
		}
		requirements, _ := sel.Requirements()
		return slices.ContainsFunc(requirements, func(r labels.Requirement) bool { return slices.Contains(keys, r.Key()) })
	}
	return reads(target.LabelSelector, konfig.ManagedbyLabelKey) ||
		reads(target.AnnotationSelector, kustomizeOriginAnnotation, kustomizeTransformationsAnnotation)
}

// directPatchInput identifies a single input document from the recorded origin
// or, for directory-only evidence, from the sole declared resource and its identity.
func directPatchInput(resources []string, source reporthandling.Source, rendered workloadinterface.IMetadata, name string) workloadinterface.IMetadata {
	if source.Path == "" || source.RelativePath == "" {
		return nil
	}
	origin, err := pathcontainment.ResolveContainedPath(source.Path, source.RelativePath)
	if err != nil {
		return nil
	}
	// With selectors, origin tracking can retain only the directory. Its
	// sole direct input can still be identified by its Kubernetes identity.
	directory, err := pathcontainment.ResolveContainedPath(source.KustomizeDirectoryName, ".")
	if err != nil {
		return nil
	}
	singleInput := len(resources) == 1 && origin == directory
	for _, entry := range resources {
		path, err := pathcontainment.ResolveContainedPath(source.KustomizeDirectoryName, entry)
		if err != nil || (!singleInput && path != origin) {
			continue
		}
		data, err := readKustomizationFile(path)
		if err != nil {
			return nil
		}
		docs, err := splitYAMLDocuments(data)
		if err != nil || len(docs) != 1 {
			return nil
		}
		var obj map[string]any
		if err := yaml.Unmarshal(docs[0], &obj); err != nil {
			return nil
		}
		input := workloadinterface.NewWorkloadObj(obj)
		if input.GetName() == name && (!singleInput || input.GetNamespace() == rendered.GetNamespace()) && input.GetKind() == rendered.GetKind() && input.GetApiVersion() == rendered.GetApiVersion() {
			return input
		}
	}
	return nil
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

func matchKustomizeTarget(target *types.Selector, resource workloadinterface.IMetadata, name string) bool {
	if target == nil {
		return true
	}
	selector, err := types.NewSelectorRegex(target)
	if err != nil {
		return false
	}
	group, version := resid.ParseGroupVersion(resource.GetApiVersion())
	id := resid.NewResIdWithNamespace(resid.NewGvk(group, version, resource.GetKind()), name, resource.GetNamespace())
	if !selector.MatchName(name) || !selector.MatchGvk(id.Gvk) || !selector.MatchNamespace(id.EffectiveNamespace()) {
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

// matchYamlHeader reports whether a merge patch header selects resource under
// name. An empty name accepts any patch name.
func matchYamlHeader(yamlObj map[string]any, resource workloadinterface.IMetadata, name string) bool {
	if k, ok := yamlObj["kind"].(string); ok && k != "" && !strings.EqualFold(k, resource.GetKind()) {
		return false
	}
	if apiVer, ok := yamlObj["apiVersion"].(string); ok && apiVer != "" {
		if !strings.EqualFold(apiVer, resource.GetApiVersion()) {
			return false
		}
	}
	if meta, ok := yamlObj["metadata"].(map[string]any); ok {
		if n, ok := meta["name"].(string); ok && n != "" && name != "" && n != name {
			return false
		}
		if ns, ok := meta["namespace"].(string); ok && ns != "" && resource.GetNamespace() != "" && ns != resource.GetNamespace() {
			return false
		}
	}
	return true
}

func patchMatchesPaths(patchData []byte, target *types.Selector, resource workloadinterface.IMetadata, name string, cleanPaths []string) (bool, error) {
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
					return true, nil
				}
			}
		}
		return false, nil
	}

	var obj map[string]any
	if err := yaml.Unmarshal(patchData, &obj); err != nil {
		return false, err
	}
	if target == nil && !matchYamlHeader(obj, resource, name) {
		return false, nil
	}
	for _, cp := range cleanPaths {
		if yamlDefinesField(obj, cp, resource) {
			return true, nil
		}
	}
	return false, nil
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
