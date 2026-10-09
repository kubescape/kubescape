package fixhandler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"gopkg.in/yaml.v3"
)

// KustomizeEmitResult records the outcome of generating Kustomize patches for Helm resources.
type KustomizeEmitResult struct {
	EmittedResources []string
	SkippedResources []KustomizeSkippedResource
}

// KustomizeSkippedResource records a resource that was declined/skipped during patch generation.
type KustomizeSkippedResource struct {
	ResourceKey string
	Reason      string
}

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
	baseObj  map[string]interface{}
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

// hasRedactedPlaceholder checks if the object contains the scan redactor's "XXXXXX" placeholder
// in container environment variables, secret data, or configmap data.
func hasRedactedPlaceholder(data interface{}) bool {
	switch v := data.(type) {
	case map[string]interface{}:
		for _, field := range []string{"data", "stringData", "binaryData"} {
			if m, ok := v[field].(map[string]interface{}); ok {
				for _, val := range m {
					if s, ok := val.(string); ok && s == "XXXXXX" {
						return true
					}
				}
			}
		}
		if envList, ok := v["env"].([]interface{}); ok {
			for _, item := range envList {
				if envMap, ok := item.(map[string]interface{}); ok {
					if val, ok := envMap["value"].(string); ok && val == "XXXXXX" {
						return true
					}
				}
			}
		}
		for _, child := range v {
			if hasRedactedPlaceholder(child) {
				return true
			}
		}
	case []interface{}:
		for _, child := range v {
			if hasRedactedPlaceholder(child) {
				return true
			}
		}
	}
	return false
}

// resolveBaseObject determines the verified unredacted base Kubernetes object for a suggestion.
// Because the scan redactor (removeData / processorhandlerutils.go:826) replaces container environment
// variables with XXXXXX and deletes envFrom outright without leaving a placeholder, report objects
// cannot be assumed complete from placeholder absence alone. A faithful base must either:
//  1. Be explicitly provided via s.UnredactedBase,
//  2. Come with explicit fidelity provenance (s.FidelityProvenance), or
//  3. Be verified and loaded directly from the local Helm chart on disk (s.ChartPath).
//
// If none of these conditions is met, or if the candidate contains redaction placeholders, the resource
// is visibly declined with an explanatory reason.
// chartCacheKey builds an unambiguous cache key encoding the chart path and all Helm value options.
func chartCacheKey(chartPath string, opts cautils.HelmValueOptions) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		chartPath,
		strings.Join(opts.ValueFiles, ","),
		strings.Join(opts.Values, ","),
		strings.Join(opts.StringValues, ","),
		strings.Join(opts.FileValues, ","),
		opts.ReleaseName,
		opts.ReleaseNamespace,
	)
}

func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint8:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	case float32:
		return float64(n), true
	case float64:
		return n, true
	default:
		return 0, false
	}
}

func joinPath(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}

// isEmptyValue reports whether v is nil, empty string, empty slice, or an empty map
// (or a map where all values are themselves empty values).
func isEmptyValue(v interface{}) bool {
	if v == nil {
		return true
	}
	switch val := v.(type) {
	case map[string]interface{}:
		if len(val) == 0 {
			return true
		}
		for _, child := range val {
			if !isEmptyValue(child) {
				return false
			}
		}
		return true
	case []interface{}:
		return len(val) == 0
	case string:
		return val == ""
	default:
		return false
	}
}

// verifyScannedFieldsMatch recursively checks that every non-redacted field present in scannedVal
// matches the corresponding field in candVal. Any field with placeholder "XXXXXX" or omitted in
// scannedVal is ignored. Empty/default fields (such as scanner-added empty resources: {}) are
// normalized so unchanged manifests match. Returns an error if any concrete non-redacted value conflicts.
func verifyScannedFieldsMatch(scannedVal, candVal interface{}, path string) error {
	if scannedVal == nil {
		return nil
	}

	if s, ok := scannedVal.(string); ok && s == "XXXXXX" {
		return nil
	}

	switch sTyped := scannedVal.(type) {
	case map[string]interface{}:
		cMap, ok := candVal.(map[string]interface{})
		if !ok {
			return fmt.Errorf("type mismatch at %s: expected map, got %T", path, candVal)
		}
		for k, v := range sTyped {
			if path == "" && k == "path" {
				continue
			}
			if s, isStr := v.(string); isStr && s == "XXXXXX" {
				continue
			}
			candChild, exists := cMap[k]
			if !exists {
				// Normalize equivalent empty/default fields (such as scanner-added resources: {})
				if isEmptyValue(v) {
					continue
				}
				return fmt.Errorf("field %s present in scanned resource is missing in rendered base", joinPath(path, k))
			}
			if isEmptyValue(v) && isEmptyValue(candChild) {
				continue
			}
			if err := verifyScannedFieldsMatch(v, candChild, joinPath(path, k)); err != nil {
				return err
			}
		}
		return nil

	case []interface{}:
		cSlice, ok := candVal.([]interface{})
		if !ok {
			return fmt.Errorf("type mismatch at %s: expected list, got %T", path, candVal)
		}
		if len(sTyped) != len(cSlice) {
			return fmt.Errorf("list length mismatch at %s: scanned %d, rendered %d", path, len(sTyped), len(cSlice))
		}
		for i := range sTyped {
			elemPath := fmt.Sprintf("%s[%d]", path, i)
			if err := verifyScannedFieldsMatch(sTyped[i], cSlice[i], elemPath); err != nil {
				return err
			}
		}
		return nil

	default:
		if sf, isSNumeric := toFloat64(scannedVal); isSNumeric {
			if cf, isCNumeric := toFloat64(candVal); isCNumeric {
				if sf != cf {
					return fmt.Errorf("value mismatch at %s: scanned %v, rendered %v", path, scannedVal, candVal)
				}
				return nil
			}
			return fmt.Errorf("type mismatch at %s: scanned numeric %v, rendered %T", path, scannedVal, candVal)
		}

		if fmt.Sprintf("%v", scannedVal) != fmt.Sprintf("%v", candVal) {
			return fmt.Errorf("value mismatch at %s: scanned %v, rendered %v", path, scannedVal, candVal)
		}
		return nil
	}
}

func getContainersFromObj(obj map[string]interface{}) []map[string]interface{} {
	if obj == nil {
		return nil
	}
	var res []map[string]interface{}
	extractContainers := func(containersList interface{}) {
		if list, ok := containersList.([]interface{}); ok {
			for _, item := range list {
				if m, ok := item.(map[string]interface{}); ok {
					res = append(res, m)
				}
			}
		}
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		extractContainers(spec["containers"])
		extractContainers(spec["initContainers"])
		extractContainers(spec["ephemeralContainers"])
		if tmpl, ok := spec["template"].(map[string]interface{}); ok {
			if tmplSpec, ok := tmpl["spec"].(map[string]interface{}); ok {
				extractContainers(tmplSpec["containers"])
				extractContainers(tmplSpec["initContainers"])
				extractContainers(tmplSpec["ephemeralContainers"])
			}
		}
		if jobTmpl, ok := spec["jobTemplate"].(map[string]interface{}); ok {
			if jobSpec, ok := jobTmpl["spec"].(map[string]interface{}); ok {
				if jobTmpl2, ok := jobSpec["template"].(map[string]interface{}); ok {
					if jobTmplSpec, ok := jobTmpl2["spec"].(map[string]interface{}); ok {
						extractContainers(jobTmplSpec["containers"])
						extractContainers(jobTmplSpec["initContainers"])
						extractContainers(jobTmplSpec["ephemeralContainers"])
					}
				}
			}
		}
	}
	return res
}

// hasValueOverrides returns true if opts provides any Helm value overrides
// (values files, set values, string values, or file values).
func hasValueOverrides(opts cautils.HelmValueOptions) bool {
	return len(opts.ValueFiles) > 0 || len(opts.Values) > 0 ||
		len(opts.StringValues) > 0 || len(opts.FileValues) > 0
}

// resolveBaseObject determines the verified unredacted base Kubernetes object for a suggestion.
// Because the scan redactor (removeData / processorhandlerutils.go:826) replaces container environment
// variables with XXXXXX and deletes envFrom outright without leaving a placeholder, report objects
// cannot be assumed complete from placeholder absence alone. A faithful base must either:
//  1. Be explicitly provided via s.UnredactedBase,
//  2. Come with explicit fidelity provenance (s.FidelityProvenance), or
//  3. Be verified and loaded directly from the local Helm chart on disk (s.ChartPath).
//
// In all cases, the candidate base is verified against the non-redacted fields of the scanned resource.
// If the scan report has redacted environment configuration and no verified Helm render inputs were
// provided, the missing information prevents establishing fidelity and the resource is visibly declined.
func resolveBaseObject(s HelmFixSuggestion, chartCache map[string]map[string][]workloadinterface.IMetadata) (map[string]interface{}, string) {
	var candidate map[string]interface{}
	var loadErr error

	if s.UnredactedBase != nil {
		candidate = s.UnredactedBase
	} else if s.FidelityProvenance && s.Resource != nil && s.Resource.GetObject() != nil {
		candidate = s.Resource.GetObject()
	} else if s.ChartPath != "" {
		candidate, loadErr = loadUnredactedFromChart(s, chartCache)
	}

	if candidate == nil {
		if loadErr != nil {
			return nil, fmt.Sprintf("declined: %s", loadErr.Error())
		}
		return nil, "unproven report fidelity: scan reports redact container environment variables and remove envFrom without leaving placeholders; provide a verified unredacted rendered base or explicit fidelity provenance"
	}

	// If the scan report comes from a scan (not an unredacted base or proven fidelity),
	// container environment configuration cannot be verified without complete render provenance
	// (Helm value overrides). Scan reports redact container environment variables and remove envFrom
	// without leaving placeholders (processorhandlerutils.go:826). Placeholder absence and matching
	// surviving fields cannot prove the original render inputs even when both objects lack envFrom.
	// Therefore, complete render provenance (Helm value overrides) or a verified unredacted base is required.
	if s.Resource != nil && s.Resource.GetObject() != nil && !s.FidelityProvenance && s.UnredactedBase == nil {
		if len(getContainersFromObj(s.Resource.GetObject())) > 0 || len(getContainersFromObj(candidate)) > 0 {
			if !hasValueOverrides(s.HelmValueOptions) {
				return nil, "declined: scan report redacts container environment configuration and no verified Helm render inputs were provided; cannot establish correspondence with scan-time overrides"
			}
		}
	}

	if s.Resource != nil && s.Resource.GetObject() != nil {
		if err := verifyScannedFieldsMatch(s.Resource.GetObject(), candidate, ""); err != nil {
			return nil, fmt.Sprintf("declined: rendered chart base does not match scan-time resource configuration (%s)", err.Error())
		}
	}

	if hasRedactedPlaceholder(candidate) {
		return nil, "declined: resource contains scan report redaction placeholders (XXXXXX)"
	}

	switch kind, _ := candidate["kind"].(string); kind {
	case "Secret", "ConfigMap":
		if reason := redactedContentReason(candidate); reason != "" {
			return nil, reason
		}
	}

	return candidate, ""
}

// validateChartFilesContainment ensures that the chart directory and every file, directory, or symlink
// target inside it resolves within allowedBasePath, preventing Helm loader from following symlinks
// or directory symlinks to external files outside the allowed boundary.
func validateChartFilesContainment(chartPath, allowedBasePath string) error {
	resolvedAllowedBase, err := filepath.EvalSymlinks(allowedBasePath)
	if err != nil {
		return fmt.Errorf("invalid allowed base path %q: %w", allowedBasePath, err)
	}

	resolvedChart, err := filepath.EvalSymlinks(chartPath)
	if err != nil {
		return fmt.Errorf("failed to resolve chart path %q: %w", chartPath, err)
	}

	if !isPathContained(resolvedAllowedBase, resolvedChart) {
		return fmt.Errorf("chart path %q is outside allowed base path %q", chartPath, allowedBasePath)
	}

	visitedDirs := make(map[string]bool)
	return validateDirContainment(resolvedChart, resolvedAllowedBase, visitedDirs)
}

func validateDirContainment(dirPath, allowedBasePath string, visitedDirs map[string]bool) error {
	resolvedDir, err := filepath.EvalSymlinks(dirPath)
	if err != nil {
		return fmt.Errorf("failed to resolve chart directory %q: %w", dirPath, err)
	}
	if !isPathContained(allowedBasePath, resolvedDir) {
		return fmt.Errorf("chart directory %q resolves to %q, which is outside allowed base path %q", dirPath, resolvedDir, allowedBasePath)
	}
	if visitedDirs[resolvedDir] {
		return nil
	}
	visitedDirs[resolvedDir] = true

	entries, err := os.ReadDir(resolvedDir)
	if err != nil {
		return fmt.Errorf("failed to read chart directory %q: %w", resolvedDir, err)
	}

	for _, entry := range entries {
		entryPath := filepath.Join(resolvedDir, entry.Name())
		resolvedEntry, err := filepath.EvalSymlinks(entryPath)
		if err != nil {
			return fmt.Errorf("failed to resolve chart entry %q: %w", entryPath, err)
		}
		if !isPathContained(allowedBasePath, resolvedEntry) {
			return fmt.Errorf("chart file %q resolves to %q, which is outside allowed base path %q", entryPath, resolvedEntry, allowedBasePath)
		}

		info, err := os.Stat(resolvedEntry)
		if err != nil {
			return fmt.Errorf("failed to stat chart entry %q: %w", resolvedEntry, err)
		}
		if info.IsDir() {
			if err := validateDirContainment(resolvedEntry, allowedBasePath, visitedDirs); err != nil {
				return err
			}
		}
	}
	return nil
}

// loadUnredactedFromChart renders the chart at chartPath using s.HelmValueOptions and returns the unredacted
// workload object matching s.Resource's full API identity (group, version, kind, name, namespace).
// It verifies that s.ChartPath and all files/symlinks inside it are contained within s.AllowedBasePath.
func loadUnredactedFromChart(s HelmFixSuggestion, chartCache map[string]map[string][]workloadinterface.IMetadata) (map[string]interface{}, error) {
	if s.ChartPath == "" {
		return nil, errors.New("empty chart path")
	}

	if s.AllowedBasePath != "" {
		if err := validateChartFilesContainment(s.ChartPath, s.AllowedBasePath); err != nil {
			return nil, err
		}
		for _, vf := range s.HelmValueOptions.ValueFiles {
			resolvedVF, err := filepath.EvalSymlinks(vf)
			if err != nil || !isPathContained(s.AllowedBasePath, resolvedVF) {
				return nil, fmt.Errorf("values file %q is outside allowed base path %q", vf, s.AllowedBasePath)
			}
		}
		for _, fv := range s.HelmValueOptions.FileValues {
			for _, item := range strings.Split(fv, ",") {
				parts := strings.SplitN(item, "=", 2)
				if len(parts) == 2 {
					filePath := parts[1]
					resolvedFP, err := filepath.EvalSymlinks(filePath)
					if err != nil || !isPathContained(s.AllowedBasePath, resolvedFP) {
						return nil, fmt.Errorf("file-values file %q is outside allowed base path %q", filePath, s.AllowedBasePath)
					}
				}
			}
		}
	}

	chartYaml := filepath.Join(s.ChartPath, "Chart.yaml")
	if _, err := os.Stat(chartYaml); err != nil {
		return nil, err
	}

	cacheKey := chartCacheKey(s.ChartPath, s.HelmValueOptions)
	sourceToWorkloads, ok := chartCache[cacheKey]
	if !ok {
		var err error
		sourceToWorkloads, _, _, err = cautils.LoadResourcesFromHelmCharts(context.Background(), s.ChartPath, s.HelmValueOptions)
		if err != nil {
			return nil, err
		}
		if chartCache != nil {
			chartCache[cacheKey] = sourceToWorkloads
		}
	}

	if s.Resource == nil {
		return nil, errors.New("nil resource")
	}

	targetGroup, targetVersion := parseGroupVersion(s.Resource.GetApiVersion())
	targetKind := s.Resource.GetKind()
	targetName := s.Resource.GetName()
	targetNamespace := s.Resource.GetNamespace()

	var matches []map[string]interface{}
	for _, workloads := range sourceToWorkloads {
		for _, w := range workloads {
			candGroup, candVersion := parseGroupVersion(w.GetApiVersion())
			candKind := w.GetKind()
			candName := w.GetName()
			candNamespace := w.GetNamespace()
			if candNamespace == "" && s.HelmValueOptions.ReleaseNamespace != "" {
				candNamespace = s.HelmValueOptions.ReleaseNamespace
			}

			if candGroup == targetGroup && candVersion == targetVersion &&
				candKind == targetKind && candName == targetName &&
				candNamespace == targetNamespace {
				obj := w.GetObject()
				if localworkload.IsTypeLocalWorkload(obj) {
					lw := localworkload.NewLocalWorkload(obj)
					lw.DeletePathEntry()
					obj = lw.GetObject()
				}
				matches = append(matches, deepCopyMap(obj))
			}
		}
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("resource %s/%s %s/%s not found in rendered chart", targetGroup, targetVersion, targetKind, targetName)
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("ambiguous match: found %d resources matching %s/%s %s/%s in rendered chart", len(matches), targetGroup, targetVersion, targetKind, targetName)
	}

	return matches[0], nil
}

// writeRestrictedFile writes data to path with mode 0600 and explicitly chmods an existing file to 0600.
func writeRestrictedFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
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
// rendered manifests that may contain sensitive data, explicitly enforcing permissions even
// when regenerating into existing directories or files.
//
// To avoid corrupting live application configuration, resources whose recorded content cannot
// be reproduced faithfully (such as objects from scan reports where removeData replaced container
// environment variables or secret data with "XXXXXX", or cleared envFrom) are visibly declined.
// EmitKustomizePatch returns an explicit KustomizeEmitResult listing all emitted and skipped resources.
func EmitKustomizePatch(suggestions []HelmFixSuggestion, dir string) (*KustomizeEmitResult, error) {
	result := &KustomizeEmitResult{}
	if len(suggestions) == 0 {
		return result, nil
	}

	chartCache := make(map[string]map[string][]workloadinterface.IMetadata)

	// 1. Group suggestions by unique resourceKey to merge multiple suggestions for the same workload,
	// and prevent overwriting between resources with same kind/name in different namespaces.
	groups := make(map[resourceKey]*resourceGroup)
	var keysInOrder []resourceKey

	for _, s := range suggestions {
		if s.Resource == nil || len(s.FixPaths) == 0 {
			continue
		}

		resKeyStr := fmt.Sprintf("%s/%s", s.Resource.GetKind(), s.Resource.GetName())

		baseObj, reason := resolveBaseObject(s, chartCache)
		if reason != "" {
			result.SkippedResources = append(result.SkippedResources, KustomizeSkippedResource{
				ResourceKey: resKeyStr,
				Reason:      reason,
			})
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
				baseObj:  baseObj,
			}
			groups[key] = rg
			keysInOrder = append(keysInOrder, key)
		}

		rg.fixPaths = append(rg.fixPaths, s.FixPaths...)
	}

	if len(groups) == 0 {
		return result, nil
	}

	// Restrict permissions on the output directory containing rendered manifests, enforcing 0700 on existing dirs too.
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create kustomize output dir %q: %w", dir, err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to restrict permissions on kustomize output dir %q: %w", dir, err)
	}

	kust := kustomizationDoc{
		APIVersion: "kustomize.config.k8s.io/v1beta1",
		Kind:       "Kustomization",
	}

	// 2. Build base.yaml containing all rendered resources so `kustomize build <dir>` works out of the box.
	var baseYamlParts [][]byte
	for _, key := range keysInOrder {
		rg := groups[key]
		if rg.baseObj != nil {
			cleanObj := stripServerManagedFields(rg.baseObj)
			objBytes, err := yaml.Marshal(cleanObj)
			if err == nil && len(objBytes) > 0 {
				baseYamlParts = append(baseYamlParts, objBytes)
			}
		}
	}

	if len(baseYamlParts) > 0 {
		baseFilePath, err := ensureSubpath(dir, "base.yaml")
		if err != nil {
			return nil, err
		}
		var baseContent []byte
		for i, part := range baseYamlParts {
			if i > 0 {
				baseContent = append(baseContent, []byte("---\n")...)
			}
			baseContent = append(baseContent, part...)
		}
		// Write base.yaml with restricted mode 0600, updating existing file mode if already present.
		if err := writeRestrictedFile(baseFilePath, baseContent); err != nil {
			return nil, fmt.Errorf("failed to write base.yaml: %w", err)
		}
		kust.Resources = append(kust.Resources, "base.yaml")
	}

	// 3. Generate one patch file per unique resource
	writtenFiles := make(map[string]resourceKey)

	for _, key := range keysInOrder {
		rg := groups[key]

		baseObj := rg.baseObj
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
			return nil, fmt.Errorf("filename collision detected: patch file %q for resource %s/%s collides with %s/%s",
				patchFileName, rg.key.Kind, rg.key.Name, existingKey.Kind, existingKey.Name)
		}
		writtenFiles[patchFileName] = rg.key

		patchFilePath, err := ensureSubpath(dir, patchFileName)
		if err != nil {
			return nil, err
		}

		patchBytes, err := yaml.Marshal(ops)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal patch for %s/%s: %w", rg.key.Kind, rg.key.Name, err)
		}
		if err := writeRestrictedFile(patchFilePath, patchBytes); err != nil {
			return nil, fmt.Errorf("failed to write patch file %q: %w", patchFileName, err)
		}

		target := kustomizeTarget{
			Group:   rg.key.Group,
			Version: rg.key.Version,
			Kind:    rg.key.Kind,
			Name:    regexp.QuoteMeta(rg.key.Name),
		}
		if rg.key.Namespace != "" {
			target.Namespace = regexp.QuoteMeta(rg.key.Namespace)
		}

		kust.Patches = append(kust.Patches, kustomizePatchEntry{
			Path:   patchFileName,
			Target: target,
		})

		resIdent := fmt.Sprintf("%s/%s", rg.key.Kind, rg.key.Name)
		if rg.key.Namespace != "" {
			resIdent = fmt.Sprintf("%s/%s/%s", rg.key.Kind, rg.key.Namespace, rg.key.Name)
		}
		result.EmittedResources = append(result.EmittedResources, resIdent)
	}

	if len(kust.Patches) == 0 {
		return result, nil
	}

	kustFilePath, err := ensureSubpath(dir, "kustomization.yaml")
	if err != nil {
		return nil, err
	}

	kustBytes, err := yaml.Marshal(kust)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal kustomization.yaml: %w", err)
	}
	if err := writeRestrictedFile(kustFilePath, kustBytes); err != nil {
		return nil, err
	}
	return result, nil
}
