package fixhandler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/gofrs/flock"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"gopkg.in/yaml.v3"
	"sigs.k8s.io/kustomize/kyaml/resid"
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

// registeredTarget tracks an emitted patch target to detect ambiguities and selector overlaps.
type registeredTarget struct {
	target          kustomizeTarget
	resIdent        string
	isClusterScoped bool
	candidateNs     string
}

func targetsOverlap(t1, t2 registeredTarget) bool {
	if t1.target.Group != t2.target.Group ||
		t1.target.Version != t2.target.Version ||
		t1.target.Kind != t2.target.Kind ||
		t1.target.Name != t2.target.Name {
		return false
	}
	if t1.isClusterScoped && t2.isClusterScoped {
		return true
	}
	if t1.target.Namespace == t2.target.Namespace {
		return true
	}

	matchNs := func(targetNs, ns string) bool {
		if targetNs == "" {
			return true
		}
		if targetNs == ns {
			return true
		}
		pattern := targetNs
		if !strings.HasPrefix(pattern, "^") {
			pattern = "^" + regexp.QuoteMeta(pattern)
		}
		if !strings.HasSuffix(pattern, "$") {
			pattern = pattern + "$"
		}
		re, err := regexp.Compile(pattern)
		if err == nil {
			return re.MatchString(ns)
		}
		return false
	}

	candidates := []string{"", "default"}
	if t1.candidateNs != "" {
		candidates = append(candidates, t1.candidateNs)
	}
	if t2.candidateNs != "" {
		candidates = append(candidates, t2.candidateNs)
	}

	for _, ns := range candidates {
		if matchNs(t1.target.Namespace, ns) && matchNs(t2.target.Namespace, ns) {
			return true
		}
	}
	return false
}

// ResourceKey uniquely identifies a Kubernetes resource across namespace/group/version/kind/name.
type ResourceKey struct {
	Group     string
	Version   string
	Kind      string
	Namespace string
	Name      string
}

type resourceKey = ResourceKey

// resourceGroup holds all fixes and the base resource for a unique resourceKey.
type resourceGroup struct {
	key                resourceKey
	resource           *reporthandling.Resource
	baseObj            map[string]interface{}
	fixPaths           []armotypes.FixPath
	isClusterScoped    bool
	isReleaseNamespace bool
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

// parseFixValue parses raw string fix values reusing the normal fixer's parsing rules:
// booleans, integers (including unsigned integers up to uint64), floats, and safe YAML flow sequences
// adhering to safeSequenceValue are parsed into their respective types; everything else (including
// nested sequences, maps, "null", and quoted strings) remains a string so that fix semantics match
// the standard fixer.
func parseFixValue(raw string) interface{} {
	if node, err := parseYAMLLiteral(raw); err == nil {
		switch node.Tag {
		case "!!int":
			var i int
			if err := node.Decode(&i); err == nil {
				return i
			}
			var i64 int64
			if err := node.Decode(&i64); err == nil {
				return i64
			}
			var u uint64
			if err := node.Decode(&u); err == nil {
				return u
			}
		case "!!bool":
			var b bool
			if err := node.Decode(&b); err == nil {
				return b
			}
		case "!!float":
			var f float64
			if err := node.Decode(&f); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				return f
			}
		}
		if node.Kind == yaml.SequenceNode && safeSequenceValue.MatchString(raw) {
			var seq []interface{}
			if err := node.Decode(&seq); err == nil {
				return seq
			}
		}
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

// deepCopyValue creates a deep copy of an arbitrary nested object without JSON serialization
// to preserve exact integer and floating-point types (e.g. int, int64, uint64).
func deepCopyValue(v interface{}) interface{} {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case map[string]interface{}:
		return deepCopyMap(val)
	case []interface{}:
		copySlice := make([]interface{}, len(val))
		for i, item := range val {
			copySlice[i] = deepCopyValue(item)
		}
		return copySlice
	default:
		return val
	}
}

// deepCopyMap creates an isolated deep copy of a resource map object without JSON serialization
// to preserve exact integer and floating-point types.
func deepCopyMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	copyMap := make(map[string]interface{}, len(m))
	for k, v := range m {
		copyMap[k] = deepCopyValue(v)
	}
	return copyMap
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

func updateParentContainer(parentMap map[string]interface{}, parentKey string, parentSlice []interface{}, parentSliceIdx int, val interface{}) {
	if parentMap != nil && parentKey != "" {
		parentMap[parentKey] = val
	} else if parentSlice != nil && parentSliceIdx >= 0 && parentSliceIdx < len(parentSlice) {
		parentSlice[parentSliceIdx] = val
	}
}

// resolveFixPathOps resolves a concrete FixPath against an evolving working copy of the resource.
// If intermediate ancestor maps are missing, it emits an "add" op creating the ancestor as {}
// once, updates the evolving copy, and resolves child fields so sibling fixes sharing a missing
// parent are both preserved.
func resolveFixPathOps(workingObj map[string]interface{}, fp armotypes.FixPath) ([]kustomizePatchOp, error) {
	parts, err := parseYAMLPath(fp.Path)
	if err != nil {
		return nil, fmt.Errorf("invalid fix path %q: %w", fp.Path, err)
	}
	if len(parts) == 0 {
		return nil, nil
	}

	parsedVal := parseFixValue(fp.Value)
	if exceedsSafeInteger(parsedVal) {
		return nil, fmt.Errorf("integer value %s cannot be preserved exactly through Kustomize build (exceeds safe integer limit %d)", fp.Value, maxSafeInteger)
	}

	var ops []kustomizePatchOp
	var pointerTokens []string
	var current interface{} = workingObj
	var parentMap map[string]interface{}
	var parentKey string
	var parentSlice []interface{}
	parentSliceIdx := -1

	for i, part := range parts {
		isLast := i == len(parts)-1

		if !isLast {
			if part.sequence {
				if part.index < 0 {
					return nil, fmt.Errorf("negative array index %d in path %s", part.index, fp.Path)
				}
				slice, ok := current.([]interface{})
				if !ok {
					return nil, fmt.Errorf("expected slice at %s but found %T in path %s", strings.Join(pointerTokens, "/"), current, fp.Path)
				}
				if part.index > len(slice) {
					return nil, fmt.Errorf("array gap detected: intermediate index %d exceeds slice length %d in path %s", part.index, len(slice), fp.Path)
				}
				pointerTokens = append(pointerTokens, strconv.Itoa(part.index))
				if part.index == len(slice) {
					var newElem interface{}
					if parts[i+1].sequence {
						newElem = make([]interface{}, 0)
					} else {
						newElem = make(map[string]interface{})
					}
					currTokens := append([]string{}, pointerTokens[:len(pointerTokens)-1]...)
					currTokens = append(currTokens, strconv.Itoa(part.index))
					ancestorPtr := "/" + strings.Join(currTokens, "/")
					ops = append(ops, kustomizePatchOp{
						Op:    "add",
						Path:  ancestorPtr,
						Value: newElem,
					})
					slice = append(slice, newElem)
					updateParentContainer(parentMap, parentKey, parentSlice, parentSliceIdx, slice)
				}
				parentSlice = slice
				parentSliceIdx = part.index
				parentMap = nil
				parentKey = ""
				current = slice[part.index]
			} else {
				pointerTokens = append(pointerTokens, escapeJSONPointerToken(part.key))
				m, ok := current.(map[string]interface{})
				if !ok {
					return nil, fmt.Errorf("expected map at %s but found %T in path %s", strings.Join(pointerTokens[:len(pointerTokens)-1], "/"), current, fp.Path)
				}
				parentMap = m
				parentKey = part.key
				parentSlice = nil
				parentSliceIdx = -1
				nextVal, exists := m[part.key]
				if !exists || nextVal == nil {
					ancestorPtr := "/" + strings.Join(pointerTokens, "/")
					if parts[i+1].sequence {
						newList := make([]interface{}, 0)
						ops = append(ops, kustomizePatchOp{
							Op:    "add",
							Path:  ancestorPtr,
							Value: newList,
						})
						m[part.key] = newList
						current = newList
					} else {
						newMap := make(map[string]interface{})
						ops = append(ops, kustomizePatchOp{
							Op:    "add",
							Path:  ancestorPtr,
							Value: newMap,
						})
						m[part.key] = newMap
						current = newMap
					}
				} else {
					current = nextVal
				}
			}
		} else {
			if part.sequence {
				if part.index < 0 {
					return nil, fmt.Errorf("negative array index %d in path %s", part.index, fp.Path)
				}
				slice, ok := current.([]interface{})
				if !ok {
					return nil, fmt.Errorf("expected slice at %s but found %T in path %s", strings.Join(pointerTokens, "/"), current, fp.Path)
				}
				if part.index > len(slice) {
					return nil, fmt.Errorf("array gap detected: terminal index %d exceeds slice length %d in path %s", part.index, len(slice), fp.Path)
				}
				pointerTokens = append(pointerTokens, strconv.Itoa(part.index))
				targetPtr := "/" + strings.Join(pointerTokens, "/")
				if part.index < len(slice) {
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
					slice = append(slice, parsedVal)
					updateParentContainer(parentMap, parentKey, parentSlice, parentSliceIdx, slice)
				}
			} else {
				pointerTokens = append(pointerTokens, escapeJSONPointerToken(part.key))
				targetPtr := "/" + strings.Join(pointerTokens, "/")
				m, ok := current.(map[string]interface{})
				if !ok {
					return nil, fmt.Errorf("expected map at %s but found %T in path %s", targetPtr, current, fp.Path)
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

	return ops, nil
}

// hasRedactedPlaceholder checks if the object contains the scan redactor's "XXXXXX" placeholder
// in container environment variables, secret data, or configmap data.
func hasRedactedPlaceholder(data interface{}) bool {
	m, ok := data.(map[string]interface{})
	if !ok {
		return false
	}
	kind, _ := m["kind"].(string)
	switch kind {
	case "Secret":
		for _, f := range []string{"data", "stringData"} {
			if dataMap, ok := m[f].(map[string]interface{}); ok {
				for _, v := range dataMap {
					if s, ok := v.(string); ok && s == "XXXXXX" {
						return true
					}
				}
			}
		}
	case "ConfigMap":
		for _, f := range []string{"data", "binaryData"} {
			if dataMap, ok := m[f].(map[string]interface{}); ok {
				for _, v := range dataMap {
					if s, ok := v.(string); ok && s == "XXXXXX" {
						return true
					}
				}
			}
		}
	}
	for _, c := range getContainersFromObj(m) {
		if envList, ok := c["env"].([]interface{}); ok {
			for _, item := range envList {
				if envMap, ok := item.(map[string]interface{}); ok {
					if val, ok := envMap["value"].(string); ok && val == "XXXXXX" {
						return true
					}
				}
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

const maxSafeInteger = (1 << 53) - 1

func toInt64(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint:
		if u := uint64(n); u <= math.MaxInt64 {
			return int64(u), true
		}
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		if n <= math.MaxInt64 {
			return int64(n), true
		}
	case json.Number:
		if i, err := strconv.ParseInt(string(n), 10, 64); err == nil {
			return i, true
		}
	}
	return 0, false
}

func toUint64(v interface{}) (uint64, bool) {
	switch n := v.(type) {
	case uint:
		return uint64(n), true
	case uint8:
		return uint64(n), true
	case uint16:
		return uint64(n), true
	case uint32:
		return uint64(n), true
	case uint64:
		return n, true
	case int:
		if n >= 0 {
			return uint64(n), true
		}
	case int8:
		if n >= 0 {
			return uint64(n), true
		}
	case int16:
		if n >= 0 {
			return uint64(n), true
		}
	case int32:
		if n >= 0 {
			return uint64(n), true
		}
	case int64:
		if n >= 0 {
			return uint64(n), true
		}
	case json.Number:
		if u, err := strconv.ParseUint(string(n), 10, 64); err == nil {
			return u, true
		}
	}
	return 0, false
}

// exceedsSafeInteger reports whether v, or any element contained recursively within v
// if v is a slice/sequence, is an integer that exceeds the safe integer limit [-maxSafeInteger, maxSafeInteger].
func exceedsSafeInteger(v interface{}) bool {
	if u, ok := toUint64(v); ok && u > maxSafeInteger {
		return true
	}
	if i, ok := toInt64(v); ok && (i > int64(maxSafeInteger) || i < -int64(maxSafeInteger)) {
		return true
	}
	if seq, ok := v.([]interface{}); ok {
		for _, elem := range seq {
			if exceedsSafeInteger(elem) {
				return true
			}
		}
	}
	return false
}

func isInteger(v interface{}) bool {
	switch n := v.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	case json.Number:
		_, err := strconv.ParseInt(string(n), 10, 64)
		if err == nil {
			return true
		}
		_, err = strconv.ParseUint(string(n), 10, 64)
		return err == nil
	default:
		return false
	}
}

// compareIntegers compares two integer values with exact arithmetic, avoiding float64 precision loss.
func compareIntegers(a, b interface{}) (bool, bool) {
	if !isInteger(a) || !isInteger(b) {
		return false, false
	}
	sA, okSA := toInt64(a)
	sB, okSB := toInt64(b)
	if okSA && okSB {
		return sA == sB, true
	}
	uA, okUA := toUint64(a)
	uB, okUB := toUint64(b)
	if okUA && okUB {
		return uA == uB, true
	}
	return false, true
}

func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case int:
		if int64(n) >= -maxSafeInteger && int64(n) <= maxSafeInteger {
			return float64(n), true
		}
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		if n >= -maxSafeInteger && n <= maxSafeInteger {
			return float64(n), true
		}
	case uint:
		if uint64(n) <= maxSafeInteger {
			return float64(n), true
		}
	case uint8:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		if n <= maxSafeInteger {
			return float64(n), true
		}
	case float32:
		return float64(n), true
	case float64:
		return n, true
	case json.Number:
		if f, err := n.Float64(); err == nil {
			return f, true
		}
	default:
		return 0, false
	}
	return 0, false
}

func joinPath(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}

var (
	containerIndexRegex     = regexp.MustCompile(`^(containers|initContainers|ephemeralContainers)\[\d+\]$`)
	containerEnvValueRegex  = regexp.MustCompile(`^(containers|initContainers|ephemeralContainers)\[\d+\]\.env\[\d+\]\.value$`)
	containerResourcesRegex = regexp.MustCompile(`^(containers|initContainers|ephemeralContainers)\[\d+\]\.resources$`)
)

func isPodWorkloadKind(kind string) bool {
	switch kind {
	case "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job", "CronJob":
		return true
	default:
		return false
	}
}

func getValidPodSpecPrefixes(kind string) []string {
	switch kind {
	case "Pod":
		return []string{"spec"}
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job":
		return []string{"spec.template.spec"}
	case "CronJob":
		return []string{"spec.jobTemplate.spec.template.spec"}
	case "":
		// When kind is unknown (e.g. direct helper test on submap), allow standard pod workload prefixes
		return []string{"spec", "spec.template.spec", "spec.jobTemplate.spec.template.spec"}
	default:
		return nil
	}
}

func isContainerPath(kind, path string) bool {
	prefixes := getValidPodSpecPrefixes(kind)
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix+".") {
			relPath := strings.TrimPrefix(path, prefix+".")
			if containerIndexRegex.MatchString(relPath) {
				return true
			}
		}
	}
	return false
}

// isScannerAddedEmptyField reports whether fieldPath and val correspond to a documented
// artifact of the scanner's typed struct unmarshaling (specifically container resources: {})
// that should be normalized when absent or null in the rendered base manifest.
func isScannerAddedEmptyField(kind, fieldPath string, val interface{}) bool {
	m, ok := val.(map[string]interface{})
	if !ok || len(m) != 0 {
		return false
	}
	if kind != "" && !isPodWorkloadKind(kind) {
		return false
	}
	prefixes := getValidPodSpecPrefixes(kind)
	for _, prefix := range prefixes {
		if strings.HasPrefix(fieldPath, prefix+".") {
			relPath := strings.TrimPrefix(fieldPath, prefix+".")
			if containerResourcesRegex.MatchString(relPath) {
				return true
			}
		}
	}
	return false
}

// isSourceMetadataKey reports whether key is scanner/report source metadata that should
// be normalized and ignored during fidelity comparison of root resource objects.
func isSourceMetadataKey(path, key string) bool {
	return path == "" && (key == "path" || key == "sourcePath")
}

// isContainerEnvFrom reports whether key is "envFrom" on a container object
// (spec.containers[i], initContainers, ephemeralContainers), which the scanner
// redactor removes without leaving a placeholder.
func isContainerEnvFrom(kind, path, key string) bool {
	if key != "envFrom" {
		return false
	}
	return isContainerPath(kind, path)
}

// isScannerRedactedField reports whether path corresponds to a field that the scan redactor
// actually replaces with "XXXXXX":
// 1. Data entries in Secrets/ConfigMaps: data.<key>, stringData.<key>, binaryData.<key>
// 2. Container environment variable values: ...containers[i].env[j].value
func isScannerRedactedField(kind, path string) bool {
	switch kind {
	case "Secret":
		return strings.HasPrefix(path, "data.") || strings.HasPrefix(path, "stringData.")
	case "ConfigMap":
		return strings.HasPrefix(path, "data.") || strings.HasPrefix(path, "binaryData.")
	default:
		if kind != "" && !isPodWorkloadKind(kind) {
			return false
		}
		prefixes := getValidPodSpecPrefixes(kind)
		for _, prefix := range prefixes {
			if strings.HasPrefix(path, prefix+".") {
				relPath := strings.TrimPrefix(path, prefix+".")
				if containerEnvValueRegex.MatchString(relPath) {
					return true
				}
			}
		}
		return false
	}
}

// verifyScannedFieldsMatch recursively checks that every non-redacted field present in scannedVal
// matches the corresponding field in candVal, and that no additional non-redacted fields are
// present in candVal that were absent from scannedVal. Only fields that the scanner actually
// redacts (secret/configmap data, container env values) with placeholder "XXXXXX" or source
// metadata (path, sourcePath) are exempted from matching. Documented scanner-added fields
// (specifically empty container resources: {}) are normalized so unchanged manifests match.
// Returns an error if any concrete non-redacted value conflicts, if selectors or empty values
// are conflated with null or missing fields, or if additional non-redacted fields exist.
func verifyScannedFieldsMatch(scannedVal, candVal interface{}, path string, kind ...string) error {
	var rKind string
	if len(kind) > 0 && kind[0] != "" {
		rKind = kind[0]
	} else if m, ok := scannedVal.(map[string]interface{}); ok {
		if k, ok := m["kind"].(string); ok {
			rKind = k
		}
	}
	if rKind == "" {
		if m, ok := candVal.(map[string]interface{}); ok {
			if k, ok := m["kind"].(string); ok {
				rKind = k
			}
		}
	}

	if scannedVal == nil {
		if candVal == nil {
			return nil
		}
		return fmt.Errorf("field %s is null in scanned resource but present with non-empty value in rendered base", path)
	}
	if candVal == nil {
		if isScannerAddedEmptyField(rKind, path, scannedVal) {
			return nil
		}
		return fmt.Errorf("field %s is present with non-empty value in scanned resource but null in rendered base", path)
	}

	if s, ok := scannedVal.(string); ok && s == "XXXXXX" {
		if isScannerRedactedField(rKind, path) {
			return nil
		}
	}

	switch sTyped := scannedVal.(type) {
	case map[string]interface{}:
		cMap, ok := candVal.(map[string]interface{})
		if !ok {
			return fmt.Errorf("type mismatch at %s: expected map, got %T", path, candVal)
		}
		for k, v := range sTyped {
			if isSourceMetadataKey(path, k) {
				continue
			}
			childPath := joinPath(path, k)
			if s, isStr := v.(string); isStr && s == "XXXXXX" {
				if isScannerRedactedField(rKind, childPath) {
					continue
				}
			}
			candChild, exists := cMap[k]
			if !exists {
				// Normalize documented scanner-added fields (such as container resources: {})
				if isScannerAddedEmptyField(rKind, childPath, v) {
					continue
				}
				return fmt.Errorf("field %s present in scanned resource is missing in rendered base", childPath)
			}
			if err := verifyScannedFieldsMatch(v, candChild, childPath, rKind); err != nil {
				return err
			}
		}

		for k := range cMap {
			if isSourceMetadataKey(path, k) || isContainerEnvFrom(rKind, path, k) {
				continue
			}
			_, exists := sTyped[k]
			if !exists {
				return fmt.Errorf("field %s present in rendered base is missing in scanned resource", joinPath(path, k))
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
			if err := verifyScannedFieldsMatch(sTyped[i], cSlice[i], elemPath, rKind); err != nil {
				return err
			}
		}
		return nil

	default:
		switch s := scannedVal.(type) {
		case string:
			c, ok := candVal.(string)
			if !ok {
				return fmt.Errorf("type mismatch at %s: scanned string %q, rendered %T (%v)", path, s, candVal, candVal)
			}
			if s != c {
				return fmt.Errorf("value mismatch at %s: scanned %q, rendered %q", path, s, c)
			}
			return nil
		case bool:
			c, ok := candVal.(bool)
			if !ok {
				return fmt.Errorf("type mismatch at %s: scanned bool %v, rendered %T (%v)", path, s, candVal, candVal)
			}
			if s != c {
				return fmt.Errorf("value mismatch at %s: scanned %v, rendered %v", path, s, c)
			}
			return nil
		default:
			if eq, bothInts := compareIntegers(scannedVal, candVal); bothInts {
				if !eq {
					return fmt.Errorf("value mismatch at %s: scanned %v, rendered %v", path, scannedVal, candVal)
				}
				return nil
			}
			if isInteger(scannedVal) {
				if cf, isCFloat := toFloat64(candVal); isCFloat {
					if cf == math.Trunc(cf) && cf >= -maxSafeInteger && cf <= maxSafeInteger {
						if eq, _ := compareIntegers(scannedVal, int64(cf)); eq {
							return nil
						}
					}
					return fmt.Errorf("value mismatch at %s: scanned %v, rendered %v", path, scannedVal, candVal)
				}
			}
			if isInteger(candVal) {
				if sf, isSFloat := toFloat64(scannedVal); isSFloat {
					if sf == math.Trunc(sf) && sf >= -maxSafeInteger && sf <= maxSafeInteger {
						if eq, _ := compareIntegers(int64(sf), candVal); eq {
							return nil
						}
					}
					return fmt.Errorf("value mismatch at %s: scanned %v, rendered %v", path, scannedVal, candVal)
				}
			}
			if sf, isSNumeric := toFloat64(scannedVal); isSNumeric {
				if cf, isCNumeric := toFloat64(candVal); isCNumeric {
					if sf != cf {
						return fmt.Errorf("value mismatch at %s: scanned %v, rendered %v", path, scannedVal, candVal)
					}
					return nil
				}
				return fmt.Errorf("type mismatch at %s: scanned numeric %v, rendered %T (%v)", path, scannedVal, candVal, candVal)
			}
			if reflect.TypeOf(scannedVal) != reflect.TypeOf(candVal) {
				return fmt.Errorf("type mismatch at %s: scanned %T, rendered %T", path, scannedVal, candVal)
			}
			if scannedVal != candVal {
				return fmt.Errorf("value mismatch at %s: scanned %v, rendered %v", path, scannedVal, candVal)
			}
			return nil
		}
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

// hasRedactedEnvironment returns true if scannedObj contains scanner redaction placeholders
// in container environment variables or Secret data, or if candidateObj has container envFrom
// or environment variables that were cleared by the scanner from scannedObj.
func hasRedactedEnvironment(scannedObj, candidateObj map[string]interface{}) bool {
	if hasRedactedPlaceholder(scannedObj) {
		return true
	}
	candContainers := getContainersFromObj(candidateObj)
	scannedContainers := getContainersFromObj(scannedObj)
	for i, cc := range candContainers {
		if envFrom, ok := cc["envFrom"].([]interface{}); ok && len(envFrom) > 0 {
			if i < len(scannedContainers) {
				scannedEnvFrom, sOk := scannedContainers[i]["envFrom"].([]interface{})
				if !sOk || len(scannedEnvFrom) == 0 {
					return true
				}
			} else {
				return true
			}
		}
		if envList, ok := cc["env"].([]interface{}); ok && len(envList) > 0 {
			if i < len(scannedContainers) {
				scannedEnv, sOk := scannedContainers[i]["env"].([]interface{})
				if !sOk || len(scannedEnv) == 0 {
					return true
				}
			} else {
				return true
			}
		}
	}
	return false
}

// containersLackEnvFrom returns true if the object contains at least one container
// and none of its containers contain a non-empty envFrom slice.
func containersLackEnvFrom(obj map[string]interface{}) bool {
	containers := getContainersFromObj(obj)
	if len(containers) == 0 {
		return false
	}
	for _, c := range containers {
		if envFrom, ok := c["envFrom"].([]interface{}); ok && len(envFrom) > 0 {
			return false
		}
	}
	return true
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
	// Furthermore, supplying value overrides alone does not establish that file contents or values match
	// the scan when environment configuration was redacted. Therefore, complete render provenance is required,
	// and a verified unredacted base (s.UnredactedBase) or explicit fidelity provenance (s.FidelityProvenance)
	// is required when redacted container environment settings are present.
	if s.Resource != nil && s.Resource.GetObject() != nil && !s.FidelityProvenance && s.UnredactedBase == nil {
		if len(getContainersFromObj(s.Resource.GetObject())) > 0 || len(getContainersFromObj(candidate)) > 0 {
			if !hasValueOverrides(s.HelmValueOptions) {
				return nil, "declined: scan report redacts container environment configuration and no verified Helm render inputs were provided; cannot establish correspondence with scan-time overrides"
			}
			if hasRedactedEnvironment(s.Resource.GetObject(), candidate) {
				return nil, "declined: scan report redacts container environment configuration and scan-time render contents cannot be verified; provide a verified unredacted base or explicit fidelity provenance"
			}
			// Ambiguous both-absent case: when both scanned object and rendered candidate lack container envFrom,
			// the absence of envFrom in the candidate may be caused by values changes or chart drift (such as
			// removing envFrom from the chart or values) while the scan report had envFrom stripped by the scanner
			// redactor (processorhandlerutils.go:826). Present-day chart syntax or values cannot establish
			// scan-time fidelity. Therefore, verified scan-time content/provenance (s.UnredactedBase or
			// s.FidelityProvenance) is required for ambiguous container resources.
			if containersLackEnvFrom(candidate) && containersLackEnvFrom(s.Resource.GetObject()) {
				return nil, "declined: scan report redacts container environment configuration and scan-time render contents cannot be verified; provide a verified unredacted base or explicit fidelity provenance"
			}
		}
	}

	// When ReleaseNamespace is specified for namespaced resources, normalize release namespaces
	// symmetrically in both directions before verifyScannedFieldsMatch runs:
	// 1. If candidate omits metadata.namespace and scanned matches ReleaseNamespace, set on candidate copy.
	// 2. If scanned omits metadata.namespace and candidate explicitly uses ReleaseNamespace, set on scanned copy.
	// Copies of top-level and metadata maps are used to avoid mutating caller objects while preserving exact types.
	scannedObjToCompare := s.Resource.GetObject()
	if s.Resource != nil && s.HelmValueOptions.ReleaseNamespace != "" {
		scannedNamespace := s.Resource.GetNamespace()
		if scannedNamespace == "" && s.Resource.GetObject() != nil {
			if meta, ok := s.Resource.GetObject()["metadata"].(map[string]interface{}); ok && meta != nil {
				scannedNamespace, _ = meta["namespace"].(string)
			}
		}

		var candNamespace string
		if meta, ok := candidate["metadata"].(map[string]interface{}); ok && meta != nil {
			candNamespace, _ = meta["namespace"].(string)
		}

		isClusterScopedRes := isSuggestionClusterScoped(s, []HelmFixSuggestion{s}, chartCache)

		if !isClusterScopedRes {
			if candNamespace == "" && s.HelmValueOptions.ReleaseNamespace == scannedNamespace {
				newCandidate := make(map[string]interface{}, len(candidate)+1)
				for k, v := range candidate {
					newCandidate[k] = v
				}
				metadata := make(map[string]interface{})
				if meta, ok := candidate["metadata"].(map[string]interface{}); ok && meta != nil {
					for k, v := range meta {
						metadata[k] = v
					}
				}
				metadata["namespace"] = s.HelmValueOptions.ReleaseNamespace
				newCandidate["metadata"] = metadata
				candidate = newCandidate
			}
			if scannedNamespace == "" && candNamespace == s.HelmValueOptions.ReleaseNamespace && s.Resource.GetObject() != nil {
				newScanned := make(map[string]interface{}, len(s.Resource.GetObject())+1)
				for k, v := range s.Resource.GetObject() {
					newScanned[k] = v
				}
				metadata := make(map[string]interface{})
				if meta, ok := s.Resource.GetObject()["metadata"].(map[string]interface{}); ok && meta != nil {
					for k, v := range meta {
						metadata[k] = v
					}
				}
				metadata["namespace"] = s.HelmValueOptions.ReleaseNamespace
				newScanned["metadata"] = metadata
				scannedObjToCompare = newScanned
			}
		}
	}

	if s.Resource != nil && scannedObjToCompare != nil {
		if err := verifyScannedFieldsMatch(scannedObjToCompare, candidate, ""); err != nil {
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

// validateChartAndValuesContainment ensures that the chart directory, all files inside it,
// and any values files or file-values passed in valueOpts resolve within allowedBasePath.
func validateChartAndValuesContainment(chartPath, allowedBasePath string, valueOpts cautils.HelmValueOptions) error {
	if allowedBasePath == "" {
		return nil
	}
	if err := validateChartFilesContainment(chartPath, allowedBasePath); err != nil {
		return err
	}
	for _, vf := range valueOpts.ValueFiles {
		resolvedVF, err := filepath.EvalSymlinks(vf)
		if err != nil || !isPathContained(allowedBasePath, resolvedVF) {
			return fmt.Errorf("values file %q is outside allowed base path %q", vf, allowedBasePath)
		}
	}
	for _, fv := range valueOpts.FileValues {
		for _, item := range strings.Split(fv, ",") {
			parts := strings.SplitN(item, "=", 2)
			if len(parts) == 2 {
				filePath := parts[1]
				resolvedFP, err := filepath.EvalSymlinks(filePath)
				if err != nil || !isPathContained(allowedBasePath, resolvedFP) {
					return fmt.Errorf("file-values file %q is outside allowed base path %q", filePath, allowedBasePath)
				}
			}
		}
	}
	return nil
}

// getOrLoadChartWorkloads returns the rendered workloads for s.ChartPath using s.HelmValueOptions,
// fetching from chartCache if available or rendering and caching them.
// It verifies that s.ChartPath and all files/symlinks inside it are contained within s.AllowedBasePath.
func getOrLoadChartWorkloads(s HelmFixSuggestion, chartCache map[string]map[string][]workloadinterface.IMetadata) (map[string][]workloadinterface.IMetadata, error) {
	if s.ChartPath == "" {
		return nil, errors.New("empty chart path")
	}

	if s.AllowedBasePath != "" {
		if err := validateChartAndValuesContainment(s.ChartPath, s.AllowedBasePath, s.HelmValueOptions); err != nil {
			return nil, err
		}
	}

	cacheKey := chartCacheKey(s.ChartPath, s.HelmValueOptions)
	if chartCache != nil {
		if sourceToWorkloads, ok := chartCache[cacheKey]; ok {
			return sourceToWorkloads, nil
		}
	}

	chartYaml := filepath.Join(s.ChartPath, "Chart.yaml")
	if _, err := os.Stat(chartYaml); err != nil {
		return nil, err
	}

	sourceToWorkloads, _, _, err := cautils.LoadResourcesFromHelmCharts(context.Background(), s.ChartPath, s.HelmValueOptions)
	if err != nil {
		return nil, err
	}
	if chartCache != nil {
		chartCache[cacheKey] = sourceToWorkloads
	}
	return sourceToWorkloads, nil
}

// loadUnredactedFromChart renders the chart at chartPath using s.HelmValueOptions and returns the unredacted
// workload object matching s.Resource's full API identity (group, version, kind, name, namespace).
// It verifies that s.ChartPath and all files/symlinks inside it are contained within s.AllowedBasePath.
func loadUnredactedFromChart(s HelmFixSuggestion, chartCache map[string]map[string][]workloadinterface.IMetadata) (map[string]interface{}, error) {
	sourceToWorkloads, err := getOrLoadChartWorkloads(s, chartCache)
	if err != nil {
		return nil, err
	}

	if s.Resource == nil {
		return nil, errors.New("nil resource")
	}

	targetGroup, targetVersion := parseGroupVersion(s.Resource.GetApiVersion())
	targetKind := s.Resource.GetKind()
	targetName := s.Resource.GetName()
	targetNamespace := s.Resource.GetNamespace()

	crdScopes := extractClusterScopedCRDsFromWorkloads(sourceToWorkloads)
	for k, v := range extractCRDsFromChartDir(s.ChartPath, s.AllowedBasePath) {
		crdScopes[k] = v
	}
	for k, v := range extractClusterScopedCRDsFromSuggestions([]HelmFixSuggestion{s}) {
		crdScopes[k] = v
	}

	isClusterScopedRes := isClusterScoped(resourceKey{
		Group:   targetGroup,
		Version: targetVersion,
		Kind:    targetKind,
	}, crdScopes)

	var matches []map[string]interface{}
	for _, workloads := range sourceToWorkloads {
		for _, w := range workloads {
			candGroup, candVersion := parseGroupVersion(w.GetApiVersion())
			candKind := w.GetKind()
			candName := w.GetName()
			candNamespace := w.GetNamespace()
			if candGroup != targetGroup || candVersion != targetVersion ||
				candKind != targetKind || candName != targetName {
				continue
			}

			if isClusterScopedRes {
				// Cluster-scoped resources match on GVK + Name; namespace is ignored.
			} else {
				namespaceMatch := candNamespace == targetNamespace
				if !namespaceMatch && s.HelmValueOptions.ReleaseNamespace != "" {
					namespaceMatch =
						(targetNamespace == "" && candNamespace == s.HelmValueOptions.ReleaseNamespace) ||
							(candNamespace == "" && targetNamespace == s.HelmValueOptions.ReleaseNamespace)
				}
				if !namespaceMatch {
					continue
				}
			}

			obj := w.GetObject()
			if localworkload.IsTypeLocalWorkload(obj) {
				lw := localworkload.NewLocalWorkload(obj)
				lw.DeletePathEntry()
				obj = lw.GetObject()
			}
			matches = append(matches, deepCopyMap(obj))
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

// isClusterScopedResource reports whether a Kubernetes resource is cluster-scoped,
// deriving scope from the full GVK using Kustomize's openapi definitions with compatibility
// fallback constrained strictly to exact built-in Kubernetes GVKs.
func isClusterScopedResource(key resourceKey) bool {
	if resid.NewGvk(key.Group, key.Version, key.Kind).IsClusterScoped() {
		return true
	}
	return isBuiltinClusterScopedGVK(key.Group, key.Kind)
}

// isBuiltinClusterScopedGVK reports whether the group and kind match a standard built-in
// cluster-scoped Kubernetes resource. Custom resources in other API groups (even if sharing
// a kind name like "Node") are not matched.
func isBuiltinClusterScopedGVK(group, kind string) bool {
	switch kind {
	case "ClusterRole", "ClusterRoleBinding":
		return group == "rbac.authorization.k8s.io"
	case "Namespace", "Node", "PersistentVolume", "ComponentStatus":
		return group == ""
	case "CustomResourceDefinition":
		return group == "apiextensions.k8s.io"
	case "APIService":
		return group == "apiregistration.k8s.io"
	case "StorageClass", "VolumeAttachment", "CSIDriver", "CSINode":
		return group == "storage.k8s.io"
	case "IngressClass":
		return group == "networking.k8s.io"
	case "RuntimeClass":
		return group == "node.k8s.io"
	case "PriorityClass":
		return group == "scheduling.k8s.io"
	case "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration",
		"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding":
		return group == "admissionregistration.k8s.io"
	case "CertificateSigningRequest":
		return group == "certificates.k8s.io"
	default:
		return false
	}
}

// isBuiltinNamespacedGVK reports whether the group and kind match a standard built-in
// namespaced Kubernetes resource.
func isBuiltinNamespacedGVK(group, kind string) bool {
	switch group {
	case "":
		switch kind {
		case "Pod", "Service", "ConfigMap", "Secret", "ServiceAccount",
			"PersistentVolumeClaim", "Endpoints", "LimitRange", "ResourceQuota",
			"ReplicationController", "PodTemplate", "Event":
			return true
		}
	case "apps":
		switch kind {
		case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ControllerRevision":
			return true
		}
	case "batch":
		switch kind {
		case "Job", "CronJob":
			return true
		}
	case "networking.k8s.io":
		switch kind {
		case "Ingress", "NetworkPolicy":
			return true
		}
	case "rbac.authorization.k8s.io":
		switch kind {
		case "Role", "RoleBinding":
			return true
		}
	case "policy":
		switch kind {
		case "PodDisruptionBudget":
			return true
		}
	case "autoscaling":
		switch kind {
		case "HorizontalPodAutoscaler":
			return true
		}
	case "coordination.k8s.io":
		switch kind {
		case "Lease":
			return true
		}
	case "discovery.k8s.io":
		switch kind {
		case "EndpointSlice":
			return true
		}
	}
	return false
}

type crdScopeKey struct {
	Group string
	Kind  string
}

// extractCRDsFromChartDir inspects standard Helm CRD directories (crds/ and dependency charts/*/crds/)
// within chartPath, parsing all YAML files for CustomResourceDefinition declarations.
func extractCRDsFromChartDir(chartPath string, allowedBasePath string) map[crdScopeKey]bool {
	res := make(map[crdScopeKey]bool)
	if chartPath == "" {
		return res
	}

	var crdDirs []string
	mainCrds := filepath.Join(chartPath, "crds")
	if fi, err := os.Stat(mainCrds); err == nil && fi.IsDir() {
		crdDirs = append(crdDirs, mainCrds)
	}

	chartsDir := filepath.Join(chartPath, "charts")
	if entries, err := os.ReadDir(chartsDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				subCrds := filepath.Join(chartsDir, entry.Name(), "crds")
				if fi, err := os.Stat(subCrds); err == nil && fi.IsDir() {
					crdDirs = append(crdDirs, subCrds)
				}
			}
		}
	}

	for _, dir := range crdDirs {
		crdRoot, openErr := os.OpenRoot(dir)
		if openErr != nil {
			continue
		}
		_ = fs.WalkDir(crdRoot.FS(), ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".yaml" && ext != ".yml" {
				return nil
			}
			if allowedBasePath != "" {
				fullPath := filepath.Join(dir, path)
				resolved, evalErr := filepath.EvalSymlinks(fullPath)
				if evalErr != nil || !isPathContained(allowedBasePath, resolved) {
					return nil
				}
			}
			data, readErr := crdRoot.ReadFile(path)
			if readErr != nil {
				return nil
			}
			decoder := yaml.NewDecoder(strings.NewReader(string(data)))
			for {
				var obj map[string]interface{}
				if decErr := decoder.Decode(&obj); decErr != nil {
					break
				}
				if obj == nil {
					continue
				}
				kind, _ := obj["kind"].(string)
				if kind != "CustomResourceDefinition" {
					continue
				}
				spec, ok := obj["spec"].(map[string]interface{})
				if !ok || spec == nil {
					continue
				}
				scope, _ := spec["scope"].(string)
				group, _ := spec["group"].(string)
				names, _ := spec["names"].(map[string]interface{})
				if names == nil {
					continue
				}
				crdKind, _ := names["kind"].(string)
				group = strings.TrimSpace(group)
				crdKind = strings.TrimSpace(crdKind)
				if group != "" && crdKind != "" {
					isCluster := strings.EqualFold(strings.TrimSpace(scope), "Cluster")
					res[crdScopeKey{Group: group, Kind: crdKind}] = isCluster
				}
			}
			return nil
		})
		_ = crdRoot.Close()
	}

	return res
}

// extractClusterScopedCRDsFromWorkloads scans rendered chart workloads for any CustomResourceDefinition
// returning the map of (Group, Kind) -> isClusterScoped.
func extractClusterScopedCRDsFromWorkloads(sourceToWorkloads map[string][]workloadinterface.IMetadata) map[crdScopeKey]bool {
	res := make(map[crdScopeKey]bool)
	for _, workloads := range sourceToWorkloads {
		for _, w := range workloads {
			if w.GetKind() != "CustomResourceDefinition" {
				continue
			}
			obj := w.GetObject()
			if obj == nil {
				continue
			}
			spec, ok := obj["spec"].(map[string]interface{})
			if !ok || spec == nil {
				continue
			}
			scope, _ := spec["scope"].(string)
			group, _ := spec["group"].(string)
			names, _ := spec["names"].(map[string]interface{})
			if names == nil {
				continue
			}
			kind, _ := names["kind"].(string)
			group = strings.TrimSpace(group)
			kind = strings.TrimSpace(kind)
			if group != "" && kind != "" {
				res[crdScopeKey{Group: group, Kind: kind}] = strings.EqualFold(strings.TrimSpace(scope), "Cluster")
			}
		}
	}
	return res
}

// extractClusterScopedCRDsFromSuggestions scans fix suggestions (and their unredacted bases)
// for any CustomResourceDefinition returning the map of (Group, Kind) -> isClusterScoped.
func extractClusterScopedCRDsFromSuggestions(suggestions []HelmFixSuggestion) map[crdScopeKey]bool {
	res := make(map[crdScopeKey]bool)
	checkObj := func(obj map[string]interface{}) {
		if obj == nil {
			return
		}
		kind, _ := obj["kind"].(string)
		if kind != "CustomResourceDefinition" {
			return
		}
		spec, ok := obj["spec"].(map[string]interface{})
		if !ok || spec == nil {
			return
		}
		scope, _ := spec["scope"].(string)
		group, _ := spec["group"].(string)
		names, _ := spec["names"].(map[string]interface{})
		if names == nil {
			return
		}
		k, _ := names["kind"].(string)
		group = strings.TrimSpace(group)
		k = strings.TrimSpace(k)
		if group != "" && k != "" {
			res[crdScopeKey{Group: group, Kind: k}] = strings.EqualFold(strings.TrimSpace(scope), "Cluster")
		}
	}
	for _, s := range suggestions {
		if s.Resource != nil {
			checkObj(s.Resource.GetObject())
		}
		if s.UnredactedBase != nil {
			checkObj(s.UnredactedBase)
		}
	}
	return res
}

type resourceScope int

const (
	scopeUnknown resourceScope = iota
	scopeNamespaced
	scopeCluster
)

// resolveResourceScope derives the resource scope (cluster, namespaced, or unknown) from
// OpenAPI definitions, built-in Kubernetes GVK tables, and discovered CRDs.
func resolveResourceScope(key resourceKey, crdScopes map[crdScopeKey]bool) resourceScope {
	if isClusterScopedResource(key) {
		return scopeCluster
	}
	if isBuiltinNamespacedGVK(key.Group, key.Kind) {
		return scopeNamespaced
	}
	if crdScopes != nil {
		if isCluster, found := crdScopes[crdScopeKey{Group: key.Group, Kind: key.Kind}]; found {
			if isCluster {
				return scopeCluster
			}
			return scopeNamespaced
		}
	}
	return scopeUnknown
}

// isClusterScoped reports whether key identifies a cluster-scoped resource.
// Unknown scopes are explicitly treated as namespaced to protect multi-namespace tenancy.
func isClusterScoped(key resourceKey, crdScopes map[crdScopeKey]bool) bool {
	scope := resolveResourceScope(key, crdScopes)
	switch scope {
	case scopeCluster:
		return true
	case scopeNamespaced:
		return false
	case scopeUnknown:
		// Explicitly handle unknown scope: resources with unknown scope cannot be
		// assumed cluster-scoped and are kept namespaced to protect multi-namespace tenancy.
		return false
	default:
		return false
	}
}

// isSuggestionClusterScoped reports whether suggestion s refers to a cluster-scoped resource.
// Built-in types are identified via isClusterScopedResource and isBuiltinNamespacedGVK.
// For custom resources, CRD declarations are inspected strictly from s's own chart (if s.ChartPath != "")
// or from non-chart suggestions in the batch. CRD declarations from different charts are isolated
// and cannot override or pollute each other.
func isSuggestionClusterScoped(s HelmFixSuggestion, allSuggestions []HelmFixSuggestion, chartCache map[string]map[string][]workloadinterface.IMetadata) bool {
	targetGroup, targetVersion := parseGroupVersion(s.Resource.GetApiVersion())
	targetKind := s.Resource.GetKind()
	if (targetGroup == "" && targetVersion == "") || targetKind == "" {
		if s.Resource.GetObject() != nil {
			if apiVersion, _ := s.Resource.GetObject()["apiVersion"].(string); apiVersion != "" {
				targetGroup, targetVersion = parseGroupVersion(apiVersion)
			}
			if kind, _ := s.Resource.GetObject()["kind"].(string); kind != "" {
				targetKind = kind
			}
		}
	}
	if targetKind == "" && s.UnredactedBase != nil {
		targetKind, _ = s.UnredactedBase["kind"].(string)
		apiVersion, _ := s.UnredactedBase["apiVersion"].(string)
		targetGroup, targetVersion = parseGroupVersion(apiVersion)
	}

	key := resourceKey{
		Group:   targetGroup,
		Version: targetVersion,
		Kind:    targetKind,
	}
	if isClusterScopedResource(key) {
		return true
	}
	if isBuiltinNamespacedGVK(key.Group, key.Kind) {
		return false
	}

	crdScopes := make(map[crdScopeKey]bool)
	if s.ChartPath != "" {
		for k, v := range extractCRDsFromChartDir(s.ChartPath, s.AllowedBasePath) {
			crdScopes[k] = v
		}
		if sourceToWorkloads, err := getOrLoadChartWorkloads(s, chartCache); err == nil && sourceToWorkloads != nil {
			for k, v := range extractClusterScopedCRDsFromWorkloads(sourceToWorkloads) {
				crdScopes[k] = v
			}
		}
		for k, v := range extractClusterScopedCRDsFromSuggestions([]HelmFixSuggestion{s}) {
			crdScopes[k] = v
		}
	} else {
		var nonChartSuggestions []HelmFixSuggestion
		for _, item := range allSuggestions {
			if item.ChartPath == "" {
				nonChartSuggestions = append(nonChartSuggestions, item)
			}
		}
		crdScopes = extractClusterScopedCRDsFromSuggestions(nonChartSuggestions)
	}

	return isClusterScoped(key, crdScopes)
}

// writeRestrictedFile writes data to filename within root with mode 0600 and explicitly chmods an existing file to 0600.
// It uses os.Root containment to prevent following symlinks that escape the output directory.
func writeRestrictedFile(root *os.Root, filename string, data []byte) error {
	file, err := root.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// ChartCache stores rendered chart workloads keyed by chart path and value options.
type ChartCache = map[string]map[string][]workloadinterface.IMetadata

// NewChartCache creates an empty cache for sharing rendered chart workloads across Kustomize operations.
func NewChartCache() ChartCache {
	return make(ChartCache)
}

// HasEmittableKustomizePatches checks whether any of the suggestions can produce
// a valid Kustomize patch without being skipped or declined.
// An optional shared chartCache can be passed to share rendered chart workloads across callers.
func HasEmittableKustomizePatches(suggestions []HelmFixSuggestion, sharedCache ...ChartCache) bool {
	if len(suggestions) == 0 {
		return false
	}
	chartCache := make(map[string]map[string][]workloadinterface.IMetadata)
	if len(sharedCache) > 0 && sharedCache[0] != nil {
		chartCache = sharedCache[0]
	}
	for _, s := range suggestions {
		if s.Resource == nil || len(s.FixPaths) == 0 {
			continue
		}
		_, declineReason := resolveBaseObject(s, chartCache)
		if declineReason == "" {
			return true
		}
	}
	return false
}

// restoreBackups moves each entry in backupRelDir back into root.
// It restores an entry only when root has no entry with that name.
// It returns an error for every entry it does not restore, including entries skipped
// because root already has that name. The caller keeps backupRelDir when the error is non-nil.
func restoreBackups(root *os.Root, backupRelDir string) error {
	entries, err := fs.ReadDir(root.FS(), backupRelDir)
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		if _, err := root.Lstat(e.Name()); err == nil {
			errs = append(errs, fmt.Errorf("cannot restore %q: destination exists", e.Name()))
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("cannot restore %q: %w", e.Name(), err))
			continue
		}
		backupPath := filepath.Join(backupRelDir, e.Name())
		if err := root.Rename(backupPath, e.Name()); err != nil {
			errs = append(errs, fmt.Errorf("cannot restore %q: %w", e.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// failKustomizeWriteDuringPublication is an unexported hook used in tests to inject write failures
// during the staging or publication phases.
var failKustomizeWriteDuringPublication func(filename string) error

// plannedResourcePatch holds the planned patch file, target, and base document for a resource.
type plannedResourcePatch struct {
	key           resourceKey
	resIdent      string
	patchFileName string
	patchBytes    []byte
	target        kustomizeTarget
	baseDoc       []byte
}

func planKustomizePatches(suggestions []HelmFixSuggestion, dir string, sharedCache ...ChartCache) ([]plannedResourcePatch, *KustomizeEmitResult, error) {
	result := &KustomizeEmitResult{}
	if len(suggestions) == 0 {
		return nil, result, nil
	}

	chartCache := make(ChartCache)
	if len(sharedCache) > 0 && sharedCache[0] != nil {
		chartCache = sharedCache[0]
	}

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

		isClusterScopedRes := isSuggestionClusterScoped(s, suggestions, chartCache)

		group, version := parseGroupVersion(s.Resource.GetApiVersion())
		rNamespace := s.Resource.GetNamespace()
		if rNamespace == "" && s.Resource.GetObject() != nil {
			if meta, ok := s.Resource.GetObject()["metadata"].(map[string]interface{}); ok && meta != nil {
				rNamespace, _ = meta["namespace"].(string)
			}
		}
		key := resourceKey{
			Group:     group,
			Version:   version,
			Kind:      s.Resource.GetKind(),
			Namespace: rNamespace,
			Name:      s.Resource.GetName(),
		}
		isReleaseNamespace := false
		if key.Namespace == "" && !isClusterScopedRes && s.HelmValueOptions.ReleaseNamespace != "" {
			key.Namespace = s.HelmValueOptions.ReleaseNamespace
			isReleaseNamespace = true
			// Copy top-level map and metadata map to avoid mutating caller object,
			// preserving exact numeric types in spec and nested structures.
			newBaseObj := make(map[string]interface{}, len(baseObj)+1)
			for k, v := range baseObj {
				newBaseObj[k] = v
			}
			metadata := make(map[string]interface{})
			if meta, ok := baseObj["metadata"].(map[string]interface{}); ok && meta != nil {
				for k, v := range meta {
					metadata[k] = v
				}
			}
			if namespace, _ := metadata["namespace"].(string); namespace == "" {
				metadata["namespace"] = key.Namespace
			}
			newBaseObj["metadata"] = metadata
			baseObj = newBaseObj
		}

		rg, exists := groups[key]
		if !exists {
			rg = &resourceGroup{
				key:                key,
				resource:           s.Resource,
				baseObj:            baseObj,
				isClusterScoped:    isClusterScopedRes,
				isReleaseNamespace: isReleaseNamespace,
			}
			groups[key] = rg
			keysInOrder = append(keysInOrder, key)
		}

		rg.fixPaths = append(rg.fixPaths, s.FixPaths...)
	}

	if len(groups) == 0 {
		return nil, result, nil
	}

	var plannedPatches []plannedResourcePatch
	writtenFiles := make(map[string]resourceKey)
	var registeredTargets []registeredTarget

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
		var applyErr error
		for _, fp := range concreteFixPaths {
			patchOps, err := resolveFixPathOps(workingObj, fp)
			if err != nil {
				applyErr = err
				break
			}
			ops = append(ops, patchOps...)
		}

		if applyErr != nil {
			result.SkippedResources = append(result.SkippedResources, KustomizeSkippedResource{
				ResourceKey: fmt.Sprintf("%s/%s", rg.key.Kind, rg.key.Name),
				Reason:      fmt.Sprintf("declined: fix path could not be applied: %v", applyErr),
			})
			continue
		}

		if len(ops) == 0 {
			continue
		}

		patchFileName := resourcePatchFilename(rg.key)
		if existingKey, exists := writtenFiles[patchFileName]; exists {
			return nil, nil, fmt.Errorf("filename collision detected: patch file %q for resource %s/%s collides with %s/%s",
				patchFileName, rg.key.Kind, rg.key.Name, existingKey.Kind, existingKey.Name)
		}
		writtenFiles[patchFileName] = rg.key

		if dir != "" {
			if _, err := ensureSubpath(dir, patchFileName); err != nil {
				return nil, nil, err
			}
		}

		patchBytes, err := yaml.Marshal(ops)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal patch for %s/%s: %w", rg.key.Kind, rg.key.Name, err)
		}

		groupSelector := "^$"
		if rg.key.Group != "" {
			groupSelector = "^" + regexp.QuoteMeta(rg.key.Group) + "$"
		}
		target := kustomizeTarget{
			Group:   groupSelector,
			Version: regexp.QuoteMeta(rg.key.Version),
			Kind:    regexp.QuoteMeta(rg.key.Kind),
			Name:    regexp.QuoteMeta(rg.key.Name),
		}
		if rg.isClusterScoped {
			target.Namespace = ""
		} else if rg.isReleaseNamespace && rg.key.Namespace != "" && rg.key.Namespace != "default" {
			target.Namespace = fmt.Sprintf("^($|default|%s$)", regexp.QuoteMeta(rg.key.Namespace))
		} else if rg.key.Namespace != "" {
			target.Namespace = rg.key.Namespace
		} else {
			target.Namespace = "default"
		}

		resIdent := fmt.Sprintf("%s/%s", rg.key.Kind, rg.key.Name)
		if rg.key.Namespace != "" {
			resIdent = fmt.Sprintf("%s/%s/%s", rg.key.Kind, rg.key.Namespace, rg.key.Name)
		}

		currentRegistered := registeredTarget{
			target:          target,
			resIdent:        resIdent,
			isClusterScoped: rg.isClusterScoped,
			candidateNs:     rg.key.Namespace,
		}
		for _, existing := range registeredTargets {
			if targetsOverlap(existing, currentRegistered) {
				return nil, nil, fmt.Errorf("ambiguous patch target detected: target %s/%s in namespace %q matches multiple resources (%s and %s)",
					target.Kind, target.Name, target.Namespace, existing.resIdent, resIdent)
			}
		}
		registeredTargets = append(registeredTargets, currentRegistered)

		cleanObj := stripServerManagedFields(rg.baseObj)
		baseDocBytes, err := yaml.Marshal(cleanObj)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal base document for %s/%s: %w", rg.key.Kind, rg.key.Name, err)
		}

		plannedPatches = append(plannedPatches, plannedResourcePatch{
			key:           rg.key,
			resIdent:      resIdent,
			patchFileName: patchFileName,
			patchBytes:    patchBytes,
			target:        target,
			baseDoc:       baseDocBytes,
		})
	}

	return plannedPatches, result, nil
}

// PlannedKustomizeFiles returns the filenames of all files that EmitKustomizePatch
// would generate for the given suggestions ("base.yaml", "kustomization.yaml",
// and all planned patch filenames). If no patches would be emitted, returns nil.
// An optional shared chartCache can be passed to avoid re-rendering Helm charts.
func PlannedKustomizeFiles(suggestions []HelmFixSuggestion, sharedCache ...ChartCache) []string {
	plannedPatches, _, err := planKustomizePatches(suggestions, "", sharedCache...)
	if err != nil || len(plannedPatches) == 0 {
		return nil
	}
	files := make([]string, 0, len(plannedPatches)+2)
	files = append(files, "base.yaml", "kustomization.yaml")
	for _, p := range plannedPatches {
		files = append(files, p.patchFileName)
	}
	return files
}

// EmitKustomizeOption configures EmitKustomizePatch execution.
type EmitKustomizeOption func(*emitKustomizeOptions)

type emitKustomizeOptions struct {
	overwrite  bool
	chartCache ChartCache
}

// WithOverwrite configures whether EmitKustomizePatch is permitted to overwrite
// an existing non-empty output directory. When false (the default), EmitKustomizePatch
// refuses to write into a non-empty directory.
func WithOverwrite(overwrite bool) EmitKustomizeOption {
	return func(o *emitKustomizeOptions) {
		o.overwrite = overwrite
	}
}

// WithChartCache configures a shared ChartCache to avoid re-rendering Helm charts.
func WithChartCache(cache ChartCache) EmitKustomizeOption {
	return func(o *emitKustomizeOptions) {
		o.chartCache = cache
	}
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
func EmitKustomizePatch(suggestions []HelmFixSuggestion, dir string, opts ...EmitKustomizeOption) (*KustomizeEmitResult, error) {
	var options emitKustomizeOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	plannedPatches, result, err := planKustomizePatches(suggestions, dir, options.chartCache)
	if err != nil {
		return nil, err
	}
	if len(plannedPatches) == 0 {
		return result, nil
	}

	// Ensure the output directory exists
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create kustomize output dir %q: %w", dir, err)
	}

	lockPath := filepath.Join(dir, ".kust.lock")
	fileLock := flock.New(lockPath)
	locked, err := fileLock.TryLock()
	if err != nil {
		return nil, fmt.Errorf("failed to lock output directory %q: %w", dir, err)
	}
	if !locked {
		return nil, fmt.Errorf("output directory %q is locked by another operation", dir)
	}
	defer func() {
		_ = fileLock.Unlock()
	}()

	// Refuse non-empty destination directory unless explicit overwrite permission is granted
	if !options.overwrite {
		entries, err := os.ReadDir(dir)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to inspect output directory %q: %w", dir, err)
		}
		var nonEmpty bool
		for _, e := range entries {
			if e.Name() != ".kust.lock" {
				nonEmpty = true
				break
			}
		}
		if nonEmpty {
			return nil, fmt.Errorf("output directory %q is not empty; pass --no-confirm to write into it anyway", dir)
		}
	}

	// Restrict permissions on the output directory containing rendered manifests, enforcing 0700 on existing dirs too.
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to restrict permissions on kustomize output dir %q: %w", dir, err)
	}

	kust := kustomizationDoc{
		APIVersion: "kustomize.config.k8s.io/v1beta1",
		Kind:       "Kustomization",
	}

	// 2. Build base.yaml containing ONLY the successfully resolved resources.
	var baseContent []byte
	for i, p := range plannedPatches {
		if i > 0 {
			baseContent = append(baseContent, []byte("---\n")...)
		}
		baseContent = append(baseContent, p.baseDoc...)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to open output directory %q: %w", dir, err)
	}
	defer root.Close()

	// Create an isolated staging directory inside root before promotion.
	// Staging protects the destination from write and validation failures before promotion.
	// If any write or verification fails, staging directory is wiped under root without modifying destination files.
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("failed to generate staging directory name: %w", err)
	}
	stagingRelDir := fmt.Sprintf(".kust-staging-%d-%x", os.Getpid(), b)
	if err := root.Mkdir(stagingRelDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create staging directory in %q: %w", dir, err)
	}
	keepStaging := false
	defer func() {
		if !keepStaging {
			_ = root.RemoveAll(stagingRelDir)
		}
	}()

	stagingRoot, err := root.OpenRoot(stagingRelDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open staging directory %q: %w", stagingRelDir, err)
	}
	defer stagingRoot.Close()

	var stagedFiles []string

	if len(baseContent) > 0 {
		if _, err := ensureSubpath(dir, "base.yaml"); err != nil {
			return nil, err
		}
		if failKustomizeWriteDuringPublication != nil {
			if err := failKustomizeWriteDuringPublication("base.yaml"); err != nil {
				return nil, err
			}
		}
		if err := writeRestrictedFile(stagingRoot, "base.yaml", baseContent); err != nil {
			return nil, fmt.Errorf("failed to write base.yaml: %w", err)
		}
		stagedFiles = append(stagedFiles, "base.yaml")
		kust.Resources = append(kust.Resources, "base.yaml")
	}

	// 3. Write patch files for the planned patches into staging
	for _, p := range plannedPatches {
		if _, err := ensureSubpath(dir, p.patchFileName); err != nil {
			return nil, err
		}
		if failKustomizeWriteDuringPublication != nil {
			if err := failKustomizeWriteDuringPublication(p.patchFileName); err != nil {
				return nil, err
			}
		}
		if err := writeRestrictedFile(stagingRoot, p.patchFileName, p.patchBytes); err != nil {
			return nil, fmt.Errorf("failed to write patch file %q: %w", p.patchFileName, err)
		}
		stagedFiles = append(stagedFiles, p.patchFileName)
		kust.Patches = append(kust.Patches, kustomizePatchEntry{
			Path:   p.patchFileName,
			Target: p.target,
		})
	}

	// 4. Write kustomization.yaml into staging
	if _, err := ensureSubpath(dir, "kustomization.yaml"); err != nil {
		return nil, err
	}

	kustBytes, err := yaml.Marshal(kust)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal kustomization.yaml: %w", err)
	}
	if failKustomizeWriteDuringPublication != nil {
		if err := failKustomizeWriteDuringPublication("kustomization.yaml"); err != nil {
			return nil, err
		}
	}
	if err := writeRestrictedFile(stagingRoot, "kustomization.yaml", kustBytes); err != nil {
		return nil, fmt.Errorf("failed to write kustomization.yaml: %w", err)
	}
	stagedFiles = append(stagedFiles, "kustomization.yaml")

	_ = stagingRoot.Close()

	// 5. Reject unsupported entries before publication, keeping backup operations root-contained.
	// Preserves existing directories, symlinks, and non-regular files from being overwritten or destroyed on failure.
	for _, fName := range stagedFiles {
		fi, err := root.Lstat(fName)
		if err == nil {
			if fi.IsDir() {
				return nil, fmt.Errorf("unsupported destination entry %q: cannot overwrite directory", fName)
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				target, linkErr := root.Readlink(fName)
				if linkErr == nil && (filepath.IsAbs(target) || strings.HasPrefix(filepath.Clean(target), "..")) {
					return nil, fmt.Errorf("pre-existing file %q is a symlink escaping output directory %q", fName, dir)
				}
				return nil, fmt.Errorf("unsupported destination entry %q: cannot overwrite symbolic link", fName)
			}
			if !fi.Mode().IsRegular() {
				return nil, fmt.Errorf("unsupported destination entry %q: unsupported file type", fName)
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("failed to inspect destination file %q: %w", fName, err)
		}
	}

	if !options.overwrite {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("failed to inspect output directory %q: %w", dir, err)
		}
		for _, e := range entries {
			if e.Name() != ".kust.lock" && e.Name() != stagingRelDir {
				return nil, fmt.Errorf("output directory %q is not empty; pass --no-confirm to write into it anyway", dir)
			}
		}
	}

	// 6. Atomically promote staged files to destination directory with rollback on failure
	backupRelDir := filepath.Join(stagingRelDir, ".backup")
	if err := root.Mkdir(backupRelDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create backup directory in %q: %w", stagingRelDir, err)
	}

	// Back up existing regular files that will be overwritten, keeping inspection and backup root-contained
	for _, fName := range stagedFiles {
		fi, err := root.Lstat(fName)
		if err == nil && fi.Mode().IsRegular() {
			backupRelPath := filepath.Join(backupRelDir, fName)
			if err := root.Rename(fName, backupRelPath); err != nil {
				if restoreErr := restoreBackups(root, backupRelDir); restoreErr != nil {
					keepStaging = true
					return nil, fmt.Errorf("failed to back up %q: %w; backups not restored and kept in %s: %v", fName, err, filepath.Join(dir, backupRelDir), restoreErr)
				}
				return nil, fmt.Errorf("failed to back up existing file %q before promotion: %w", fName, err)
			}
		} else if err == nil {
			if restoreErr := restoreBackups(root, backupRelDir); restoreErr != nil {
				keepStaging = true
				return nil, fmt.Errorf("unsupported destination entry %q changed before promotion; backups not restored and kept in %s: %v", fName, filepath.Join(dir, backupRelDir), restoreErr)
			}
			return nil, fmt.Errorf("unsupported destination entry %q changed before promotion", fName)
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			if restoreErr := restoreBackups(root, backupRelDir); restoreErr != nil {
				keepStaging = true
				return nil, fmt.Errorf("failed to inspect destination file %q: %w; backups not restored and kept in %s: %v", fName, err, filepath.Join(dir, backupRelDir), restoreErr)
			}
			return nil, fmt.Errorf("failed to inspect destination file %q before promotion: %w", fName, err)
		}
	}

	var promoted []string
	var promotionErr error
	for _, fName := range stagedFiles {
		if failKustomizeWriteDuringPublication != nil {
			if err := failKustomizeWriteDuringPublication("publish:" + fName); err != nil {
				promotionErr = err
				break
			}
		}
		srcRelPath := filepath.Join(stagingRelDir, fName)
		if err := root.Rename(srcRelPath, fName); err != nil {
			promotionErr = err
			break
		}
		promoted = append(promoted, fName)
	}

	if promotionErr != nil {
		var removalErrs []error
		// Roll back partially promoted files under root
		for _, fName := range promoted {
			if err := root.Remove(fName); err != nil && !errors.Is(err, fs.ErrNotExist) {
				removalErrs = append(removalErrs, fmt.Errorf("failed to remove partially promoted file %q: %w", fName, err))
			}
		}
		restoreErr := restoreBackups(root, backupRelDir)
		if len(removalErrs) > 0 || restoreErr != nil {
			keepStaging = true
			return nil, fmt.Errorf("failed to promote staged files: %w; rollback incomplete (backups preserved in %s): removal errors: %v; restore errors: %v",
				promotionErr, filepath.Join(dir, backupRelDir), errors.Join(removalErrs...), restoreErr)
		}
		return nil, fmt.Errorf("failed to promote staged file: %w", promotionErr)
	}

	for _, p := range plannedPatches {
		result.EmittedResources = append(result.EmittedResources, p.resIdent)
	}

	return result, nil
}
