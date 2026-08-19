package printer

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

type pathSegment struct {
	key   string
	index int
}

func splitPath(path string) []pathSegment {
	path = strings.TrimPrefix(path, ".")
	if i := strings.Index(path, "="); i >= 0 {
		path = path[:i]
	}

	var segments []pathSegment
	for _, part := range strings.Split(path, ".") {
		if part == "" {
			continue
		}
		seg := pathSegment{index: -1}
		if i := strings.Index(part, "["); i >= 0 {
			seg.key = part[:i]
			tail := part[i+1:]
			if j := strings.Index(tail, "]"); j >= 0 {
				if n, err := strconv.Atoi(tail[:j]); err == nil {
					seg.index = n
				}
			}
		} else {
			seg.key = part
		}
		segments = append(segments, seg)
	}
	return segments
}

// anyToString converts a value to its string representation.
// It handles all numeric types that may appear in JSON-decoded or
// programmatically-constructed Kubernetes objects. Maps and slices are
// rendered as compact JSON rather than dropped, so a failing path whose
// value is an object or array (e.g. a container's full securityContext, an
// env var list) still surfaces something instead of falling back to the
// bare path with no value at all.
func anyToString(v any) (string, bool) {
	switch val := v.(type) {
	case nil:
		return "null", true
	case bool:
		return strconv.FormatBool(val), true
	case string:
		if val == "" {
			return `""`, true
		}
		return val, true
	case float64:
		if val == float64(int64(val)) {
			return strconv.FormatInt(int64(val), 10), true
		}
		return strconv.FormatFloat(val, 'f', -1, 64), true
	case int:
		return strconv.Itoa(val), true
	case int32:
		return strconv.FormatInt(int64(val), 10), true
	case int64:
		return strconv.FormatInt(val, 10), true
	case uint:
		return strconv.FormatUint(uint64(val), 10), true
	case uint32:
		return strconv.FormatUint(uint64(val), 10), true
	case uint64:
		return strconv.FormatUint(val, 10), true
	case json.Number:
		return val.String(), true
	case map[string]any, []any:
		b, err := json.Marshal(val)
		if err != nil {
			return "", false
		}
		return string(b), true
	default:
		return "", false
	}
}

func extractValueAtPath(obj map[string]any, path string) (string, bool) {
	if len(obj) == 0 || path == "" {
		return "", false
	}
	segments := splitPath(path)
	if len(segments) == 0 {
		return "", false
	}

	var cur any = obj
	for _, seg := range segments {
		switch v := cur.(type) {
		case map[string]any:
			next, ok := v[seg.key]
			if !ok {
				return "", false
			}
			if seg.index >= 0 {
				arr, ok := next.([]any)
				if !ok || seg.index >= len(arr) {
					return "", false
				}
				cur = arr[seg.index]
			} else {
				cur = next
			}
		case []any:
			if seg.index < 0 || seg.index >= len(v) {
				return "", false
			}
			cur = v[seg.index]
		default:
			return "", false
		}
	}
	return anyToString(cur)
}

// isSensitivePath reports whether a path targets a field whose value must
// not be surfaced in scan output unless --show-secrets is set. Secret
// data/stringData and container env[N].value (C-0012 plaintext credentials)
// are treated as sensitive.
func isSensitivePath(kind, path string) bool {
	if i := strings.Index(path, "="); i >= 0 {
		path = path[:i]
	}
	path = strings.TrimLeft(path, ".")
	if kind == "Secret" {
		return path == "data" || strings.HasPrefix(path, "data.") ||
			path == "stringData" || strings.HasPrefix(path, "stringData.")
	}
	// C-0012 plaintext credentials live on container env .value, not Secret.data.
	return isContainerEnvValuePath(path)
}

// isContainerEnvValuePath reports whether path selects env[N].value
// (including under spec.template.spec / initContainers / ephemeralContainers).
func isContainerEnvValuePath(path string) bool {
	if !strings.HasSuffix(path, "].value") {
		return false
	}
	env := strings.LastIndex(path, "env[")
	if env < 0 {
		return false
	}
	inner := path[env+len("env[") : len(path)-len("].value")]
	if inner == "" {
		return false
	}
	for i := 0; i < len(inner); i++ {
		if inner[i] < '0' || inner[i] > '9' {
			return false
		}
	}
	return true
}

// enrichedPathsForField iterates a control's rule paths, extracts the string
// field selected by getPath, and appends " (current: <value>)" when the value
// can be read from the resource object. Paths that are sensitive (e.g., Secret
// data fields) or whose value is a map, slice, or absent fall back to the bare
// path string so the output is never degraded or a security risk.
func enrichedPathsForField(control *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata, getPath func(armotypes.PosturePaths) string) []string {
	var paths []string
	obj := resource.GetObject()
	kind := resource.GetKind()
	for j := range control.ResourceAssociatedRules {
		for k := range control.ResourceAssociatedRules[j].Paths {
			p := getPath(control.ResourceAssociatedRules[j].Paths[k])
			if p == "" {
				continue
			}
			if !isSensitivePath(kind, p) {
				if val, ok := extractValueAtPath(obj, p); ok {
					paths = append(paths, p+" (current: "+val+")")
					continue
				}
			}
			paths = append(paths, p)
		}
	}
	return paths
}

func failedPathsWithCurrentValues(control *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata) []string {
	return enrichedPathsForField(control, resource, func(p armotypes.PosturePaths) string { return p.FailedPath })
}

func reviewPathsWithCurrentValues(control *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata) []string {
	return enrichedPathsForField(control, resource, func(p armotypes.PosturePaths) string { return p.ReviewPath })
}

// redactedValue is substituted for sensitive field values when --show-secrets is not set.
const redactedValue = "[redacted]"

// fixPathsToStringFiltered emits fix paths as "path=value", redacting the value to
// [redacted] for Secret.data and Secret.stringData paths when showSecrets is false.
// This prevents FixPath.Value leaking secret material through the evidence column.
func fixPathsToStringFiltered(control *resourcesresults.ResourceAssociatedControl, kind string, showSecrets bool) []string {
	var paths []string
	for j := range control.ResourceAssociatedRules {
		for k := range control.ResourceAssociatedRules[j].Paths {
			p := control.ResourceAssociatedRules[j].Paths[k].FixPath.Path
			if p == "" {
				continue
			}
			v := control.ResourceAssociatedRules[j].Paths[k].FixPath.Value
			if !showSecrets && isSensitivePath(kind, p) {
				v = redactedValue
			}
			paths = append(paths, fmt.Sprintf("%s=%s", p, v))
		}
	}
	return paths
}

// AssistedRemediationPathsWithCurrentValuesFiltered is like AssistedRemediationPathsWithCurrentValues
// but redacts sensitive field values (Secret.data, Secret.stringData) unless showSecrets is true.
// enrichedPathsForFieldUnredacted is like enrichedPathsForField but never suppresses values
// for sensitive paths — used when --show-secrets is set and the operator explicitly wants
// Secret.data / Secret.stringData values surfaced.
func enrichedPathsForFieldUnredacted(control *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata, getPath func(armotypes.PosturePaths) string) []string {
	var paths []string
	obj := resource.GetObject()
	for j := range control.ResourceAssociatedRules {
		for k := range control.ResourceAssociatedRules[j].Paths {
			p := getPath(control.ResourceAssociatedRules[j].Paths[k])
			if p == "" {
				continue
			}
			if val, ok := extractValueAtPath(obj, p); ok {
				paths = append(paths, p+" (current: "+val+")")
				continue
			}
			paths = append(paths, p)
		}
	}
	return paths
}

func failedPathsWithCurrentValuesUnredacted(control *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata) []string {
	return enrichedPathsForFieldUnredacted(control, resource, func(p armotypes.PosturePaths) string { return p.FailedPath })
}

func reviewPathsWithCurrentValuesUnredacted(control *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata) []string {
	return enrichedPathsForFieldUnredacted(control, resource, func(p armotypes.PosturePaths) string { return p.ReviewPath })
}

func AssistedRemediationPathsWithCurrentValuesFiltered(control *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata, showSecrets bool) []string {
	kind := resource.GetKind()
	if showSecrets {
		// extract values for all paths including sensitive ones — caller explicitly opted in
		fixPaths := fixPathsToStringFiltered(control, kind, true)
		deletePaths := deletePathsToString(control)
		enrichedReview := reviewPathsWithCurrentValuesUnredacted(control, resource)
		enrichedFailed := failedPathsWithCurrentValuesUnredacted(control, resource)
		paths := append(fixPaths, append(deletePaths, enrichedReview...)...)
		return appendFailedPathsIfNotInPaths(paths, enrichedFailed)
	}
	fixPaths := fixPathsToStringFiltered(control, kind, false)
	deletePaths := deletePathsToString(control)
	enrichedReview := reviewPathsWithCurrentValuesRedacted(control, resource)
	enrichedFailed := failedPathsWithCurrentValuesRedacted(control, resource)
	paths := append(fixPaths, append(deletePaths, enrichedReview...)...)
	return appendFailedPathsIfNotInPaths(paths, enrichedFailed)
}

func enrichedPathsForFieldRedacted(control *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata, getPath func(armotypes.PosturePaths) string) []string {
	var paths []string
	obj := resource.GetObject()
	kind := resource.GetKind()
	for j := range control.ResourceAssociatedRules {
		for k := range control.ResourceAssociatedRules[j].Paths {
			p := getPath(control.ResourceAssociatedRules[j].Paths[k])
			if p == "" {
				continue
			}
			if isSensitivePath(kind, p) {
				paths = append(paths, p+" (current: "+redactedValue+")")
				continue
			}
			if val, ok := extractValueAtPath(obj, p); ok {
				paths = append(paths, p+" (current: "+val+")")
				continue
			}
			paths = append(paths, p)
		}
	}
	return paths
}

func failedPathsWithCurrentValuesRedacted(control *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata) []string {
	return enrichedPathsForFieldRedacted(control, resource, func(p armotypes.PosturePaths) string { return p.FailedPath })
}

func reviewPathsWithCurrentValuesRedacted(control *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata) []string {
	return enrichedPathsForFieldRedacted(control, resource, func(p armotypes.PosturePaths) string { return p.ReviewPath })
}

func AssistedRemediationPathsWithCurrentValues(control *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata) []string {
	fixPaths := fixPathsToString(control, false)
	deletePaths := deletePathsToString(control)
	enrichedReview := reviewPathsWithCurrentValues(control, resource)
	enrichedFailed := failedPathsWithCurrentValues(control, resource)

	paths := append(fixPaths, append(deletePaths, enrichedReview...)...)
	return appendFailedPathsIfNotInPaths(paths, enrichedFailed)
}
