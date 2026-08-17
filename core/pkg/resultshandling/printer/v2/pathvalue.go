package printer

import (
	"encoding/json"
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
// not be surfaced in scan output. Secret data and stringData contain
// credentials that are base64-encoded (or plaintext) and must never be
// printed regardless of what the existing redaction in updateResults has done.
func isSensitivePath(kind, path string) bool {
	if kind != "Secret" {
		return false
	}
	if i := strings.Index(path, "="); i >= 0 {
		path = path[:i]
	}
	path = strings.TrimLeft(path, ".")
	return path == "data" || strings.HasPrefix(path, "data.") ||
		path == "stringData" || strings.HasPrefix(path, "stringData.")
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

func AssistedRemediationPathsWithCurrentValues(control *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata) []string {
	fixPaths := fixPathsToString(control, false)
	deletePaths := deletePathsToString(control)
	enrichedReview := reviewPathsWithCurrentValues(control, resource)
	enrichedFailed := failedPathsWithCurrentValues(control, resource)

	paths := append(fixPaths, append(deletePaths, enrichedReview...)...)
	return appendFailedPathsIfNotInPaths(paths, enrichedFailed)
}
