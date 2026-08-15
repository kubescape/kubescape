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

// anyToString converts a scalar value to its string representation.
// It handles all numeric types that may appear in JSON-decoded or
// programmatically-constructed Kubernetes objects.
// Maps and slices return ("", false).
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

// secretFieldPatterns lists normalized field-name substrings that mark a
// path's value as secret-shaped regardless of resource kind. This mirrors
// anonymizer.isSensitiveEnvName's pattern list in core/pkg/anonymizer -
// intentionally not imported from there, since anonymizer imports
// resultshandling, which imports this package, and importing anonymizer
// here would create an import cycle.
var secretFieldPatterns = []string{
	"password", "passwd", "pwd",
	"secret",
	"token",
	"apikey",
	"accesskey",
	"privatekey",
	"credential",
	"databaseurl", "dburl",
	"redisurl",
	"mongouri", "mongodburi",
	"dsn",
	"connectionstring",
}

// hasSecretShapedFieldName reports whether path's final segment looks like
// a credential field name (e.g. "apiKey", "db_password", "clientSecret"),
// independent of resource kind. Separators are stripped before matching so
// API_KEY, api-key, and apiKey are all treated the same way. This only
// looks at the field name in the path itself - it does not correlate a
// generic field (e.g. a container env var's "value") with a sibling field
// that names it (e.g. that same env var's "name"), which is a separate,
// harder problem left out of scope here.
func hasSecretShapedFieldName(path string) bool {
	if i := strings.Index(path, "="); i >= 0 {
		path = path[:i]
	}
	segments := splitPath(path)
	if len(segments) == 0 {
		return false
	}
	name := strings.ToLower(segments[len(segments)-1].key)
	for _, sep := range []string{"_", "-", ".", " "} {
		name = strings.ReplaceAll(name, sep, "")
	}
	for _, pattern := range secretFieldPatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

// isSensitivePath reports whether a path targets a field whose value must
// not be surfaced in scan output. Secret data and stringData contain
// credentials that are base64-encoded (or plaintext) and must never be
// printed regardless of what the existing redaction in updateResults has
// done. Beyond that Secret-specific case, any path whose final field name
// looks like a credential is masked regardless of kind, since a hardcoded
// secret can live in a plain field on any resource - a ConfigMap entry
// named apiKey, a CRD's spec.auth.token, and so on.
func isSensitivePath(kind, path string) bool {
	trimmed := path
	if i := strings.Index(trimmed, "="); i >= 0 {
		trimmed = trimmed[:i]
	}
	trimmed = strings.TrimLeft(trimmed, ".")
	if kind == "Secret" && (trimmed == "data" || strings.HasPrefix(trimmed, "data.") ||
		trimmed == "stringData" || strings.HasPrefix(trimmed, "stringData.")) {
		return true
	}
	return hasSecretShapedFieldName(path)
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
