package printer

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
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

// normalizeForPathExtraction converts obj into a tree built entirely from
// encoding/json's generic decoding types (map[string]any, []any, float64,
// string, bool, nil). Earlier processing stages (for example
// opaprocessor.removePodData, which reads containers via
// workload.GetContainers() and writes the resulting []corev1.Container back
// into the object map) can leave typed structs in place of the plain
// map/slice shape the manifest originally had. extractValueAtPath only knows
// how to walk map[string]any and []any, so those typed sections would
// otherwise be invisible to it - which is most posture findings, since they
// target container-scoped fields. Round-tripping through JSON once per
// resource makes the whole tree walkable regardless of how it got there.
func normalizeForPathExtraction(obj map[string]any) map[string]any {
	b, err := json.Marshal(obj)
	if err != nil {
		return obj
	}
	var normalized map[string]any
	if err := json.Unmarshal(b, &normalized); err != nil {
		return obj
	}
	return normalized
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
				elem, ok := indexList(next, seg.index)
				if !ok {
					return "", false
				}
				cur = elem
			} else {
				cur = next
			}
		default:
			elem, ok := indexList(v, seg.index)
			if !ok {
				return "", false
			}
			cur = elem
		}
	}
	return anyToString(cur)
}

// indexList returns the element at index i of a slice. JSON-decoded objects
// use []any; conversions often produce []map[string]any instead, and the
// previous []any-only assert dropped those lookups. Other slice types are
// indexed through reflection. Out-of-range indexes fail closed.
func indexList(v any, i int) (any, bool) {
	if i < 0 {
		return nil, false
	}
	switch arr := v.(type) {
	case []any:
		if i >= len(arr) {
			return nil, false
		}
		return arr[i], true
	case []map[string]any:
		if i >= len(arr) {
			return nil, false
		}
		return arr[i], true
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice || i >= rv.Len() {
		return nil, false
	}
	return rv.Index(i).Interface(), true
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

// podSpecKinds are the built-in kinds whose schema carries a PodSpec, either
// directly (Pod) or through a pod template. Depending on the kind a PodSpec
// field sits at spec., spec.template.spec., or
// spec.jobTemplate.spec.template.spec., so the rules below match a field's
// immediate parents rather than a fully anchored path.
var podSpecKinds = []string{
	"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet",
	"ReplicationController", "Job", "CronJob",
}

// safeFieldRule scopes a safe-field exception to one documented Kubernetes
// location: the kinds whose schema defines the field, and the parent segments
// it sits directly under. parents is matched as a suffix, so a PodSpec field
// is recognized through any pod-template nesting; an empty parents means the
// field sits at the object root.
type safeFieldRule struct {
	kinds   []string
	parents []string
}

// safeFieldRules lists Kubernetes API fields whose names match a
// secretFieldPatterns substring but which do not themselves hold a
// credential. Each is keyed by its normalized name and scoped to where that
// field genuinely exists, because the exception is a statement about a
// specific API field and not about a field name: a CRD is free to define
// spec.serviceAccountToken as an actual credential, and excusing it on the
// strength of its name alone would reopen the very kind-blind hole this file
// exists to close. Anything outside these locations - a custom resource, or a
// core kind carrying the name somewhere its schema does not define it - falls
// through to the pattern match below and is redacted.
//
// A word-boundary-aware match (splitting at camelCase/snake_case/kebab-case
// boundaries and requiring whole-word membership) was considered instead of
// scoping, but it cannot separate these at all: "Token" and "Secret" are
// complete, genuine words in each of them, not substring artifacts spanning
// two unrelated words. The distinction is semantic - a field naming or
// describing a credential versus a field holding one - so it is drawn by
// location, which is where that meaning actually lives.
var safeFieldRules = map[string][]safeFieldRule{
	// A boolean toggle on PodSpec, and on ServiceAccount as the default for
	// pods using it - not token content either way.
	"automountserviceaccounttoken": {
		{kinds: podSpecKinds, parents: []string{"spec"}},
		{kinds: []string{"ServiceAccount"}},
	},
	// A projected volume source's configuration block
	// (ServiceAccountTokenProjection). It describes a token the kubelet will
	// mint at mount time; the block itself carries no credential.
	"serviceaccounttoken": {
		{kinds: podSpecKinds, parents: []string{"projected", "sources"}},
	},
	// That block's requested lifetime, a number of seconds.
	"tokenexpirationseconds": {
		{kinds: podSpecKinds, parents: []string{"sources", "serviceAccountToken"}},
	},
	// A reference to a Secret by name (SecretVolumeSource, and Ingress TLS).
	// The referenced object holds the sensitive value, and that object is
	// redacted separately by kind ("Secret").
	"secretname": {
		{kinds: podSpecKinds, parents: []string{"volumes", "secret"}},
		{kinds: []string{"Ingress"}, parents: []string{"tls"}},
	},
}

// normalizeFieldName lowercases a path segment's key and strips separators, so
// API_KEY, api-key, and apiKey all normalize to the same form.
func normalizeFieldName(key string) string {
	name := strings.ToLower(key)
	for _, sep := range []string{"_", "-", ".", " "} {
		name = strings.ReplaceAll(name, sep, "")
	}
	return name
}

// matchesSafeField reports whether kind, and the parents of a field named
// name, place that field at one of the documented locations in
// safeFieldRules.
func matchesSafeField(kind, name string, parents []pathSegment) bool {
	for _, rule := range safeFieldRules[name] {
		if !slices.Contains(rule.kinds, kind) {
			continue
		}
		if len(rule.parents) == 0 {
			// The field is defined at the object root only.
			if len(parents) == 0 {
				return true
			}
			continue
		}
		if len(parents) < len(rule.parents) {
			continue
		}
		tail := parents[len(parents)-len(rule.parents):]
		matched := true
		for i, want := range rule.parents {
			if !strings.EqualFold(tail[i].key, want) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// hasSecretShapedFieldName reports whether path's final segment looks like a
// credential field name (e.g. "apiKey", "db_password", "clientSecret"). The
// match itself is kind-independent - a hardcoded secret can live in a plain
// field on any resource - but kind is still consulted, to place a field
// against safeFieldRules before concluding it is credential-shaped. This only
// looks at the field name in the path itself: it does not correlate a generic
// field (e.g. a container env var's "value") with a sibling field that names
// it (e.g. that same env var's "name"), which is a separate, harder problem
// left out of scope here.
func hasSecretShapedFieldName(kind, path string) bool {
	if i := strings.Index(path, "="); i >= 0 {
		path = path[:i]
	}
	segments := splitPath(path)
	if len(segments) == 0 {
		return false
	}
	name := normalizeFieldName(segments[len(segments)-1].key)
	if matchesSafeField(kind, name, segments[:len(segments)-1]) {
		return false
	}
	for _, pattern := range secretFieldPatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

// isSensitivePath reports whether a path targets a field whose value must
// not be surfaced in scan output unless --show-secrets is set. Three
// separate cases are covered:
//   - Secret data and stringData contain credentials that are base64-encoded
//     (or plaintext) and must never be printed regardless of what the
//     existing redaction in updateResults has done.
//   - Container env[N].value holds the C-0012 plaintext credentials, which
//     live on the workload rather than on a Secret.
//   - Beyond those kind- and shape-specific cases, any path whose final
//     field name looks like a credential is masked regardless of kind, since
//     a hardcoded secret can live in a plain field on any resource - a
//     ConfigMap entry named apiKey, a CRD's spec.auth.token, and so on.
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
	// C-0012 plaintext credentials live on container env .value, not Secret.data.
	if isContainerEnvValuePath(trimmed) {
		return true
	}
	return hasSecretShapedFieldName(kind, path)
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
	obj := normalizeForPathExtraction(resource.GetObject())
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
	obj := normalizeForPathExtraction(resource.GetObject())
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
		paths := append(fixPaths, append(deletePaths, enrichedReview...)...)
		return deduplicatePaths(paths)
	}
	fixPaths := fixPathsToStringFiltered(control, kind, false)
	deletePaths := deletePathsToString(control)
	enrichedReview := reviewPathsWithCurrentValuesRedacted(control, resource)
	paths := append(fixPaths, append(deletePaths, enrichedReview...)...)
	return deduplicatePaths(paths)
}

func enrichedPathsForFieldRedacted(control *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata, getPath func(armotypes.PosturePaths) string) []string {
	var paths []string
	obj := normalizeForPathExtraction(resource.GetObject())
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

func reviewPathsWithCurrentValuesRedacted(control *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata) []string {
	return enrichedPathsForFieldRedacted(control, resource, func(p armotypes.PosturePaths) string { return p.ReviewPath })
}

func AssistedRemediationPathsWithCurrentValues(control *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata) []string {
	fixPaths := fixPathsToString(control, false)
	deletePaths := deletePathsToString(control)
	enrichedReview := reviewPathsWithCurrentValues(control, resource)
	paths := append(fixPaths, append(deletePaths, enrichedReview...)...)
	return deduplicatePaths(paths)
}
