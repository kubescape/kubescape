package printer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/pathparse"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

// pathSegment aliases the shared parser's segment so this package's existing
// spelling keeps working. The grammar lives in pathparse because the location
// resolver needs it too, and it cannot import this package: printer/v2 already
// imports locationresolver, so the dependency only runs one way.
type pathSegment = pathparse.Segment

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
//
// Numbers are decoded as json.Number rather than float64. A float64 cannot
// hold every integer above 2^53, so the default decoding would report
// metadata.generation 9007199254740993 as 9007199254740992; json.Number keeps
// the literal digits, and anyToString renders them unchanged.
func normalizeForPathExtraction(obj map[string]any) map[string]any {
	b, err := json.Marshal(obj)
	if err != nil {
		return obj
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var normalized map[string]any
	if err := dec.Decode(&normalized); err != nil {
		return obj
	}
	return normalized
}

// extractValueAtPath is extractValue for an object that carries its own kind,
// as every scanned Kubernetes object does.
func extractValueAtPath(obj map[string]any, path string) (string, bool) {
	kind, _ := obj["kind"].(string)
	return extractValue(kind, obj, path)
}

// extractValue resolves path against obj and returns the value as text. A value
// the scan scrubbed reads as redactedValue (see maskScrubbed); nothing else is
// changed, so this is the variant for output where --show-secrets is set.
func extractValue(kind string, obj map[string]any, path string) (string, bool) {
	if len(obj) == 0 || path == "" {
		return "", false
	}
	// A malformed path resolves nothing. The nearest well-formed reading of it
	// is a real field, and returning that field's value would present it as
	// the value the rule pointed at.
	segments, err := pathparse.ParsePath(path)
	if err != nil || len(segments) == 0 {
		return "", false
	}
	cur, ok := resolveSegments(obj, segments)
	if !ok {
		return "", false
	}
	masked, _ := maskScrubbed(kind, segments, cur)
	return anyToString(masked)
}

// pathResolves reports whether path selects something in obj, without reading
// the value. It is for callers that only need to know the field exists.
func pathResolves(obj map[string]any, path string) bool {
	if len(obj) == 0 || path == "" {
		return false
	}
	segments, err := pathparse.ParsePath(path)
	if err != nil || len(segments) == 0 {
		return false
	}
	_, ok := resolveSegments(obj, segments)
	return ok
}

// extractRedactedValueAtPath is extractValueAtPath for output that must not
// carry credentials: the path itself is checked with isSensitivePath, and when
// it selects an object or list, every credential-shaped descendant is replaced
// with redactedValue before the value is serialized. Checking only the path a
// rule named is not enough when that path is an ancestor - spec.volumes[0]
// is not sensitive, but a field below it can be.
func extractRedactedValueAtPath(kind string, obj map[string]any, path string) (string, bool) {
	if len(obj) == 0 || path == "" {
		return "", false
	}
	segments, err := pathparse.ParsePath(path)
	if err != nil || len(segments) == 0 {
		return "", false
	}
	if isSensitiveSegments(kind, segments) {
		return "", false
	}
	cur, ok := resolveSegments(obj, segments)
	if !ok {
		return "", false
	}
	// A path naming one element of args or command reads a single string, but
	// whether that string is a credential can depend on the element before it
	// ("--token" followed by its value), so it is redacted in the context of its
	// list.
	if last := segments[len(segments)-1]; last.Index >= 0 && isCommandLineSegment(last) {
		parent := slices.Clone(segments)
		parent[len(parent)-1].Index = -1
		if list, found := resolveSegments(obj, parent); found {
			if args, isList := list.([]any); isList && last.Index < len(args) {
				cur = redactCommandLine(args)[last.Index]
			}
		}
	}
	return anyToString(redactSensitiveDescendants(kind, segments, cur))
}

// scrubbedPlaceholder is the text the scan writes over the contents of Secret
// and ConfigMap data and over container environment variable values before any
// output is built. The original is gone by then, so a path that resolves to it
// has no value to show, and printing the placeholder would present it as the
// field's real value. The literal is repeated here, and not imported, so the
// printer does not depend on the scan code that writes it.
const scrubbedPlaceholder = "XXXXXX"

// isScrubbedLocation reports whether the scan writes scrubbedPlaceholder at the
// field that segments select within an object of the given kind. The text alone
// is not enough to call a value scrubbed: an annotation, a label or an image
// can hold it too, and that is a genuine value that must be shown. The places
// are the ones the scan scrubs:
//   - every entry of a Secret's data and stringData;
//   - every entry of a ConfigMap's data and binaryData;
//   - the value of a container, init container or ephemeral container
//     environment variable, in a pod or in the pod template of a workload.
func isScrubbedLocation(kind string, segments []pathSegment) bool {
	switch kind {
	case "Secret":
		return len(segments) >= 2 && (segments[0].Key == "data" || segments[0].Key == "stringData")
	case "ConfigMap":
		return len(segments) >= 2 && (segments[0].Key == "data" || segments[0].Key == "binaryData")
	}
	if !isContainerEnvValue(segments) || len(segments) < 3 {
		return false
	}
	switch segments[len(segments)-3].Key {
	case "containers", "initContainers", "ephemeralContainers":
		return true
	}
	return false
}

// maskScrubbed returns v with each scrubbedPlaceholder that the scan wrote
// replaced by redactedValue, so evidence reads "[redacted]" where a value was
// removed, and reports whether it changed anything. segments is where v sits in
// the object of the given kind. It applies with --show-secrets too: that flag
// cannot bring back a value the scan has already removed.
//
// The object belongs to the scan, so it is never modified. A subtree with
// nothing to mask is returned as it is, not copied, so a path that selects a
// large subtree costs a read of it and no allocation unless something changes.
func maskScrubbed(kind string, segments []pathSegment, v any) (any, bool) {
	switch val := v.(type) {
	case string:
		if val == scrubbedPlaceholder && isScrubbedLocation(kind, segments) {
			return redactedValue, true
		}
		return v, false
	case map[string]any:
		var out map[string]any
		for key, child := range val {
			childPath := append(slices.Clone(segments), pathSegment{Key: key, Index: -1})
			masked, changed := maskScrubbed(kind, childPath, child)
			if !changed {
				continue
			}
			if out == nil {
				out = maps.Clone(val)
			}
			out[key] = masked
		}
		if out == nil {
			return v, false
		}
		return out, true
	case []any:
		var out []any
		for i, child := range val {
			childPath := slices.Clone(segments)
			if last := len(childPath) - 1; last >= 0 && childPath[last].Index < 0 {
				childPath[last].Index = i
			} else {
				childPath = append(childPath, pathSegment{Index: i})
			}
			masked, changed := maskScrubbed(kind, childPath, child)
			if !changed {
				continue
			}
			if out == nil {
				out = slices.Clone(val)
			}
			out[i] = masked
		}
		if out == nil {
			return v, false
		}
		return out, true
	default:
		return v, false
	}
}

// isCommandLineSegment reports whether a path segment names a container's args
// or command: the fields that hold a command line, where a credential is
// written into the value ("--<name>=<value>") rather than under a field named
// for it.
func isCommandLineSegment(seg pathSegment) bool {
	return seg.Key == "args" || seg.Key == "command"
}

// credentialFlagName reports whether a command-line flag or KEY=VALUE key
// names a credential. It reads the name the way isSensitiveSegments reads a
// field name: separators and leading dashes are dropped, so --db-url, -token
// and API_KEY all classify like dbUrl, token and apiKey.
func credentialFlagName(flag string) bool {
	name := normalizeFieldName(strings.TrimLeft(flag, "-"))
	if name == "" {
		return false
	}
	for _, pattern := range secretFieldPatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

// redactCommandLine returns a copy of an args or command list with credential
// values replaced by redactedValue. Field-name redaction cannot see these: the
// list elements have no names, and the credential is inside the string.
//
// Four spellings are covered:
//   - "--<credential>=<value>" (or KEY=VALUE): the part after the first "="
//     is replaced when the part before it names a credential.
//   - "--<flag>=<name>=<value>", as in "--env=KEY=VALUE" or helm's
//     "--set=a=1,b=2": when the outer flag is not a credential, each
//     assignment in its value is checked the same way, so the credential
//     inside is replaced and the rest of the argument is kept.
//   - "--<credential> <value>" written as one element: the value is replaced.
//   - "--<credential>", "<value>" as two elements: the element after a
//     credential flag with no value of its own is replaced.
//
// A password in a URL ("scheme://user:<password>@host") is replaced wherever it
// appears.
//
// The element after a bare credential flag is masked even when it starts with
// "-", because a value can ("--password", "-secret") and the two readings cannot
// be told apart. That element is then still read as a flag in its own right, so
// the one after it is masked too. The cost is that a credential-named flag
// that takes no value hides the flag that follows it.
//
// It does not parse shell, so a credential inside a larger string such as a
// "sh -c" script is not recognised, and it only knows a credential by its name,
// so an opaque value under a flag that is not named like one is not hidden.
func redactCommandLine(args []any) []any {
	out := make([]any, len(args))
	copy(out, args)
	// masked marks an element already replaced whole as the value of the flag
	// before it. It must not be rewritten from its own text afterwards:
	// "--token", "a=b" would otherwise have its mask overwritten with "a=b".
	masked := make([]bool, len(args))
	for i, arg := range args {
		s, ok := arg.(string)
		if !ok {
			continue
		}
		if !masked[i] {
			out[i] = redactArgument(s)
		}
		if i+1 < len(args) && isBareCredentialFlag(s) {
			if _, isString := args[i+1].(string); isString {
				out[i+1] = redactedValue
				masked[i+1] = true
			}
		}
	}
	return out
}

// isBareCredentialFlag reports whether s is a credential-named flag that has no
// value of its own, so the next element is its value.
func isBareCredentialFlag(s string) bool {
	return strings.HasPrefix(s, "-") &&
		!strings.ContainsAny(s, "= \t") &&
		credentialFlagName(s)
}

// urlPassword matches a URL's "user:password@" up to the last "@" of its
// authority. The password may itself contain "@" ("jane:p@ssword@host"), so it
// is matched greedily and the match ends at the last "@" before the authority
// ends. The authority ends at "/", "?" or "#", which the password therefore
// cannot cross: an "@" in a path or query is not part of the user information.
var urlPassword = regexp.MustCompile(`(://[^/?#\s:@]*:)[^/?#\s]+@`)

// redactArgument masks a credential inside a single argument.
func redactArgument(s string) string {
	s = urlPassword.ReplaceAllString(s, "${1}"+redactedValue+"@")

	// "--flag value" written as one element. The space comes before any "=", so
	// the first "=" belongs to the value, not to the flag.
	if strings.HasPrefix(s, "-") {
		sp := strings.IndexAny(s, " \t")
		eq := strings.Index(s, "=")
		if sp > 0 && (eq < 0 || sp < eq) {
			flag, value := s[:sp], strings.TrimLeft(s[sp:], " \t")
			if credentialFlagName(flag) {
				return flag + " " + redactedValue
			}
			return flag + " " + redactAssignment(value)
		}
	}
	if strings.Index(s, "=") > 0 {
		return redactAssignment(s)
	}
	return s
}

// redactAssignment masks the credential in a "name=value" string. When the
// name is a credential the whole value goes. Otherwise the value may itself
// hold assignments ("--env=KEY=VALUE", "--set=a=1,b=2"), so each comma-separated
// part is checked in turn and only a credential-named one is replaced.
// Every recursive call is on a strictly shorter string, so it terminates.
func redactAssignment(s string) string {
	eq := strings.Index(s, "=")
	if eq <= 0 {
		return s
	}
	name, value := s[:eq], s[eq+1:]
	if credentialFlagName(name) {
		return name + "=" + redactedValue
	}
	if !strings.Contains(value, "=") {
		return s
	}
	parts := strings.Split(value, ",")
	for i, part := range parts {
		parts[i] = redactAssignment(part)
	}
	return name + "=" + strings.Join(parts, ",")
}

// redactSensitiveDescendants returns a copy of v, the value found at segments,
// with each descendant that isSensitiveSegments flags replaced by
// redactedValue. Descendant paths are built as segments, in the same shape
// pathparse produces, so the classifier sees exactly the path a rule would
// have to name to reach that field directly: a list element sets the index of
// the segment that holds the list ("volumes" becomes "volumes[0]"), and a map
// entry appends a new segment. Values that are neither maps nor lists are
// returned as they are.
func redactSensitiveDescendants(kind string, segments []pathSegment, v any) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for key, child := range val {
			childPath := append(slices.Clone(segments), pathSegment{Key: key, Index: -1})
			if isSensitiveSegments(kind, childPath) {
				out[key] = redactedValue
				continue
			}
			out[key] = redactSensitiveDescendants(kind, childPath, child)
		}
		return out
	case []any:
		if last := len(segments) - 1; last >= 0 && segments[last].Index < 0 && isCommandLineSegment(segments[last]) {
			val = redactCommandLine(val)
		}
		out := make([]any, len(val))
		for i, child := range val {
			childPath := slices.Clone(segments)
			if last := len(childPath) - 1; last >= 0 && childPath[last].Index < 0 {
				childPath[last].Index = i
			} else {
				// A list inside a list has no spelling in the path grammar;
				// its elements are classified by the keys below them.
				childPath = append(childPath, pathSegment{Index: i})
			}
			if isSensitiveSegments(kind, childPath) {
				out[i] = redactedValue
				continue
			}
			out[i] = redactSensitiveDescendants(kind, childPath, child)
		}
		return out
	case string:
		// The scrub is applied in this traversal and not in a second one, so a
		// path that selects a large subtree is read and copied once.
		if val == scrubbedPlaceholder && isScrubbedLocation(kind, segments) {
			return redactedValue
		}
		return v
	default:
		return v
	}
}

// resolveSegments walks obj along segments and returns the value found there.
func resolveSegments(obj map[string]any, segments []pathSegment) (any, bool) {
	var cur any = obj
	for _, seg := range segments {
		switch v := cur.(type) {
		case map[string]any:
			next, ok := v[seg.Key]
			if !ok {
				return nil, false
			}
			if seg.Index >= 0 {
				elem, ok := indexList(next, seg.Index)
				if !ok {
					return nil, false
				}
				cur = elem
			} else {
				cur = next
			}
		default:
			// A named segment is a map lookup, and this is not a map. Every
			// segment the parser produces carries a key, so reaching here means
			// the path asks for a field of a list - "env['ignored'][1]" - which
			// no resource has.
			//
			// It fails rather than indexing past the name. Indexing anyway
			// would resolve the path by quietly discarding a segment, and
			// isSensitivePath reads that same segment: it would see "ignored"
			// where traversal saw the env list, judge the path harmless, and
			// print a credential the two functions disagreed about. Traversal
			// and classification have to give the same answer about what a path
			// means, and the safe direction for a malformed path is to resolve
			// nothing.
			if seg.Key != "" {
				return nil, false
			}
			elem, ok := indexList(v, seg.Index)
			if !ok {
				return nil, false
			}
			cur = elem
		}
	}
	return cur, true
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

// podSpecPrefixes maps each built-in kind whose schema carries a PodSpec to
// the exact parent segments that precede a PodSpec field on that kind. The
// prefix is spelled out per kind rather than matched as a trailing "spec",
// because this is a redaction boundary: the scanner reads manifests directly,
// without API schema admission, so a document is free to nest an arbitrary
// spec. anywhere and a suffix match would read that as the PodSpec.
var podSpecPrefixes = map[string][]parentSegment{
	"Pod":                   mapPath("spec"),
	"Deployment":            mapPath("spec", "template", "spec"),
	"StatefulSet":           mapPath("spec", "template", "spec"),
	"DaemonSet":             mapPath("spec", "template", "spec"),
	"ReplicaSet":            mapPath("spec", "template", "spec"),
	"ReplicationController": mapPath("spec", "template", "spec"),
	"Job":                   mapPath("spec", "template", "spec"),
	"CronJob":               mapPath("spec", "jobTemplate", "spec", "template", "spec"),
}

// parentSegment is one segment of a safe field's canonical parent path, with
// whether the Kubernetes schema defines that segment as a list.
//
// The shape has to be part of the match, not just the key. pathparse.ParsePath records
// an index only for a bracketed segment, and extractValueAtPath walks an
// unindexed segment straight through a map - so spec.volumes.secret.secretName
// resolves against a manifest that happens to carry an object named "volumes",
// even though PodSpec.volumes is a list and that path is not
// SecretVolumeSource.secretName at all. Matching on keys alone would hand that
// object-shaped path the list-shaped path's exception and let its value out
// through failedPathValues.
type parentSegment struct {
	key string
	// list requires this segment to be indexed ("volumes[0]"). A schema list
	// reached without an index, or a schema map reached with one, is not the
	// documented location and is redacted.
	list bool
}

// mapPath builds a parent path whose segments are all plain maps.
func mapPath(keys ...string) []parentSegment {
	segments := make([]parentSegment, len(keys))
	for i, key := range keys {
		segments[i] = parentSegment{key: key}
	}
	return segments
}

// safeFieldRule scopes a safe-field exception to one documented Kubernetes
// location. A rule matches a field's parent path in full, never as a suffix,
// so the exception covers exactly the canonical location and nothing that
// merely ends the same way.
//
// onPodSpec anchors a rule to every kind in podSpecPrefixes: the canonical
// parent path is that kind's prefix followed by podSpecParents, which is empty
// for a field sitting directly on the PodSpec. Otherwise the rule applies to
// kinds at exactly parents, where an empty parents means the object root.
type safeFieldRule struct {
	onPodSpec      bool
	podSpecParents []parentSegment

	kinds   []string
	parents []parentSegment
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
// through to the pattern match below and is redacted. Each location is the
// field's full canonical parent path, so an off-schema path on a built-in kind
// (Pod spec.extension.spec.automountServiceAccountToken, say) fails closed.
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
		{onPodSpec: true},
		{kinds: []string{"ServiceAccount"}},
	},
	// A projected volume source's configuration block
	// (ServiceAccountTokenProjection). It describes a token the kubelet will
	// mint at mount time; the block itself carries no credential.
	"serviceaccounttoken": {
		{onPodSpec: true, podSpecParents: []parentSegment{
			{key: "volumes", list: true}, {key: "projected"}, {key: "sources", list: true},
		}},
	},
	// That block's requested lifetime, a number of seconds.
	"tokenexpirationseconds": {
		{onPodSpec: true, podSpecParents: []parentSegment{
			{key: "volumes", list: true}, {key: "projected"}, {key: "sources", list: true}, {key: "serviceAccountToken"},
		}},
	},
	// A reference to a Secret by name (SecretVolumeSource, and Ingress TLS).
	// The referenced object holds the sensitive value, and that object is
	// redacted separately by kind ("Secret").
	"secretname": {
		{onPodSpec: true, podSpecParents: []parentSegment{
			{key: "volumes", list: true}, {key: "secret"},
		}},
		{kinds: []string{"Ingress"}, parents: []parentSegment{
			{key: "spec"}, {key: "tls", list: true},
		}},
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

// equalParentPath reports whether parents is exactly want, segment for
// segment, in both key and shape. Comparing the whole path rather than its
// tail is what keeps an exception pinned to the schema location it was written
// for; comparing the shape is what stops an object-shaped path from borrowing
// a list-shaped path's exception.
//
// A segment pathparse.ParsePath could not read an index from - "volumes[container_ndx]",
// an unsubstituted rule placeholder - carries index -1 and so reads as
// unindexed, failing a list segment's match. That is the safe direction: an
// unresolvable path is redacted rather than excused.
func equalParentPath(parents []pathSegment, want []parentSegment) bool {
	if len(parents) != len(want) {
		return false
	}
	for i := range want {
		if !strings.EqualFold(parents[i].Key, want[i].key) {
			return false
		}
		if want[i].list != (parents[i].Index >= 0) {
			return false
		}
	}
	return true
}

// matchesSafeField reports whether kind, and the parents of a field named
// name, place that field at one of the documented locations in
// safeFieldRules. A kind absent from podSpecPrefixes never matches an
// onPodSpec rule, and a built-in kind matches only on its own canonical path,
// so anything off-schema falls through and is redacted.
func matchesSafeField(kind, name string, parents []pathSegment) bool {
	for _, rule := range safeFieldRules[name] {
		if rule.onPodSpec {
			prefix, ok := podSpecPrefixes[kind]
			if !ok {
				continue
			}
			canonical := make([]parentSegment, 0, len(prefix)+len(rule.podSpecParents))
			canonical = append(canonical, prefix...)
			canonical = append(canonical, rule.podSpecParents...)
			if equalParentPath(parents, canonical) {
				return true
			}
			continue
		}
		if !slices.Contains(rule.kinds, kind) {
			continue
		}
		if equalParentPath(parents, rule.parents) {
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
func hasSecretShapedFieldName(kind string, segments []pathSegment) bool {
	if len(segments) == 0 {
		return false
	}
	name := normalizeFieldName(segments[len(segments)-1].Key)
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
	// Sensitivity is decided on the parsed path, the same grammar
	// extractValueAtPath resolves with. Classifying from the raw string instead
	// lets the two disagree about what a path means, and a field the classifier
	// does not recognise but extraction does resolve is a value printed in the
	// clear.
	segments, err := pathparse.ParsePath(path)
	if err != nil {
		// A path that cannot be read cannot be cleared. Extraction refuses it
		// too, so no resource value is at stake here, but a fix path's value
		// comes from the rule rather than the resource and is printed without
		// extraction - so it is hidden rather than shown on a guess.
		return true
	}
	return isSensitiveSegments(kind, segments)
}

// isSensitiveSegments is isSensitivePath on an already parsed path.
func isSensitiveSegments(kind string, segments []pathSegment) bool {
	// Everything under a Secret's data or stringData is sensitive, whatever the
	// individual key happens to be called. Deciding that on the first segment
	// covers a bracketed key: "data[username]" holds Secret content exactly as
	// "data.password" does, but it does not start with "data." and its own name
	// is not credential-shaped, so a prefix test let it through.
	if kind == "Secret" && len(segments) > 0 &&
		(segments[0].Key == "data" || segments[0].Key == "stringData") {
		return true
	}
	// C-0012 plaintext credentials live on container env .value, not Secret.data.
	if isContainerEnvValue(segments) {
		return true
	}
	return hasSecretShapedFieldName(kind, segments)
}

// isContainerEnvValue reports whether segments select the value of a container
// environment variable - the C-0012 plaintext credential, which lives on the
// workload rather than on a Secret. Matching the last two segments covers every
// container list and pod-template nesting without enumerating them.
//
// This reads segments rather than the path string. The same field has several
// spellings - env[0].value, ['env'][0].value, ["env"][0].value - and a string
// search for "env[" recognises only the first, while extraction resolves all
// three. Classifying from the grammar extraction already uses is what stops the
// two from disagreeing, because a path the classifier misses and extraction
// resolves is a credential printed without --show-secrets.
func isContainerEnvValue(segments []pathSegment) bool {
	if len(segments) < 2 {
		return false
	}
	value := segments[len(segments)-1]
	env := segments[len(segments)-2]
	return value.Key == "value" && env.Key == "env" && env.Index >= 0
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
				if val, ok := extractValue(kind, obj, p); ok {
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
	kind := resource.GetKind()
	for j := range control.ResourceAssociatedRules {
		for k := range control.ResourceAssociatedRules[j].Paths {
			p := getPath(control.ResourceAssociatedRules[j].Paths[k])
			if p == "" {
				continue
			}
			if val, ok := extractValue(kind, obj, p); ok {
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
	return assistedRemediationPaths(control, resource, showSecrets, false)
}

// evidencePathsWithCurrentValues is AssistedRemediationPathsWithCurrentValuesFiltered
// for the terminal --show-evidence view, which additionally reports the
// current value of each delete path. A delete path names the field that made
// the control fail, so leaving it bare printed the path an auditor needs to
// check without the value they need to check it against.
//
// It is separate from the exported function on purpose: that one also feeds
// the HTML, SARIF, GitLab SAST and GitHub Actions printers, and changing it
// would change four report formats to improve one table.
func evidencePathsWithCurrentValues(control *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata, showSecrets bool) []string {
	return assistedRemediationPaths(control, resource, showSecrets, true)
}

// assistedRemediationPaths renders a control's fix, delete and review paths as
// one deduplicated list. deleteValues appends the current value to each delete
// path; review paths always carry theirs.
func assistedRemediationPaths(control *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata, showSecrets, deleteValues bool) []string {
	kind := resource.GetKind()
	// showSecrets extracts values for all paths including sensitive ones - the
	// caller explicitly opted in.
	fixPaths := fixPathsToStringFiltered(control, kind, showSecrets)
	deletePaths := deletePathsToString(control)
	if deleteValues {
		deletePaths = deletePathsWithCurrentValues(control, resource, showSecrets)
	}
	var enrichedReview []string
	if showSecrets {
		enrichedReview = reviewPathsWithCurrentValuesUnredacted(control, resource)
	} else {
		enrichedReview = reviewPathsWithCurrentValuesRedacted(control, resource)
	}
	paths := append(fixPaths, append(deletePaths, enrichedReview...)...)
	return deduplicatePaths(paths)
}

// deletePathsWithCurrentValues is deletePathsToString with " (current: <value>)"
// appended to each delete path that resolves against the resource's object.
//
// Redaction follows the rest of the evidence output. A path that is sensitive
// by name shows redactedValue, but only when it resolves: an absent field has
// no value to hide, and "[redacted]" on it would claim one. Any other path is
// read with extractRedactedValueAtPath, so a delete path that selects an
// object or list (a whole securityContext, say) has its credential-shaped
// descendants masked rather than printed. A path that does not resolve stays
// bare, as it did before.
func deletePathsWithCurrentValues(control *resourcesresults.ResourceAssociatedControl, resource workloadinterface.IMetadata, showSecrets bool) []string {
	var paths []string
	obj := normalizeForPathExtraction(resource.GetObject())
	kind := resource.GetKind()
	for j := range control.ResourceAssociatedRules {
		for k := range control.ResourceAssociatedRules[j].Paths {
			p := control.ResourceAssociatedRules[j].Paths[k].DeletePath
			if p == "" {
				continue
			}
			paths = append(paths, p+currentValueSuffix(kind, obj, p, showSecrets))
		}
	}
	return paths
}

// currentValueSuffix returns " (current: <value>)" for path, or "" when the
// path does not resolve.
func currentValueSuffix(kind string, obj map[string]any, path string, showSecrets bool) string {
	if showSecrets {
		if val, ok := extractValue(kind, obj, path); ok {
			return " (current: " + val + ")"
		}
		return ""
	}
	if isSensitivePath(kind, path) {
		if pathResolves(obj, path) {
			return " (current: " + redactedValue + ")"
		}
		return ""
	}
	if val, ok := extractRedactedValueAtPath(kind, obj, path); ok {
		return " (current: " + val + ")"
	}
	return ""
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
			paths = append(paths, p+currentValueSuffix(kind, obj, p, false))
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
