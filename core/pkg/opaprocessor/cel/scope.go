package cel

import (
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// appliesTo reports whether an object of the given kind falls within the
// policy's spec.matchConstraints. At live admission a non-matching object is
// never handed to the policy, so the offline scan must not evaluate it either:
// the validations self-guard by object.kind and evaluate to true for a
// non-matching kind, which the scanner would otherwise record as a pass the
// cluster never made (issue #2001).
//
// Matching covers everything on matchConstraints whose input the scanned
// object itself carries: the resource rules (apiGroups/apiVersions/resources,
// each rule's operations, scope and resourceNames, honoring "*" and
// excludeResourceRules) and the objectSelector, which matches the object's own
// labels. The scan models every resource as a fresh CREATE (see stub.go), so a
// rule that fires only on other operations does not match here either. The one
// selector NOT evaluated is namespaceSelector — its input is the namespace's
// labels, which the scan cannot guarantee to have — so a policy narrowing with
// it is refused at load instead (see requireSupported). matchPolicy is
// genuinely irrelevant offline: Equivalent matching only widens a rule across
// API conversions, and a scan never converts — the object is matched at the
// exact group/version it was scanned at.
func (v *VAP) AppliesTo(obj map[string]any) bool {
	if v.matchConstraints == nil || len(v.matchConstraints.ResourceRules) == 0 {
		return true // no scoping info: evaluate (a malformed-policy edge)
	}
	gvr, resources, ok := objectGVR(obj)
	if !ok {
		return true // kind undeterminable; let evaluation proceed (it will error and skip)
	}
	name, _, _ := unstructured.NestedString(obj, "metadata", "name")
	target := scopedObject{gvr: gvr, resources: resources, name: name, namespaced: isNamespaced(obj)}
	matchPolicy := effectiveMatchPolicy(v.matchConstraints)

	included := false
	for i := range v.matchConstraints.ResourceRules {
		if resourceRuleMatches(&v.matchConstraints.ResourceRules[i], target, matchPolicy) {
			included = true
			break
		}
	}
	if !included {
		return false
	}
	for i := range v.matchConstraints.ExcludeResourceRules {
		if resourceRuleMatches(&v.matchConstraints.ExcludeResourceRules[i], target, matchPolicy) {
			return false
		}
	}
	return objectSelectorMatches(v.matchConstraints.ObjectSelector, obj)
}

// objectSelectorMatches evaluates matchConstraints.objectSelector against the
// object's own labels — fully resolvable offline, since the labels are on the
// scanned object itself. The nil guard matters: an omitted selector means
// "match everything" on a policy, but metav1.LabelSelectorAsSelector maps nil
// to "match nothing", the exact opposite.
//
// Both malformed cases (a selector that will not parse, labels that are not a
// string map) fall back to evaluating, the same stance appliesTo takes on an
// undeterminable kind: widening surfaces as an evaluated result, while
// narrowing on something we failed to read would drop the resource silently.
// An object with no labels at all is not malformed — it is an empty set, which
// correctly fails a matchLabels selector and satisfies a DoesNotExist one.
func objectSelectorMatches(selector *metav1.LabelSelector, obj map[string]any) bool {
	if selector == nil {
		return true
	}
	sel, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return true
	}
	objLabels, found, err := unstructured.NestedStringMap(obj, "metadata", "labels")
	if err != nil {
		return true // labels present but not a string map
	}
	if !found {
		objLabels = nil
	}
	return sel.Matches(labels.Set(objLabels))
}

// resourcePluralAnnotation lets an object declare the plural its CRD actually
// registers, for a plural the kind->resource guess cannot reach.
const resourcePluralAnnotation = "kubescape.io/resource-plural"

// objectGVR resolves an object's GroupVersionResource from its apiVersion and
// kind, along with every resource name that kind may be registered under (see
// resourceNames). The GVR carries the first of them, the one a live cluster is
// most likely to serve.
func objectGVR(obj map[string]any) (schema.GroupVersionResource, []string, bool) {
	apiVersion, _ := obj["apiVersion"].(string)
	kind, _ := obj["kind"].(string)
	if apiVersion == "" || kind == "" {
		return schema.GroupVersionResource{}, nil, false
	}
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return schema.GroupVersionResource{}, nil, false
	}
	names := resourceNames(obj, gv, kind)
	return gv.WithResource(names[0]), names, true
}

// resourceNames returns the resource names a kind may be registered under, most
// likely first. Offline there is no discovery or RESTMapper, and a CRD picks its
// own spec.names.plural, so the spelling cannot be known: apimachinery's guess
// misses every sibilant kind (Sandbox -> "sandboxs") and every vowel+"y" kind
// (Gateway -> "gatewaies"), which an exact compare would drop silently. Keeping
// both spellings lets a rule match either one, and the annotation stays
// authoritative when an object declares the plural outright.
func resourceNames(obj map[string]any, gv schema.GroupVersion, kind string) []string {
	if plural, ok := annotatedPlural(obj); ok {
		return []string{plural}
	}
	guessed, singular := meta.UnsafeGuessKindToResource(gv.WithKind(kind))
	if guessed.Resource == singular.Resource {
		return []string{guessed.Resource} // kind is already plural (Endpoints)
	}
	names := []string{pluralize(singular.Resource)}
	if guessed.Resource != names[0] {
		names = append(names, guessed.Resource)
	}
	return names
}

// pluralize applies the English rules a CRD author (and controller-gen) follows:
// a sibilant ending takes "es", a consonant before a final "y" takes "ies", and
// everything else takes "s".
func pluralize(singular string) string {
	switch {
	case hasAnySuffix(singular, "s", "x", "z", "ch", "sh"):
		return singular + "es"
	case strings.HasSuffix(singular, "y") && len(singular) > 1 && !isVowel(singular[len(singular)-2]):
		return singular[:len(singular)-1] + "ies"
	}
	return singular + "s"
}

func hasAnySuffix(s string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}

func isVowel(c byte) bool {
	return strings.IndexByte("aeiou", c) >= 0
}

// annotatedPlural reads the resource-plural hint off the object. A missing,
// blank or non-string-map annotation set leaves the guess in charge.
func annotatedPlural(obj map[string]any) (string, bool) {
	annotations, found, err := unstructured.NestedStringMap(obj, "metadata", "annotations")
	if err != nil || !found {
		return "", false
	}
	plural := strings.TrimSpace(annotations[resourcePluralAnnotation])
	return plural, plural != ""
}

// scopedObject is what appliesTo reads off the scanned object once and matches
// every resource rule against, so adding a rule field to honor costs one field
// here rather than another parameter on every call.
type scopedObject struct {
	gvr schema.GroupVersionResource
	// resources are the names the object's kind may be registered under, any of
	// which a rule may name (see resourceNames).
	resources  []string
	name       string
	namespaced bool
}

func resourceRuleMatches(rule *admissionregistrationv1.NamedRuleWithOperations, target scopedObject, matchPolicy admissionregistrationv1.MatchPolicyType) bool {
	return matchesOperation(rule.Operations) &&
		matchesScope(rule.Scope, target.namespaced) &&
		matchesValue(rule.APIGroups, target.gvr.Group) &&
		matchesAPIVersion(rule.APIVersions, target.gvr.Version, matchPolicy) &&
		matchesResource(rule.Resources, target.resources) &&
		matchesName(rule.ResourceNames, target.name)
}

// effectiveMatchPolicy resolves matchConstraints.matchPolicy, which the API
// defaults to Equivalent when it is unset - as every policy in the bundle
// leaves it.
func effectiveMatchPolicy(mr *admissionregistrationv1.MatchResources) admissionregistrationv1.MatchPolicyType {
	if mr == nil || mr.MatchPolicy == nil {
		return admissionregistrationv1.Equivalent
	}
	return *mr.MatchPolicy
}

// matchesAPIVersion reports whether the rule's apiVersions admit the object's
// version.
func matchesAPIVersion(allowed []string, version string, _ admissionregistrationv1.MatchPolicyType) bool {
	return matchesValue(allowed, version)
}

// matchesScope reports whether the rule's scope admits the object. nil and "*"
// are the API default and admit everything.
//
// Only a Cluster rule narrows anything offline: an object carrying a namespace
// is proven namespaced, and admission would not hand it to that rule. The
// reverse is not provable — the apiserver defaults metadata.namespace before
// admission, so an absent one does not make the object cluster-scoped — which
// is why a Namespaced rule matches regardless, the same widening appliesTo
// applies to an undeterminable kind. Exclude rules get this symmetrically: a
// Cluster-scoped exclusion does not exempt an object we know is namespaced.
func matchesScope(scope *admissionregistrationv1.ScopeType, namespaced bool) bool {
	if scope == nil || *scope != admissionregistrationv1.ClusterScope {
		return true
	}
	return !namespaced
}

// matchesName reports whether the rule's resourceNames admit the object's
// metadata.name. An empty list is the common case and matches every name. The
// empty-NAME edge mirrors admission: a resource created with generateName has
// no name yet when admission evaluates it, so a named rule does not match it
// there, and an offline manifest carrying only generateName gets the same
// no-match here.
func matchesName(allowed []string, name string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if a == name && name != "" {
			return true
		}
	}
	return false
}

// matchesOperation reports whether the rule fires on CREATE, the one operation
// the offline scan models (request.operation is stubbed to CREATE, see stub.go).
// A rule listing only UPDATE or DELETE never sees the CREATE we model, so at
// admission the policy would not be handed the object and the scan must not
// evaluate it either. This applies to exclude rules symmetrically: an exclusion
// scoped to UPDATE does not exempt the CREATE we model. An empty list is invalid
// on a real policy (the API requires at least one operation); treat it as
// matching so a malformed rule surfaces as an evaluated result rather than a
// silently dropped one, the same stance appliesTo takes on missing constraints.
func matchesOperation(ops []admissionregistrationv1.OperationType) bool {
	if len(ops) == 0 {
		return true
	}
	for _, op := range ops {
		if op == admissionregistrationv1.OperationAll || op == admissionregistrationv1.Create {
			return true
		}
	}
	return false
}

// matchesValue reports whether want is listed, treating "*" as "any".
func matchesValue(allowed []string, want string) bool {
	for _, a := range allowed {
		if a == "*" || a == want {
			return true
		}
	}
	return false
}

// matchesResource is matchesValue for resources, also accepting the "*/*"
// subresource wildcard. It matches when the rule names any of the object's
// candidate resource names. A "resource/subresource" entry never matches a bare
// resource, which is correct: the scan does not evaluate subresources.
//
// A rule resource differing from a candidate only in separators still matches: a
// CRD may register "worker-pools" for kind WorkerPool, which pluralizing renders
// "workerpools". Dropping that object would be silent — the policy evaluates
// against nothing and the control reads as clean. A plural further from the
// candidates than that still needs the resource-plural annotation.
func matchesResource(allowed, wants []string) bool {
	for _, a := range allowed {
		if a == "*" || a == "*/*" {
			return true
		}
		for _, want := range wants {
			if want != "" && normalizePlural(a) == normalizePlural(want) {
				return true
			}
		}
	}
	return false
}

// pluralSeparators strips the separators a CRD plural may carry, so
// "worker-pools" and the guessed "workerpools" compare equal.
var pluralSeparators = strings.NewReplacer("-", "", "_", "")

func normalizePlural(resource string) string {
	return pluralSeparators.Replace(strings.ToLower(resource))
}
