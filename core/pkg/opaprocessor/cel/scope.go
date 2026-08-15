package cel

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ResourcePluralAnnotation is an optional annotation that callers can set on a
// scanned object to declare its exact plural resource name. When present,
// objectGVR uses this value instead of UnsafeGuessKindToResource, which
// lower-cases and pluralizes the Kind — a convention that holds for all core
// K8s types but silently breaks for CRDs whose spec.names.plural deviates
// from it (e.g. a CRD that registers "worker-pools" instead of "workerpools").
//
// The cluster collector sets this automatically from the API server's discovery
// response. Manifest-scan callers that know the real plural (e.g. integration
// tests for agent-runtime CRD policies) can set it by hand:
//
//	obj.metadata.annotations["kubescape.io/resource"] = "actortemplates"
const ResourcePluralAnnotation = "kubescape.io/resource"

// appliesTo reports whether an object of the given kind falls within the
// policy's spec.matchConstraints. At live admission a non-matching object is
// never handed to the policy, so the offline scan must not evaluate it either:
// the validations self-guard by object.kind and evaluate to true for a
// non-matching kind, which the scanner would otherwise record as a pass the
// cluster never made (issue #2001).
//
// Matching covers everything on matchConstraints whose input the scanned
// object itself carries: the resource rules (apiGroups/apiVersions/resources,
// each rule's operations and resourceNames, honoring "*" and
// excludeResourceRules) and the objectSelector, which matches the object's own
// labels. The scan models every resource as a fresh CREATE (see stub.go), so a
// rule that fires only on other operations does not match here either. The one
// selector NOT evaluated is namespaceSelector — its input is the namespace's
// labels, which the scan cannot guarantee to have — so a policy narrowing with
// it is refused at load instead (see requireSupported). matchPolicy is
// genuinely irrelevant offline: Equivalent matching only widens a rule across
// API conversions, and a scan never converts — the object is matched at the
// exact group/version it was scanned at.
func (v *VAP) appliesTo(obj map[string]any) bool {
	if v.matchConstraints == nil || len(v.matchConstraints.ResourceRules) == 0 {
		return true // no scoping info: evaluate (a malformed-policy edge)
	}
	gvr, ok := objectGVR(obj)
	if !ok {
		return true // kind undeterminable; let evaluation proceed (it will error and skip)
	}
	name, _, _ := unstructured.NestedString(obj, "metadata", "name")

	included := false
	for i := range v.matchConstraints.ResourceRules {
		if resourceRuleMatches(&v.matchConstraints.ResourceRules[i], gvr, name) {
			included = true
			break
		}
	}
	if !included {
		return false
	}
	for i := range v.matchConstraints.ExcludeResourceRules {
		if resourceRuleMatches(&v.matchConstraints.ExcludeResourceRules[i], gvr, name) {
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

// objectGVR derives an object's GroupVersionResource from its apiVersion and
// kind. Offline there is no discovery or RESTMapper, so the function first
// checks for a ResourcePluralAnnotation set by the cluster collector or by the
// caller; if the annotation is absent it falls back to apimachinery's
// UnsafeGuessKindToResource, which lower-cases and pluralizes the Kind.
//
// The guess is correct for every core and built-in K8s kind the current
// bundle's policies constrain, but silently wrong for CRDs whose
// spec.names.plural deviates from the convention. In that case the resource
// field of the returned GVR will not match the policy's matchConstraints entry
// and resourceRuleMatches will return false — the policy evaluates against
// nothing, which is indistinguishable from "all resources pass". The annotation
// exists precisely to let callers that know the real plural bypass the guess
// (see ResourcePluralAnnotation).
func objectGVR(obj map[string]any) (schema.GroupVersionResource, bool) {
	apiVersion, _ := obj["apiVersion"].(string)
	kind, _ := obj["kind"].(string)
	if apiVersion == "" || kind == "" {
		return schema.GroupVersionResource{}, false
	}
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return schema.GroupVersionResource{}, false
	}
	// Prefer the explicit annotation over the guess. UnsafeGuessKindToResource
	// pluralizes and lower-cases, which is correct for core types but silently
	// wrong for CRDs with non-standard spec.names.plural values.
	if hint, _, _ := unstructured.NestedString(obj, "metadata", "annotations", ResourcePluralAnnotation); hint != "" {
		return gv.WithResource(hint), true
	}
	gvr, _ := meta.UnsafeGuessKindToResource(gv.WithKind(kind))
	return gvr, true
}

func resourceRuleMatches(rule *admissionregistrationv1.NamedRuleWithOperations, gvr schema.GroupVersionResource, name string) bool {
	return matchesOperation(rule.Operations) &&
		matchesValue(rule.APIGroups, gvr.Group) &&
		matchesValue(rule.APIVersions, gvr.Version) &&
		matchesResource(rule.Resources, gvr.Resource) &&
		matchesName(rule.ResourceNames, name)
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
// subresource wildcard. A "resource/subresource" entry never matches a bare
// resource, which is correct: the scan does not evaluate subresources.
func matchesResource(allowed []string, want string) bool {
	for _, a := range allowed {
		if a == "*" || a == "*/*" || a == want {
			return true
		}
	}
	return false
}
