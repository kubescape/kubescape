package cel

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// appliesTo reports whether an object of the given kind falls within the
// policy's spec.matchConstraints. At live admission a non-matching object is
// never handed to the policy, so the offline scan must not evaluate it either:
// the validations self-guard by object.kind and evaluate to true for a
// non-matching kind, which the scanner would otherwise record as a pass the
// cluster never made (issue #2001).
//
// Matching is by resource rule (apiGroups/apiVersions/resources, honoring "*"
// and excludeResourceRules). The label selectors and operations on
// matchConstraints are not applied offline: the vendored bundle uses neither,
// and ignoring them can only widen scope, which surfaces as an evaluated result
// rather than a silently dropped one.
func (v *VAP) appliesTo(obj map[string]any) bool {
	if v.matchConstraints == nil || len(v.matchConstraints.ResourceRules) == 0 {
		return true // no scoping info: evaluate (a malformed-policy edge)
	}
	gvr, ok := objectGVR(obj)
	if !ok {
		return true // kind undeterminable; let evaluation proceed (it will error and skip)
	}

	included := false
	for i := range v.matchConstraints.ResourceRules {
		if resourceRuleMatches(&v.matchConstraints.ResourceRules[i], gvr) {
			included = true
			break
		}
	}
	if !included {
		return false
	}
	for i := range v.matchConstraints.ExcludeResourceRules {
		if resourceRuleMatches(&v.matchConstraints.ExcludeResourceRules[i], gvr) {
			return false
		}
	}
	return true
}

// objectGVR guesses an object's GroupVersionResource from its apiVersion and
// kind. Offline there is no discovery or RESTMapper, so we use apimachinery's
// standard kind->resource guess (lower-case and pluralize), which is correct
// for every kind the bundle's policies constrain.
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
	gvr, _ := meta.UnsafeGuessKindToResource(gv.WithKind(kind))
	return gvr, true
}

func resourceRuleMatches(rule *admissionregistrationv1.NamedRuleWithOperations, gvr schema.GroupVersionResource) bool {
	return matchesValue(rule.APIGroups, gvr.Group) &&
		matchesValue(rule.APIVersions, gvr.Version) &&
		matchesResource(rule.Resources, gvr.Resource)
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
