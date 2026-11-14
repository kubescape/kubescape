package getter

import "github.com/armosec/armoapi-go/armotypes"

// secondaryExceptionSourceAttribute records the merge source independently of
// CRD event provenance, which a primary file may also carry after serialization.
const secondaryExceptionSourceAttribute = "kubescape.io/secondary-exception-source"

// FilterMatchedExceptions gives primary policies precedence over secondary
// policies for an already-matched resource and rule. Workload matching must run
// first: comparing designator strings cannot subtract overlapping regex scopes.
// Only covered posture tuples are removed, preserving other frameworks/rules.
// The returned policies do not mutate the input or their posture-policy slices.
func FilterMatchedExceptions(matched []armotypes.PostureExceptionPolicy) []armotypes.PostureExceptionPolicy {
	var primaries []armotypes.PosturePolicy
	hasSecondary := false
	for _, exception := range matched {
		if secondary, _ := exception.Attributes[secondaryExceptionSourceAttribute].(bool); secondary {
			hasSecondary = true
			continue
		}
		if len(exception.PosturePolicies) == 0 {
			primaries = append(primaries, armotypes.PosturePolicy{})
		} else {
			primaries = append(primaries, exception.PosturePolicies...)
		}
	}
	if !hasSecondary || len(primaries) == 0 {
		return matched
	}
	matcher := newScopeMatcher()
	filtered := make([]armotypes.PostureExceptionPolicy, 0, len(matched))
	for _, exception := range matched {
		secondary, _ := exception.Attributes[secondaryExceptionSourceAttribute].(bool)
		if !secondary {
			filtered = append(filtered, exception)
			continue
		}
		if len(exception.PosturePolicies) == 0 {
			if !matcher.coveredBy(primaries, armotypes.PosturePolicy{}) {
				filtered = append(filtered, exception)
			}
			continue
		}
		policies := make([]armotypes.PosturePolicy, 0, len(exception.PosturePolicies))
		for _, policy := range exception.PosturePolicies {
			if !matcher.coveredBy(primaries, policy) {
				policies = append(policies, policy)
			}
		}
		if len(policies) != 0 {
			exception.PosturePolicies = policies
			filtered = append(filtered, exception)
		}
	}
	return filtered
}
