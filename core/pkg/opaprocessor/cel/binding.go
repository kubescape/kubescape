package cel

import (
	"fmt"
	"slices"

	"github.com/kubescape/k8s-interface/k8sinterface"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
)

// BindingScope is a ValidatingAdmissionPolicyBinding's spec.matchResources:
// which of the objects its policy matches the binding actually binds. At
// admission a binding only supplies its paramRef (and its validationActions)
// to the requests it covers, so the scan must apply the binding's params to
// exactly those objects.
//
// A nil *BindingScope is a binding without matchResources, which covers every
// object the policy matches.
type BindingScope struct {
	matchResources    admissionregistrationv1.MatchResources
	namespaceSelector labels.Selector
}

// ParseBindingScope reads spec.matchResources from a binding. It returns nil
// when the binding has none.
//
// The apiserver defaults a binding's matchResources on create (matchPolicy
// Equivalent, empty namespaceSelector and objectSelector), so a live binding
// written with `matchResources: {}` - as `kubescape vap create-policy-binding`
// writes it - comes back carrying those defaults even though it narrows
// nothing. Nil selectors are read the same way, so an offline binding that was
// never defaulted behaves like the live one.
//
// A selector that will not parse is an error rather than a widening: the
// apiserver rejects such a binding on create, so one reaching the scan is not
// something admission ever enforced, and guessing its scope would put the
// binding's params on objects it may never bind.
func ParseBindingScope(binding map[string]any) (*BindingScope, error) {
	raw, found, err := unstructured.NestedMap(binding, "spec", "matchResources")
	if err != nil {
		return nil, fmt.Errorf("read spec.matchResources: %w", err)
	}
	if !found {
		return nil, nil
	}
	scope := &BindingScope{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(raw, &scope.matchResources); err != nil {
		return nil, fmt.Errorf("decode spec.matchResources: %w", err)
	}
	scope.namespaceSelector, err = parseSelector(scope.matchResources.NamespaceSelector)
	if err != nil {
		return nil, fmt.Errorf("spec.matchResources.namespaceSelector: %w", err)
	}
	if _, err := parseSelector(scope.matchResources.ObjectSelector); err != nil {
		return nil, fmt.Errorf("spec.matchResources.objectSelector: %w", err)
	}
	return scope, nil
}

// parseSelector converts a binding selector, reading nil as the empty selector
// the apiserver defaults it to (which matches everything), not as the "match
// nothing" metav1.LabelSelectorAsSelector gives nil.
func parseSelector(selector *metav1.LabelSelector) (labels.Selector, error) {
	if selector == nil {
		return labels.Everything(), nil
	}
	return metav1.LabelSelectorAsSelector(selector)
}

// Covers reports whether the binding binds obj, following the apiserver's
// policy matcher (admission/plugin/policy/matching Matcher.Matches): the
// namespaceSelector, then the objectSelector, then excludeResourceRules, then
// resourceRules, where an empty list covers everything the policy matches.
// The caller has already checked the policy's own matchConstraints.
//
// The answer picks the params obj is evaluated with, so it has to be proven:
// when it depends on something the scan cannot establish, Covers returns an
// error instead of a guess. That happens when
//   - a non-empty namespaceSelector needs a namespace the scan does not know:
//     the object has no metadata.namespace and its kind is not known to be
//     cluster-scoped, or its Namespace was not collected;
//   - a rule's scope needs a scope the scan does not know;
//   - under the Equivalent matchPolicy, a rule matches the object's resource
//     except for its group or version. Only the cluster knows which group
//     versions are equivalent.
//
// An object the binding provably does not bind is answered without the
// missing input.
//
// namespaceObject is the scanned Namespace of a namespaced obj, or nil when the
// scan did not collect it.
func (s *BindingScope) Covers(obj, namespaceObject map[string]any) (bool, error) {
	if s == nil {
		return true, nil
	}
	if !objectSelectorMatches(s.matchResources.ObjectSelector, obj) {
		return false, nil
	}
	target, ok := newScopedObject(obj)
	if !ok {
		return false, fmt.Errorf("the resource's apiVersion and kind are unreadable, so the binding's resource rules cannot be matched")
	}
	scope := resolveObjectScope(obj, target)

	namespaceMatches, namespaceErr := s.namespaceSelectorMatches(obj, scope, namespaceObject)
	if namespaceErr == nil && !namespaceMatches {
		return false, nil
	}

	matchPolicy := effectiveMatchPolicy(&s.matchResources)
	var unknown error
	for i := range s.matchResources.ExcludeResourceRules {
		switch bindingRuleMatches(&s.matchResources.ExcludeResourceRules[i], target, scope, matchPolicy) {
		case ruleMatch:
			return false, nil
		case ruleUnknown:
			unknown = errRuleUnknown("excludeResourceRules")
		}
	}
	if len(s.matchResources.ResourceRules) > 0 {
		included := ruleNoMatch
		for i := range s.matchResources.ResourceRules {
			if m := bindingRuleMatches(&s.matchResources.ResourceRules[i], target, scope, matchPolicy); m > included {
				included = m
			}
		}
		switch included {
		case ruleNoMatch:
			return false, nil
		case ruleUnknown:
			if unknown == nil {
				unknown = errRuleUnknown("resourceRules")
			}
		}
	}
	if namespaceErr != nil {
		return false, namespaceErr
	}
	if unknown != nil {
		return false, unknown
	}
	return true, nil
}

func errRuleUnknown(field string) error {
	return fmt.Errorf("whether the binding's %s match the resource depends on its scope or on which API versions the cluster treats as equivalent, which the scan cannot establish", field)
}

// objectScope is what the scan can establish about where an object lives.
type objectScope int

const (
	scopeUnknown objectScope = iota
	scopeNamespaced
	scopeCluster
)

// resolveObjectScope establishes obj's scope from what the scan has: an object
// with metadata.namespace is namespaced; a Namespace is cluster-scoped, as the
// apiserver's matchers treat it; otherwise the kind's scope comes from the
// cluster's discovery (or k8s-interface's built-in resource list offline). An
// offline manifest commonly omits metadata.namespace, so a missing namespace
// alone proves nothing.
func resolveObjectScope(obj map[string]any, target scopedObject) objectScope {
	if isNamespaced(obj) {
		return scopeNamespaced
	}
	if isNamespaceObject(obj) {
		return scopeCluster
	}
	groupVersion := target.gvr.GroupVersion().String()
	if target.gvr.Group == "" {
		groupVersion = "/" + target.gvr.Version
	}
	for _, resource := range target.resources {
		served, ok := k8sinterface.GetResourceFromGroupMapping(resource)
		if !ok || !slices.Contains(served, groupVersion) {
			continue
		}
		gvr := target.gvr.GroupVersion().WithResource(resource)
		if k8sinterface.IsNamespaceScope(&gvr) {
			return scopeNamespaced
		}
		return scopeCluster
	}
	return scopeUnknown
}

// namespaceSelectorMatches mirrors the apiserver's namespace matcher
// (webhook/predicates/namespace Matcher.MatchNamespaceSelector): an empty
// selector matches, a Namespace is matched on its own labels, and a
// cluster-scoped object is never exempted. A namespaced object is matched on
// its Namespace's labels, which needs both its namespace and the collected
// Namespace object.
func (s *BindingScope) namespaceSelectorMatches(obj map[string]any, scope objectScope, namespaceObject map[string]any) (bool, error) {
	if s.namespaceSelector.Empty() {
		return true, nil
	}
	if isNamespaceObject(obj) {
		return s.namespaceSelector.Matches(labels.Set(objectLabels(obj))), nil
	}
	switch scope {
	case scopeCluster:
		return true, nil
	case scopeUnknown:
		return false, fmt.Errorf("the resource has no metadata.namespace and its kind is not known to be cluster-scoped, so the binding's namespaceSelector cannot be evaluated")
	}
	namespace, _, _ := unstructured.NestedString(obj, "metadata", "namespace")
	if namespace == "" {
		return false, fmt.Errorf("the resource is namespaced but has no metadata.namespace, so the binding's namespaceSelector cannot be evaluated")
	}
	if namespaceObject == nil {
		return false, fmt.Errorf("namespace %q was not collected, so the binding's namespaceSelector cannot be evaluated", namespace)
	}
	return s.namespaceSelector.Matches(labels.Set(objectLabels(namespaceObject))), nil
}

// ruleResult is a three-way rule match, ordered so the strongest result wins.
type ruleResult int

const (
	ruleNoMatch ruleResult = iota
	ruleUnknown
	ruleMatch
)

// bindingRuleMatches matches one of the binding's resource rules without the
// widening AppliesTo allows a policy's own rules. A policy that evaluates an
// object it would not match at admission only reports an extra result; a
// binding that covers an object it does not bind hands it params that can
// suppress a finding. So the scope must be known whenever the rule restricts
// it, and under the Equivalent matchPolicy a rule naming another group or
// version of the object's resource is unknown rather than a match.
func bindingRuleMatches(rule *admissionregistrationv1.NamedRuleWithOperations, target scopedObject, scope objectScope, matchPolicy admissionregistrationv1.MatchPolicyType) ruleResult {
	if !matchesOperation(rule.Operations) ||
		!matchesResource(rule.Resources, target.resources) ||
		!matchesName(rule.ResourceNames, target.name) {
		return ruleNoMatch
	}
	result := ruleMatch
	if rule.Scope != nil && *rule.Scope != admissionregistrationv1.AllScopes {
		switch {
		case scope == scopeUnknown:
			result = ruleUnknown
		case (*rule.Scope == admissionregistrationv1.ClusterScope) != (scope == scopeCluster):
			return ruleNoMatch
		}
	}
	if !matchesValue(rule.APIGroups, target.gvr.Group) || !matchesValue(rule.APIVersions, target.gvr.Version) {
		if matchPolicy != admissionregistrationv1.Equivalent {
			return ruleNoMatch
		}
		result = ruleUnknown
	}
	return result
}

// isNamespaceObject reports whether obj is a core/v1 Namespace.
func isNamespaceObject(obj map[string]any) bool {
	apiVersion, _ := obj["apiVersion"].(string)
	kind, _ := obj["kind"].(string)
	return apiVersion == "v1" && kind == "Namespace"
}

func objectLabels(obj map[string]any) map[string]string {
	objLabels, _, _ := unstructured.NestedStringMap(obj, "metadata", "labels")
	return objLabels
}
