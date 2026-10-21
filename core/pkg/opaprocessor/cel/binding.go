package cel

import (
	"fmt"

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
// namespaceObject is the scanned Namespace of a namespaced obj, or nil when the
// scan did not collect it. An error means the answer is unknown: only a
// non-empty namespaceSelector on a namespaced object needs that Namespace, and
// an object the other criteria already rule out is answered without it.
func (s *BindingScope) Covers(obj, namespaceObject map[string]any) (bool, error) {
	if s == nil {
		return true, nil
	}
	namespaceMatches, namespaceKnown := s.namespaceSelectorMatches(obj, namespaceObject)
	if namespaceKnown && !namespaceMatches {
		return false, nil
	}
	if !objectSelectorMatches(s.matchResources.ObjectSelector, obj) {
		return false, nil
	}

	target, ok := newScopedObject(obj)
	if !ok {
		return false, fmt.Errorf("the resource's apiVersion and kind are unreadable, so the binding's resource rules cannot be matched")
	}
	matchPolicy := effectiveMatchPolicy(&s.matchResources)
	for i := range s.matchResources.ExcludeResourceRules {
		if resourceRuleMatches(&s.matchResources.ExcludeResourceRules[i], target, matchPolicy) {
			return false, nil
		}
	}
	if len(s.matchResources.ResourceRules) > 0 {
		included := false
		for i := range s.matchResources.ResourceRules {
			if resourceRuleMatches(&s.matchResources.ResourceRules[i], target, matchPolicy) {
				included = true
				break
			}
		}
		if !included {
			return false, nil
		}
	}
	if !namespaceKnown {
		namespace, _, _ := unstructured.NestedString(obj, "metadata", "namespace")
		return false, fmt.Errorf("namespace %q was not collected, so the binding's namespaceSelector cannot be evaluated", namespace)
	}
	return true, nil
}

// namespaceSelectorMatches mirrors the apiserver's namespace matcher
// (webhook/predicates/namespace Matcher.MatchNamespaceSelector): a
// cluster-scoped object other than a Namespace is never exempted, an empty
// selector matches, and a Namespace is matched on its own labels.
func (s *BindingScope) namespaceSelectorMatches(obj, namespaceObject map[string]any) (matches, known bool) {
	if s.namespaceSelector.Empty() {
		return true, true
	}
	if isNamespaceObject(obj) {
		return s.namespaceSelector.Matches(labels.Set(objectLabels(obj))), true
	}
	if !isNamespaced(obj) {
		return true, true
	}
	if namespaceObject == nil {
		return false, false
	}
	return s.namespaceSelector.Matches(labels.Set(objectLabels(namespaceObject))), true
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
