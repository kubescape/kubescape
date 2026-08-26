package vapreconcile

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
)

// ResourceInfo is the minimal identity a coverage check needs for one
// scanned resource: which namespace it lives in (empty for cluster-scoped)
// and its own labels, for objectSelector matching.
type ResourceInfo struct {
	ResourceID string
	Namespace  string
	Labels     map[string]string
}

// ResourceCoverage reports whether one specific resource that failed a
// control actually falls within the scope of a live, bound VAPBinding for
// that control's policy -- as opposed to merely having *some* binding exist
// somewhere in the cluster, which BuildIndex/EnrichSummary already report
// via VAPEnforcementStatus.Bound.
type ResourceCoverage struct {
	ResourceID string
	Covered    bool
	// Reason explains why Covered is false. Empty when Covered is true.
	Reason string
}

// ControlCoverage summarizes, for one control, how much of its failing
// resource set a live VAPBinding actually enforces against -- versus how
// much BuildIndex/EnrichSummary's coarser, all-or-nothing Bound signal
// implies. A control can be Bound (some binding exists) while none of its
// failing resources are actually covered by that binding's scope, e.g. a
// namespaceSelector that only matches kube-system while every failure is
// elsewhere.
type ControlCoverage struct {
	ControlID  string
	PolicyName string
	// Bound mirrors VAPEnforcementStatus.Bound: true when at least one
	// binding names this control's policy, regardless of its scope.
	Bound     bool
	Resources []ResourceCoverage
}

// TotalFailing returns how many of the control's failing resources were
// evaluated for coverage.
func (c *ControlCoverage) TotalFailing() int {
	if c == nil {
		return 0
	}
	return len(c.Resources)
}

// CoveredCount returns how many of the control's failing resources are
// within scope of a live, bound binding.
func (c *ControlCoverage) CoveredCount() int {
	if c == nil {
		return 0
	}
	n := 0
	for _, r := range c.Resources {
		if r.Covered {
			n++
		}
	}
	return n
}

// FullyCovered reports whether every one of the control's failing resources
// is within scope of a live, bound binding: the case where the coarse
// Bound=true signal is actually trustworthy end to end.
func (c *ControlCoverage) FullyCovered() bool {
	if c == nil || !c.Bound || len(c.Resources) == 0 {
		return false
	}
	return c.CoveredCount() == len(c.Resources)
}

// PartiallyCovered reports whether the binding is bound and enforces against
// some, but not all, of the control's failing resources -- the case where
// Bound=true actively misleads about the control's actual live-enforcement
// reach.
func (c *ControlCoverage) PartiallyCovered() bool {
	if c == nil || !c.Bound {
		return false
	}
	covered := c.CoveredCount()
	return covered > 0 && covered < len(c.Resources)
}

// bindingScope is the parsed matchResources.namespaceSelector/objectSelector
// of one binding, compiled once per BuildCoverage call rather than once per
// resource it is checked against.
type bindingScope struct {
	namespaceSelector labels.Selector
	objectSelector    labels.Selector
}

// matches reports whether a resource falls within this binding's scope.
// namespaceLabelsKnown is false when the resource's Namespace object was not
// collected by the scan (out of scope, or the scan predates namespace
// collection): a namespaceSelector then cannot be evaluated, so the binding
// is treated as not matching rather than optimistically matching --
// silently over-crediting a binding's coverage would defeat the point of
// this check.
func (s *bindingScope) matches(resourceNamespace string, resourceLabels, namespaceLabels map[string]string, namespaceLabelsKnown bool) (bool, string) {
	if !s.objectSelector.Empty() && !s.objectSelector.Matches(labels.Set(resourceLabels)) {
		return false, "objectSelector does not match the resource's labels"
	}
	if !s.namespaceSelector.Empty() {
		if resourceNamespace == "" {
			return false, "namespaceSelector is set but the resource is cluster-scoped"
		}
		if !namespaceLabelsKnown {
			return false, "namespaceSelector is set but the resource's Namespace object was not collected by the scan"
		}
		if !s.namespaceSelector.Matches(labels.Set(namespaceLabels)) {
			return false, "namespaceSelector does not match the resource's namespace"
		}
	}
	return true, ""
}

// parseSelector converts a raw, unstructured LabelSelector (as decoded from
// JSON into map[string]any) into a labels.Selector. A missing or empty
// selector (nil, or a map with neither matchLabels nor matchExpressions)
// selects everything, matching the Kubernetes API's own semantics for an
// absent selector field.
func parseSelector(raw any) (labels.Selector, error) {
	if raw == nil {
		return labels.Everything(), nil
	}
	m, ok := raw.(map[string]any)
	if !ok || len(m) == 0 {
		return labels.Everything(), nil
	}

	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var typed metav1.LabelSelector
	if err := json.Unmarshal(b, &typed); err != nil {
		return nil, err
	}
	return metav1.LabelSelectorAsSelector(&typed)
}

// resolveBindingScope extracts and compiles one binding's
// matchResources.namespaceSelector/objectSelector. A binding with no
// matchResources at all (or no spec, which should not happen for a real
// object but is handled rather than assumed) has no additional scoping
// beyond its policy's own matchConstraints, so it resolves to a scope that
// matches everything.
func resolveBindingScope(binding unstructured.Unstructured) (*bindingScope, error) {
	spec, _ := binding.Object["spec"].(map[string]any)
	matchResources, _ := spec["matchResources"].(map[string]any)

	var nsRaw, objRaw any
	if matchResources != nil {
		nsRaw = matchResources["namespaceSelector"]
		objRaw = matchResources["objectSelector"]
	}

	nsSel, err := parseSelector(nsRaw)
	if err != nil {
		return nil, fmt.Errorf("binding %q: invalid namespaceSelector: %w", binding.GetName(), err)
	}
	objSel, err := parseSelector(objRaw)
	if err != nil {
		return nil, fmt.Errorf("binding %q: invalid objectSelector: %w", binding.GetName(), err)
	}
	return &bindingScope{namespaceSelector: nsSel, objectSelector: objSel}, nil
}

// indexPoliciesByControl mirrors BuildIndex's own policy/control join, kept
// separate (rather than shared) so BuildCoverage cannot be destabilized by a
// future change to BuildIndex's semantics, and vice versa.
func indexPoliciesByControl(policies []unstructured.Unstructured) (controlByPolicy map[string]string, policiesByControl map[string][]string) {
	controlByPolicy = make(map[string]string, len(policies))
	policiesByControl = make(map[string][]string, len(policies))
	for i := range policies {
		name := policies[i].GetName()
		controlID := policies[i].GetLabels()[controlIDLabel]
		if name == "" || controlID == "" {
			continue
		}
		if _, seen := controlByPolicy[name]; seen {
			continue // a repeated name is the same policy listed twice
		}
		controlByPolicy[name] = controlID
		policiesByControl[controlID] = append(policiesByControl[controlID], name)
	}
	return controlByPolicy, policiesByControl
}

// indexBindingsByPolicy groups bindings by the policy name they name in
// spec.policyName, keeping the raw binding objects (unlike BuildIndex's
// actionsByPolicy, which only needs their validationActions) so
// BuildCoverage can inspect each one's own matchResources scope.
func indexBindingsByPolicy(bindings []unstructured.Unstructured, controlByPolicy map[string]string) map[string][]unstructured.Unstructured {
	byPolicy := make(map[string][]unstructured.Unstructured, len(bindings))
	for i := range bindings {
		spec, ok := bindings[i].Object["spec"].(map[string]any)
		if !ok {
			continue
		}
		policyName, _ := spec["policyName"].(string)
		if _, known := controlByPolicy[policyName]; !known {
			continue
		}
		byPolicy[policyName] = append(byPolicy[policyName], bindings[i])
	}
	return byPolicy
}

// BuildCoverage computes, per control, whether each of its failing
// resources actually falls within the scope of a live, bound VAPBinding --
// refining BuildIndex's coarser "is any binding present" signal with the
// namespaceSelector/objectSelector scoping the Kubernetes API server itself
// applies at admission time. A control absent from the returned map has no
// VAP at all (BuildIndex would not have indexed it either); a control
// present with Bound=false has a policy but no binding names it -- both
// match BuildIndex's own reporting for the same inputs.
//
// resourceRules, excludeResourceRules and matchPolicy on the binding are not
// evaluated: a binding's scope is assumed to cover every GVR/operation its
// policy's matchConstraints admits. This can overstate coverage for a
// binding that further narrows the GVRs/operations from what its policy
// covers, but never understates it, and namespaceSelector/objectSelector are
// by far the more commonly used per-binding scoping mechanism.
func BuildCoverage(
	policies, bindings []unstructured.Unstructured,
	failingByControl map[string][]ResourceInfo,
	namespaceLabels map[string]map[string]string,
) map[string]*ControlCoverage {
	controlByPolicy, policiesByControl := indexPoliciesByControl(policies)
	bindingsByPolicy := indexBindingsByPolicy(bindings, controlByPolicy)

	coverage := make(map[string]*ControlCoverage, len(failingByControl))
	for controlID, resources := range failingByControl {
		policyNames := policiesByControl[controlID]
		if len(policyNames) == 0 {
			continue // no VAP for this control: nothing to report
		}
		slices.Sort(policyNames)

		result := &ControlCoverage{ControlID: controlID, PolicyName: policyNames[0]}

		scopesByPolicy := make(map[string][]*bindingScope)
		for _, name := range policyNames {
			rawBindings := bindingsByPolicy[name]
			if len(rawBindings) == 0 {
				continue
			}
			if !result.Bound {
				result.Bound = true
				result.PolicyName = name
			}
			for _, b := range rawBindings {
				scope, err := resolveBindingScope(b)
				if err != nil {
					// A binding this malformed cannot be evaluated for scope;
					// treat it as covering nothing rather than guessing.
					continue
				}
				scopesByPolicy[name] = append(scopesByPolicy[name], scope)
			}
		}

		for _, res := range resources {
			nsLabels, known := namespaceLabels[res.Namespace]
			covered := false
			reason := "no bound binding names this control's policy"
			if result.Bound {
				reason = "no binding's scope covers this resource"
			policyLoop:
				for _, scopes := range scopesByPolicy {
					for _, scope := range scopes {
						ok, whyNot := scope.matches(res.Namespace, res.Labels, nsLabels, known)
						if ok {
							covered = true
							break policyLoop
						}
						// Keep the most recent scope's reason: with a single
						// binding (the common case) it is the only reason
						// there is, and with several it is still a concrete,
						// truthful example of why none of them matched.
						reason = whyNot
					}
				}
			}
			rc := ResourceCoverage{ResourceID: res.ResourceID, Covered: covered}
			if !covered {
				rc.Reason = reason
			}
			result.Resources = append(result.Resources, rc)
		}

		coverage[controlID] = result
	}

	return coverage
}

// CollectFailingResourcesByControl derives, for every control, the identity
// (ID, namespace, labels) of each resource that failed it -- the input
// BuildCoverage needs to check per-resource binding scope, since neither
// ResourcesResult nor the OPA session tracks that on its own.
func CollectFailingResourcesByControl(
	resourcesResult map[string]resourcesresults.Result,
	allResources map[string]workloadinterface.IMetadata,
) map[string][]ResourceInfo {
	byControl := make(map[string][]ResourceInfo)
	for resourceID, result := range resourcesResult {
		resource, ok := allResources[resourceID]
		if !ok || resource == nil {
			continue
		}
		info := ResourceInfo{
			ResourceID: resourceID,
			Namespace:  resource.GetNamespace(),
			Labels:     resourceLabels(resource),
		}
		for _, ac := range result.AssociatedControls {
			if !ac.GetStatus(nil).IsFailed() {
				continue
			}
			byControl[ac.ControlID] = append(byControl[ac.ControlID], info)
		}
	}
	return byControl
}

// CollectNamespaceLabels indexes every scanned Namespace object's labels by
// name, for BuildCoverage's namespaceSelector evaluation. A namespace absent
// from this map was not collected by the scan (out of scope, or the scan
// predates namespace collection), and BuildCoverage treats that as "cannot
// determine" rather than "matches everything".
func CollectNamespaceLabels(allResources map[string]workloadinterface.IMetadata) map[string]map[string]string {
	nsLabels := make(map[string]map[string]string)
	for _, resource := range allResources {
		if resource == nil || resource.GetApiVersion() != "v1" || resource.GetKind() != "Namespace" {
			continue
		}
		name := resource.GetName()
		if name == "" {
			continue
		}
		nsLabels[name] = resourceLabels(resource)
	}
	return nsLabels
}

// resourceLabels extracts a resource's labels. IMetadata does not carry
// labels; IBasicWorkload does, so this casts rather than widening every
// caller's parameter type to it.
func resourceLabels(resource workloadinterface.IMetadata) map[string]string {
	basicWorkload, ok := resource.(workloadinterface.IBasicWorkload)
	if !ok {
		return nil
	}
	return basicWorkload.GetLabels()
}
