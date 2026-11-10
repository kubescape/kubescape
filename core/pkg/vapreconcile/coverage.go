package vapreconcile

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/namespaceselector"
	"github.com/kubescape/kubescape/v4/core/pkg/opaprocessor/cel"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
)

// ResourceInfo is the minimal identity a coverage check needs for one
// scanned resource: what it is, which namespace it lives in (empty for
// cluster-scoped) and its own labels, for objectSelector matching.
type ResourceInfo struct {
	ResourceID string
	APIVersion string
	Kind       string
	Name       string // object name; Namespace objects use it for the immutable namespace-name label
	Namespace  string
	Labels     map[string]string
	// Object is the scanned resource itself, when the caller has it. A
	// binding's resourceRules and excludeResourceRules are matched against
	// it; without it they are matched against an object rebuilt from the
	// identity fields above.
	Object map[string]any
}

// ruleObject returns the object a binding's resource rules are matched
// against: the scanned resource when it was collected, otherwise one rebuilt
// from the identity fields, which is all the rule matcher reads.
func (r ResourceInfo) ruleObject() map[string]any {
	if r.Object != nil {
		return r.Object
	}
	metadata := map[string]any{}
	if r.Name != "" {
		metadata["name"] = r.Name
	}
	if r.Namespace != "" {
		metadata["namespace"] = r.Namespace
	}
	if len(r.Labels) > 0 {
		objLabels := make(map[string]any, len(r.Labels))
		for k, v := range r.Labels {
			objLabels[k] = v
		}
		metadata["labels"] = objLabels
	}
	return map[string]any{"apiVersion": r.APIVersion, "kind": r.Kind, "metadata": metadata}
}

// The core/v1 Namespace identity, which a namespaceSelector reads
// differently from every other kind (see bindingScope.matches).
const (
	namespaceAPIVersion = "v1"
	namespaceKind       = "Namespace"
)

// knownClusterScopedKinds holds Kubernetes built-in and common ecosystem
// cluster-scoped kinds that may be absent from bundled discovery data.
var knownClusterScopedKinds = map[string]struct{}{
	"ServiceCIDR":                      {},
	"IPAddress":                        {},
	"ClusterCIDR":                      {},
	"ValidatingAdmissionPolicy":        {},
	"ValidatingAdmissionPolicyBinding": {},
	"MutatingAdmissionPolicy":          {},
	"MutatingAdmissionPolicyBinding":   {},
	"SelfSubjectReview":                {},
	"ClusterIssuer":                    {},
}

// isNamespace reports whether the resource is a Namespace object. It carries
// no metadata.namespace of its own, so scope has to be decided on the kind.
func (r ResourceInfo) isNamespace() bool {
	return r.APIVersion == namespaceAPIVersion && r.Kind == namespaceKind
}

// isNamespaced reports whether the resource belongs to a namespace. An object with
// an explicit Namespace is namespaced; a Namespace or cluster-scoped object is not;
// otherwise scope is determined from its Kind using Kubernetes resource mappings.
func (r ResourceInfo) isNamespaced() bool {
	if r.Namespace != "" {
		return true
	}
	if r.isNamespace() || r.isClusterScoped() {
		return false
	}
	if r.Kind != "" {
		return k8sinterface.IsResourceInNamespaceScope(r.Kind)
	}
	return false
}

// isClusterScoped reports whether the resource is known to be cluster-scoped.
// A Namespace object is cluster-scoped, as are standard Kubernetes kinds that
// are confirmed not to be in namespace scope, kinds prefixed with "Cluster",
// and built-in cluster-scoped kinds missing from bundled discovery data.
func (r ResourceInfo) isClusterScoped() bool {
	if r.Namespace != "" {
		return false
	}
	if r.isNamespace() {
		return true
	}
	if r.Kind == "" {
		return false
	}
	if _, ok := knownClusterScopedKinds[r.Kind]; ok {
		return true
	}
	if strings.HasPrefix(r.Kind, "Cluster") {
		return true
	}
	return k8sinterface.IsKindKubernetes(r.Kind) && !k8sinterface.IsResourceInNamespaceScope(r.Kind)
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
	// rules holds a binding's resourceRules, excludeResourceRules and
	// matchPolicy, matched by the CEL engine's binding matcher so coverage
	// and the scan agree on which objects a binding binds. Nil when the
	// binding narrows no resources (and always for a policy's
	// matchConstraints, whose rules are not evaluated here).
	rules *cel.BindingScope
}

// matches reports whether a resource falls within this binding's scope. It
// takes the whole ResourceInfo because the two selectors read different parts
// of it, and the apiserver's own namespace matcher also branches on what the
// resource is, not just on where it lives.
//
// namespaceLabelsKnown is false when the resource's Namespace object was not
// collected by the scan (out of scope, or the scan predates namespace
// collection). Only the immutable namespace-name label can be inferred in
// that case; selectors needing other labels remain uncovered rather than
// optimistically matching --
// silently over-crediting a binding's coverage would defeat the point of
// this check.
func (s *bindingScope) matches(res ResourceInfo, namespaceLabels map[string]string, namespaceLabelsKnown bool) (bool, string) {
	if ok, whyNot := s.selectorsMatch(res, namespaceLabels, namespaceLabelsKnown); !ok {
		return false, whyNot
	}
	if s.rules != nil {
		// The rules-only scope carries no selectors, so no namespace object
		// is needed: selectorsMatch has already decided them.
		covered, err := s.rules.Covers(res.ruleObject(), nil)
		if err != nil {
			return false, "binding resource rules could not be evaluated: " + err.Error()
		}
		if !covered {
			return false, "binding resourceRules/excludeResourceRules do not match the resource"
		}
	}
	return true, ""
}

// selectorsMatch decides the namespaceSelector and objectSelector half of
// matches.
func (s *bindingScope) selectorsMatch(res ResourceInfo, namespaceLabels map[string]string, namespaceLabelsKnown bool) (bool, string) {
	if !s.objectSelector.Empty() && !s.objectSelector.Matches(labels.Set(res.Labels)) {
		return false, "objectSelector does not match the resource's labels"
	}
	if !s.namespaceSelector.Empty() {
		if res.isNamespace() {
			// The namespace a Namespace is "in" is itself, so the selector is
			// read against the object's own labels. Falling through to the
			// cluster-scoped arm below covered it unconditionally, which
			// overstated the reach of a binding that excludes it.
			if matched, _ := namespaceselector.Matches(s.namespaceSelector, res.Name, res.Labels, true); !matched {
				return false, "namespaceSelector does not match the namespace's own labels"
			}
			return true, ""
		}
		if res.Namespace == "" {
			if res.isClusterScoped() {
				// A cluster-scoped resource has no namespace whose labels the
				// selector could be read against, and the apiserver does not
				// exempt it for that: its namespace matcher returns "matches"
				// before it ever parses the selector. Reporting it uncovered
				// understated the reach of every binding scoped by namespace.
				return true, ""
			}
			if res.isNamespaced() {
				return false, "namespaceSelector is set but namespaced resource has no namespace specified"
			}
			return false, "namespaceSelector is set but the resource's scope could not be determined and it has no namespace"
		}
		matched, determinable := namespaceselector.Matches(s.namespaceSelector, res.Namespace, namespaceLabels, namespaceLabelsKnown)
		if !determinable {
			return false, "namespaceSelector is set but the resource's Namespace object was not collected by the scan"
		}
		if !matched {
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
// matchResources: its namespaceSelector/objectSelector, and its
// resourceRules/excludeResourceRules/matchPolicy. A binding with no
// matchResources at all (or no spec, which should not happen for a real
// object but is handled rather than assumed) has no additional scoping
// beyond its policy's own matchConstraints, so it resolves to a scope that
// matches everything.
func resolveBindingScope(binding unstructured.Unstructured) (*bindingScope, error) {
	scope, err := resolveSelectorScope(binding, "matchResources")
	if err != nil {
		return nil, err
	}
	scope.rules, err = resolveBindingRules(binding)
	if err != nil {
		return nil, fmt.Errorf("matchResources %q: %w", binding.GetName(), err)
	}
	return scope, nil
}

// resolveBindingRules parses the resource-narrowing part of a binding's
// matchResources with the CEL engine's binding matcher, so coverage uses the
// same rule matching as the scan does when it applies the binding. The
// selectors are left out: resolveSelectorScope already handles them, and
// keeping them in one place keeps their existing behavior unchanged. It
// returns nil when the binding narrows no resources, because an empty
// resourceRules covers everything the policy matches and matchPolicy only
// affects how rules are compared.
func resolveBindingRules(binding unstructured.Unstructured) (*cel.BindingScope, error) {
	matchResources, _, err := unstructured.NestedMap(binding.Object, "spec", "matchResources")
	if err != nil || matchResources == nil {
		return nil, err
	}
	rulesOnly := map[string]any{}
	for _, field := range []string{"resourceRules", "excludeResourceRules"} {
		rules, present := matchResources[field]
		if !present || rules == nil {
			continue
		}
		if list, ok := rules.([]any); ok && len(list) == 0 {
			continue
		}
		// Anything else, a malformed value included, goes to the parser,
		// which rejects what it cannot decode rather than dropping it.
		rulesOnly[field] = rules
	}
	if len(rulesOnly) == 0 {
		return nil, nil
	}
	if matchPolicy, ok := matchResources["matchPolicy"]; ok {
		rulesOnly["matchPolicy"] = matchPolicy
	}
	return cel.ParseBindingScope(map[string]any{"spec": map[string]any{"matchResources": rulesOnly}})
}

// resolveSelectorScope shares selector parsing between policies and bindings.
// Their selectors are intersected, not alternatives.
func resolveSelectorScope(obj unstructured.Unstructured, field string) (*bindingScope, error) {
	spec, _ := obj.Object["spec"].(map[string]any)
	matchResources, _ := spec[field].(map[string]any)

	var nsRaw, objRaw any
	if matchResources != nil {
		nsRaw = matchResources["namespaceSelector"]
		objRaw = matchResources["objectSelector"]
	}

	nsSel, err := parseSelector(nsRaw)
	if err != nil {
		return nil, fmt.Errorf("%s %q: invalid namespaceSelector: %w", field, obj.GetName(), err)
	}
	objSel, err := parseSelector(objRaw)
	if err != nil {
		return nil, fmt.Errorf("%s %q: invalid objectSelector: %w", field, obj.GetName(), err)
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
// applies at admission time, intersected with the selectors in each policy's
// matchConstraints. A control absent from the returned map has no
// VAP at all (BuildIndex would not have indexed it either); a control
// present with Bound=false has a policy but no binding names it -- both
// match BuildIndex's own reporting for the same inputs.
//
// A binding's resourceRules, excludeResourceRules and matchPolicy are
// matched with the CEL engine's binding matcher (cel.BindingScope.Covers).
// When that match depends on something the scan cannot establish -- the
// resource's scope, or which API versions the cluster treats as equivalent
// under matchPolicy Equivalent -- the resource is reported uncovered with
// the reason, never optimistically covered. The resourceRules of a policy's
// own matchConstraints are not evaluated.
func BuildCoverage(
	policies, bindings []unstructured.Unstructured,
	failingByControl map[string][]ResourceInfo,
	namespaceLabels map[string]map[string]string,
) map[string]*ControlCoverage {
	controlByPolicy, policiesByControl := indexPoliciesByControl(policies)
	bindingsByPolicy := indexBindingsByPolicy(bindings, controlByPolicy)
	policyScopes := make(map[string]*bindingScope, len(controlByPolicy))
	for _, policy := range policies {
		name := policy.GetName()
		if controlID, known := controlByPolicy[name]; !known || policy.GetLabels()[controlIDLabel] != controlID {
			continue
		}
		if _, seen := policyScopes[name]; seen {
			continue
		}
		// Preserve Bound for malformed policies, but never credit coverage
		// when their selectors cannot be evaluated.
		scope, _ := resolveSelectorScope(policy, "matchConstraints")
		policyScopes[name] = scope
	}

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
				for name, scopes := range scopesByPolicy {
					policyScope := policyScopes[name]
					if policyScope == nil {
						reason = "policy selectors could not be evaluated"
						continue
					}
					if ok, whyNot := policyScope.matches(res, nsLabels, known); !ok {
						reason = "policy " + whyNot
						continue
					}
					for _, scope := range scopes {
						ok, whyNot := scope.matches(res, nsLabels, known)
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

// ResourceCatalog abstracts the resource lookups and iteration required by coverage checks.
// It is implemented by cautils.ResourceCatalog and any mock or map catalog.
type ResourceCatalog interface {
	Get(id string) (workloadinterface.IMetadata, bool)
	ForEach(fn func(id string, res workloadinterface.IMetadata) bool)
}

type mapResourceCatalog map[string]workloadinterface.IMetadata

func (m mapResourceCatalog) Get(id string) (workloadinterface.IMetadata, bool) {
	if m == nil {
		return nil, false
	}
	res, ok := m[id]
	return res, ok
}

func (m mapResourceCatalog) ForEach(fn func(id string, res workloadinterface.IMetadata) bool) {
	for id, res := range m {
		if !fn(id, res) {
			break
		}
	}
}

func hasException(control *resourcesresults.ResourceAssociatedControl) bool {
	for i := range control.ResourceAssociatedRules {
		if len(control.ResourceAssociatedRules[i].Exception) > 0 {
			return true
		}
	}
	return false
}

func controlFilters(summary *reportsummary.SummaryDetails, controlID string) *helpersv1.Filters {
	filters := &helpersv1.Filters{}
	if summary == nil {
		return filters
	}
	for i := range summary.Frameworks {
		framework := &summary.Frameworks[i]
		if _, ok := framework.Controls[controlID]; ok && framework.GetName() != "" {
			filters.FrameworkNames = append(filters.FrameworkNames, framework.GetName())
		}
	}
	return filters
}

// controlStatus returns the effective status of a control in the frameworks of
// the scan that contain it, matching how the report summary and printers evaluate
// framework-scoped exceptions. With no summary it falls back to raw status.
func controlStatus(summary *reportsummary.SummaryDetails, control *resourcesresults.ResourceAssociatedControl) apis.IStatus {
	if !hasException(control) {
		return control.GetStatus(nil)
	}
	return control.GetStatus(controlFilters(summary, control.GetID()))
}

// CollectFailingResourcesByControl derives, for every control, the identity
// (ID, namespace, labels) of each resource that failed it -- the input
// BuildCoverage needs to check per-resource binding scope, since neither
// ResourcesResult nor the OPA session tracks that on its own.
// Maintained for backward compatibility.
func CollectFailingResourcesByControl(
	summary *reportsummary.SummaryDetails,
	resourcesResult map[string]resourcesresults.Result,
	allResources map[string]workloadinterface.IMetadata,
) map[string][]ResourceInfo {
	return CollectFailingResourcesByControlFromCatalog(summary, resourcesResult, mapResourceCatalog(allResources))
}

// CollectFailingResourcesByControlFromCatalog derives failing resource identities on demand from catalog.
func CollectFailingResourcesByControlFromCatalog(
	summary *reportsummary.SummaryDetails,
	resourcesResult map[string]resourcesresults.Result,
	catalog ResourceCatalog,
) map[string][]ResourceInfo {
	byControl := make(map[string][]ResourceInfo)
	if catalog == nil {
		return byControl
	}
	for resourceID, result := range resourcesResult {
		hasFailed := false
		for i := range result.AssociatedControls {
			if controlStatus(summary, &result.AssociatedControls[i]).IsFailed() {
				hasFailed = true
				break
			}
		}
		if !hasFailed {
			continue
		}
		resource, ok := catalog.Get(resourceID)
		if !ok || resource == nil {
			continue
		}
		info := ResourceInfo{
			ResourceID: resourceID,
			APIVersion: resource.GetApiVersion(),
			Kind:       resource.GetKind(),
			Name:       resource.GetName(),
			Namespace:  resource.GetNamespace(),
			Labels:     resourceLabels(resource),
			Object:     resource.GetObject(),
		}
		for i := range result.AssociatedControls {
			ac := &result.AssociatedControls[i]
			if !controlStatus(summary, ac).IsFailed() {
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
// Maintained for backward compatibility.
func CollectNamespaceLabels(allResources map[string]workloadinterface.IMetadata) map[string]map[string]string {
	return CollectNamespaceLabelsFromCatalog(mapResourceCatalog(allResources))
}

// CollectNamespaceLabelsFromCatalog indexes scanned Namespace object labels using catalog iteration.
func CollectNamespaceLabelsFromCatalog(catalog ResourceCatalog) map[string]map[string]string {
	nsLabels := make(map[string]map[string]string)
	if catalog == nil {
		return nsLabels
	}
	catalog.ForEach(func(_ string, resource workloadinterface.IMetadata) bool {
		if resource == nil || resource.GetApiVersion() != namespaceAPIVersion || resource.GetKind() != namespaceKind {
			return true
		}
		name := resource.GetName()
		if name == "" {
			return true
		}
		nsLabels[name] = resourceLabels(resource)
		return true
	})
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
