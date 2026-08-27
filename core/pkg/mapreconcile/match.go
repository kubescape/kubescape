package mapreconcile

import (
	admissionregistrationv1alpha1 "k8s.io/api/admissionregistration/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// ObjectInfo identifies one candidate object for matching against a
// MutatingAdmissionPolicy's matchConstraints/matchResources: the API
// coordinates a NamedRuleWithOperations rule matches against, plus the labels
// a namespaceSelector/objectSelector match against.
type ObjectInfo struct {
	Group     string
	Version   string
	Resource  string // plural resource name, e.g. "pods"
	Name      string // the object's own name, matched against a rule's ResourceNames
	Namespace string // empty for a cluster-scoped object
	Labels    map[string]string
	Operation admissionregistrationv1alpha1.OperationType

	// ClusterScoped marks obj as a cluster-scoped resource. A Namespace
	// object is itself cluster-scoped ("Namespace API objects are
	// cluster-scoped", per Rule.Scope's own doc comment) and must still set
	// this true for Rule.Scope matching -- IsNamespaceObject below is what
	// distinguishes it from every other cluster-scoped kind for
	// namespaceSelector purposes specifically.
	ClusterScoped bool

	// IsNamespaceObject marks obj as a Namespace object itself. Per
	// MatchResources' own doc comment, a namespaceSelector is evaluated
	// against a Namespace object's *own* labels (there is no separate
	// containing namespace to look up), whereas for every other
	// cluster-scoped kind it never skips the policy at all. Getting this
	// wrong in either direction is a real false-positive/negative for a
	// security-analysis tool, not just an edge case.
	IsNamespaceObject bool

	// NamespaceLabels is the labels of ObjectInfo's own namespace object,
	// needed for namespaceSelector matching. NamespaceLabelsKnown
	// distinguishes "this namespace really has no labels" from "the caller
	// never looked the namespace up" -- the latter must not be treated as a
	// confident empty-label-set match against a non-empty selector.
	NamespaceLabels      map[string]string
	NamespaceLabelsKnown bool
}

// ruleMatches reports whether one NamedRuleWithOperations rule covers obj.
// An empty rule (the zero value) never matches: a well-formed API object
// always has at least one non-empty field in a real rule, so an empty one is
// either a defensively-parsed malformed object or a caller mistake, and
// treating it as "matches everything" would be the dangerous direction to be
// wrong in.
func ruleMatches(rule admissionregistrationv1alpha1.NamedRuleWithOperations, obj ObjectInfo) bool {
	if !operationMatches(rule.Operations, obj.Operation) {
		return false
	}
	if !stringRuleMatches(rule.APIGroups, obj.Group) {
		return false
	}
	if !stringRuleMatches(rule.APIVersions, obj.Version) {
		return false
	}
	if !stringRuleMatches(rule.Resources, obj.Resource) {
		return false
	}
	if !resourceNamesMatch(rule.ResourceNames, obj.Name) {
		return false
	}
	if !scopeMatches(rule.Scope, obj) {
		return false
	}
	return true
}

// resourceNamesMatch reports whether obj's name is covered by a rule's
// ResourceNames. An empty list is documented as "an optional white list...
// An empty set means that everything is allowed", so it does not restrict
// matching at all.
func resourceNamesMatch(names []string, objName string) bool {
	if len(names) == 0 {
		return true
	}
	for _, n := range names {
		if n == objName {
			return true
		}
	}
	return false
}

// scopeMatches reports whether obj's scope satisfies a rule's Scope. A nil
// Scope defaults to AllScopes, per Rule.Scope's own doc comment ("Default is
// '*'").
func scopeMatches(scope *admissionregistrationv1alpha1.ScopeType, obj ObjectInfo) bool {
	if scope == nil {
		return true
	}
	switch *scope {
	case admissionregistrationv1alpha1.ClusterScope:
		return obj.ClusterScoped
	case admissionregistrationv1alpha1.NamespacedScope:
		return !obj.ClusterScoped
	default: // AllScopes, or any value this package does not recognize
		return true
	}
}

func operationMatches(ops []admissionregistrationv1alpha1.OperationType, op admissionregistrationv1alpha1.OperationType) bool {
	for _, o := range ops {
		if o == admissionregistrationv1alpha1.OperationAll || o == op {
			return true
		}
	}
	return false
}

// stringRuleMatches reports whether candidate is covered by values, where
// values comes from a Rule's APIGroups/APIVersions/Resources: "*" (alone, or
// alongside other entries) matches anything, otherwise candidate must appear
// verbatim.
func stringRuleMatches(values []string, candidate string) bool {
	for _, v := range values {
		if v == "*" || v == candidate {
			return true
		}
	}
	return false
}

// resourceRulesVerdict OR-combines every rule in rules against obj. An empty
// rule list matches everything, matching MatchResources' own documented
// semantics for an unset ResourceRules (required for a policy's
// matchConstraints in practice, but optional -- and non-constraining when
// absent -- on a binding's matchResources).
func resourceRulesVerdict(rules []admissionregistrationv1alpha1.NamedRuleWithOperations, obj ObjectInfo) bool {
	if len(rules) == 0 {
		return true
	}
	return anyRuleMatches(rules, obj)
}

// anyRuleMatches OR-combines every rule in rules against obj, with no
// "empty means match everything" override: an empty rule list matches
// nothing. This is what ExcludeResourceRules needs -- an absent exclude list
// must exclude nothing, not everything, unlike an absent (required)
// ResourceRules list.
func anyRuleMatches(rules []admissionregistrationv1alpha1.NamedRuleWithOperations, obj ObjectInfo) bool {
	for _, rule := range rules {
		if ruleMatches(rule, obj) {
			return true
		}
	}
	return false
}

// compiledMatchResources pre-parses one MatchResources' selectors once so a
// query does not re-parse them on every call.
type compiledMatchResources struct {
	namespaceSelector labels.Selector // nil means "no selector: matches everything"
	objectSelector    labels.Selector
	resourceRules     []admissionregistrationv1alpha1.NamedRuleWithOperations
	excludeRules      []admissionregistrationv1alpha1.NamedRuleWithOperations
	matchPolicy       admissionregistrationv1alpha1.MatchPolicyType
}

// compileMatchResources parses mr's selectors once. A nil mr compiles to "no
// restriction at all" (matches every object), matching MatchResources' own
// nil semantics. A malformed selector is reported rather than silently
// treated as matching everything or nothing -- either guess can turn a real
// mutation into an invisible one or a phantom one.
func compileMatchResources(mr *admissionregistrationv1alpha1.MatchResources) (*compiledMatchResources, error) {
	c := &compiledMatchResources{matchPolicy: admissionregistrationv1alpha1.Equivalent}
	if mr == nil {
		return c, nil
	}

	c.resourceRules = mr.ResourceRules
	c.excludeRules = mr.ExcludeResourceRules
	if mr.MatchPolicy != nil {
		c.matchPolicy = *mr.MatchPolicy
	}

	if mr.NamespaceSelector != nil {
		sel, err := metav1.LabelSelectorAsSelector(mr.NamespaceSelector)
		if err != nil {
			return nil, err
		}
		c.namespaceSelector = sel
	}
	if mr.ObjectSelector != nil {
		sel, err := metav1.LabelSelectorAsSelector(mr.ObjectSelector)
		if err != nil {
			return nil, err
		}
		c.objectSelector = sel
	}
	return c, nil
}

// matches reports whether obj is matched by c. determinable is false only
// when a namespaceSelector must be evaluated but obj's namespace labels were
// never supplied -- in that case matched is meaningless and callers must
// treat the result as Unknown, not as a confident non-match.
//
// matchPolicy Equivalent (the API's default) is documented to also match a
// request arriving via an API-group/version this policy did not list, if
// that version is equivalent to one that was. Resolving that equivalence
// needs full API discovery data this package is not given, so a resourceRules
// miss under an explicit Equivalent matchPolicy is reported as indeterminate
// rather than a confident non-match: the object may still be covered via a
// version this rule never named.
func (c *compiledMatchResources) matches(obj ObjectInfo) (matched bool, determinable bool) {
	if c.namespaceSelector != nil && !c.namespaceSelector.Empty() {
		switch {
		case obj.IsNamespaceObject:
			// There is no separate containing namespace to look up: the
			// selector is evaluated against the Namespace object's own
			// labels, which the caller always has (they are obj.Labels,
			// not a lookup that can be "unknown").
			if !c.namespaceSelector.Matches(labels.Set(obj.Labels)) {
				return false, true
			}
		case !obj.ClusterScoped:
			if !obj.NamespaceLabelsKnown {
				return false, false
			}
			if !c.namespaceSelector.Matches(labels.Set(obj.NamespaceLabels)) {
				return false, true
			}
		default:
			// A cluster-scoped object other than Namespace itself: a
			// namespaceSelector never skips the policy for it, per
			// MatchResources' own doc comment.
		}
	}

	if c.objectSelector != nil && !c.objectSelector.Empty() {
		if !c.objectSelector.Matches(labels.Set(obj.Labels)) {
			return false, true
		}
	}

	if anyRuleMatches(c.excludeRules, obj) {
		// Exclude rules take precedence over include rules unconditionally.
		return false, true
	}

	if resourceRulesVerdict(c.resourceRules, obj) {
		return true, true
	}
	if c.matchPolicy == admissionregistrationv1alpha1.Equivalent && resourceRulesAmbiguousUnderEquivalence(c.resourceRules, obj) {
		return false, false
	}
	return false, true
}

// resourceRulesAmbiguousUnderEquivalence reports whether some rule in rules
// matches obj's resource name and operation but not its group/version --
// exactly the situation Equivalent matchPolicy resolves using API
// group/version-equivalence data (e.g. autoscaling/v1 vs autoscaling/v2
// HorizontalPodAutoscalers) that this package is not given. A rule that does
// not even name this resource (e.g. "configmaps" when obj is a "pods") is
// never ambiguous: two unrelated resource kinds are never equivalent under
// any matchPolicy.
func resourceRulesAmbiguousUnderEquivalence(rules []admissionregistrationv1alpha1.NamedRuleWithOperations, obj ObjectInfo) bool {
	for _, rule := range rules {
		if !operationMatches(rule.Operations, obj.Operation) {
			continue
		}
		if !stringRuleMatches(rule.Resources, obj.Resource) {
			continue
		}
		if !stringRuleMatches(rule.APIGroups, obj.Group) || !stringRuleMatches(rule.APIVersions, obj.Version) {
			return true
		}
	}
	return false
}
