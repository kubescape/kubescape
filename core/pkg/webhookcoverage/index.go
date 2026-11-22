package webhookcoverage

import (
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Verdict is the outcome of matching one webhook against a request.
type Verdict string

const (
	// Matched: every filter is satisfied; the webhook would be called.
	Matched Verdict = "Matched"
	// NotMatched: some filter definitively rejects the request; the webhook
	// would not be called. This says nothing about whether the request is
	// otherwise protected.
	NotMatched Verdict = "NotMatched"
	// Indeterminate: nothing definitively rejects the request, but a filter
	// could not be evaluated. See Result.Reasons.
	Indeterminate Verdict = "Indeterminate"
)

// Reason says why a result has its verdict. For NotMatched it names the
// filters that definitively rejected the request; for Indeterminate it names
// the filters that could not be evaluated from the supplied information.
type Reason string

// Reasons that explain a NotMatched verdict.
const (
	// ReasonExemptResource: the apiserver never sends webhook and admission
	// policy configuration objects to API-defined webhooks.
	ReasonExemptResource Reason = "ExemptResource"
	// ReasonRulesDoNotMatch: no rule of the webhook covers the request. Under
	// matchPolicy Equivalent this also means no rule could cover it through an
	// equivalent resource, which is only established when every rule differs
	// from the request in operation or subresource.
	ReasonRulesDoNotMatch Reason = "RulesDoNotMatch"
	// ReasonNamespaceSelectorExcludes: the namespaceSelector rejects the
	// request's namespace.
	ReasonNamespaceSelectorExcludes Reason = "NamespaceSelectorExcludes"
	// ReasonObjectSelectorExcludes: the objectSelector rejects every object
	// the apiserver tests for this operation.
	ReasonObjectSelectorExcludes Reason = "ObjectSelectorExcludes"
)

// Reasons that explain an Indeterminate verdict.
const (
	// ReasonMatchConditions: the webhook has matchConditions, CEL that needs
	// request context.
	ReasonMatchConditions Reason = "MatchConditions"
	// ReasonEquivalentResources: matchPolicy Equivalent (the default) could
	// route this request to the webhook through an equivalent resource, which
	// only the apiserver's registry knows. No rule matches the request itself,
	// but one agrees with it on operation and subresource.
	ReasonEquivalentResources Reason = "EquivalentResources"
	// ReasonNamespaceLabelsUnknown: the namespaceSelector needs namespace labels
	// that were not supplied, or that the apiserver has not finalised yet.
	ReasonNamespaceLabelsUnknown Reason = "NamespaceLabelsUnknown"
	// ReasonNamespaceUnknown: the request targets a namespaced resource but
	// names no namespace, so a namespaceSelector cannot be evaluated.
	ReasonNamespaceUnknown Reason = "NamespaceUnknown"
	// ReasonInvalidRule: a rule holds an operation or scope this package does
	// not recognise, so it cannot be ruled out as a match.
	ReasonInvalidRule Reason = "InvalidRule"
	// ReasonObjectLabelsUnknown: the objectSelector needs labels of an object
	// that was not supplied.
	ReasonObjectLabelsUnknown Reason = "ObjectLabelsUnknown"
	// ReasonInvalidNamespaceSelector: the namespaceSelector is malformed.
	ReasonInvalidNamespaceSelector Reason = "InvalidNamespaceSelector"
	// ReasonInvalidObjectSelector: the objectSelector is malformed.
	ReasonInvalidObjectSelector Reason = "InvalidObjectSelector"
	// ReasonKindUnknown: the request targets the admissionregistration.k8s.io
	// group but no Kind was supplied, and the apiserver's exemption for webhook
	// and admission-policy configurations is decided by kind.
	ReasonKindUnknown Reason = "KindUnknown"
	// ReasonVersionDependentExclusion: the request targets an authentication or
	// authorization review resource, which newer apiservers exclude from all
	// webhooks and older ones do not.
	ReasonVersionDependentExclusion Reason = "VersionDependentExclusion"
	// ReasonIncompleteRequest: the request lacks an operation, version or
	// resource, or contradicts itself (a ClusterScoped request that names a
	// namespace), so nothing can be evaluated.
	ReasonIncompleteRequest Reason = "IncompleteRequest"
)

// WebhookType tells which kind of configuration a webhook came from.
type WebhookType string

const (
	ValidatingWebhook WebhookType = "Validating"
	MutatingWebhook   WebhookType = "Mutating"
)

// Request is a synthetic admission request. Operation, Version and Resource
// are required; everything else narrows the result. Group is empty for the
// core API group.
type Request struct {
	Group       string
	Version     string
	Resource    string // plural, e.g. "pods"
	Subresource string // e.g. "exec"; empty for the resource itself
	// Kind is the request's kind, e.g. "ValidatingWebhookConfiguration". It is
	// only needed for the admissionregistration.k8s.io group, and is assumed to
	// share the resource's group.
	Kind      string
	Operation admissionregistrationv1.OperationType // Create, Update, Delete or Connect
	Name      string                                // required for a Namespace
	// Namespace is the namespace of a namespaced resource. It is ignored for
	// the Namespace resource itself, which is identified by Name.
	Namespace string
	// ClusterScoped marks a cluster-scoped resource other than Namespace, such
	// as nodes, which needs no Namespace. A request for any other resource
	// with no Namespace and ClusterScoped unset is namespaced with an unknown
	// namespace: that is never taken to mean cluster-scoped.
	ClusterScoped bool

	// ObjectLabels are the labels of the object being written (CREATE, UPDATE).
	// OldObjectLabels are the labels of the stored object (UPDATE, DELETE).
	// A label set is only used when its Known flag is true, so that an object
	// without labels can be told apart from an object nobody supplied. Sets
	// the operation does not carry are ignored. A CONNECT request has neither,
	// as the apiserver admits its options object instead.
	ObjectLabels         map[string]string
	ObjectLabelsKnown    bool
	OldObjectLabels      map[string]string
	OldObjectLabelsKnown bool

	// NamespaceLabels are the labels of the request's namespace, used by
	// namespaceSelector. For a Namespace being created or updated the
	// object's own ObjectLabels are used instead, as the apiserver does.
	// kubernetes.io/metadata.name is inferred even when they are unknown.
	NamespaceLabels      map[string]string
	NamespaceLabelsKnown bool
}

// Result is the outcome for one webhook.
type Result struct {
	Configuration string // name of the webhook configuration
	Webhook       string // name of the webhook inside it
	Type          WebhookType
	Verdict       Verdict
	// Reasons explains the verdict, ordered by the filter that raised them,
	// without duplicates. NotMatched lists every filter that rejected the
	// request; Indeterminate lists every filter that could not be evaluated
	// (it is only returned when none rejected); Matched has none.
	Reasons []Reason
}

// webhook is one compiled webhook of either type.
type webhook struct {
	configuration string
	name          string
	kind          WebhookType

	ruleSet            []admissionregistrationv1.RuleWithOperations
	invalidRules       bool
	equivalent         bool
	hasMatchConditions bool

	namespaceSelector labels.Selector
	namespaceErr      error
	objectSelector    labels.Selector
	objectErr         error
}

// Index holds compiled webhook configurations for repeated queries.
type Index struct {
	webhooks []*webhook
}

// NewIndex compiles the webhooks of the given configurations. Rules are
// copied, so later changes to the inputs do not affect the index.
//
// A malformed selector or a rule with an unrecognised operation or scope does
// not drop the webhook: it stays in the index, is reported in errs, and
// answers Indeterminate whenever that part would have to be evaluated. An
// unrecognised matchPolicy is reported and treated as Equivalent.
func NewIndex(validating []admissionregistrationv1.ValidatingWebhookConfiguration, mutating []admissionregistrationv1.MutatingWebhookConfiguration) (idx *Index, errs []error) {
	idx = &Index{}
	for i := range validating {
		cfg := &validating[i]
		for j := range cfg.Webhooks {
			w := &cfg.Webhooks[j]
			errs = append(errs, idx.add("ValidatingWebhookConfiguration", cfg.Name, w.Name, ValidatingWebhook, w.Rules, w.MatchPolicy,
				len(w.MatchConditions) > 0, w.NamespaceSelector, w.ObjectSelector)...)
		}
	}
	for i := range mutating {
		cfg := &mutating[i]
		for j := range cfg.Webhooks {
			w := &cfg.Webhooks[j]
			errs = append(errs, idx.add("MutatingWebhookConfiguration", cfg.Name, w.Name, MutatingWebhook, w.Rules, w.MatchPolicy,
				len(w.MatchConditions) > 0, w.NamespaceSelector, w.ObjectSelector)...)
		}
	}
	return idx, errs
}

func (idx *Index) add(configKind, configuration, name string, kind WebhookType, ruleSet []admissionregistrationv1.RuleWithOperations,
	policy *admissionregistrationv1.MatchPolicyType, hasMatchConditions bool, namespaceSelector, objectSelector *metav1.LabelSelector) (errs []error) {
	w := &webhook{
		configuration: configuration,
		name:          name,
		kind:          kind,
		// The API server defaults an unset matchPolicy to Equivalent. Any
		// value other than Exact is treated as possibly Equivalent: v0.37.2
		// handles an unknown value like Exact, but a newer API may give it
		// a meaning, and guessing Exact could produce a false NotMatched.
		equivalent:         policy == nil || *policy != admissionregistrationv1.Exact,
		hasMatchConditions: hasMatchConditions,
	}
	prefix := fmt.Sprintf("%s %s: webhook %q", configKind, configuration, name)
	for i := range ruleSet {
		rule := *ruleSet[i].DeepCopy()
		if err := checkRule(rule); err != nil {
			w.invalidRules = true
			errs = append(errs, fmt.Errorf("%s: rule %d: %w", prefix, i, err))
		}
		w.ruleSet = append(w.ruleSet, rule)
	}
	if policy != nil && *policy != admissionregistrationv1.Exact && *policy != admissionregistrationv1.Equivalent {
		errs = append(errs, fmt.Errorf("%s: unknown matchPolicy %q, treated as Equivalent", prefix, *policy))
	}
	var err error
	if w.namespaceSelector, err = compileSelector(namespaceSelector); err != nil {
		w.namespaceErr = err
		errs = append(errs, fmt.Errorf("%s: invalid namespaceSelector: %w", prefix, err))
	}
	if w.objectSelector, err = compileSelector(objectSelector); err != nil {
		w.objectErr = err
		errs = append(errs, fmt.Errorf("%s: invalid objectSelector: %w", prefix, err))
	}
	idx.webhooks = append(idx.webhooks, w)
	return errs
}

// checkRule reports an operation or scope value this package does not know.
// The apiserver matches such a rule against nothing, but a configuration
// written for a newer API may give those values a meaning, so the webhook
// cannot be ruled out. Empty lists are left alone: they match nothing.
func checkRule(r admissionregistrationv1.RuleWithOperations) error {
	for _, op := range r.Operations {
		switch op {
		case admissionregistrationv1.OperationAll, admissionregistrationv1.Create, admissionregistrationv1.Update,
			admissionregistrationv1.Delete, admissionregistrationv1.Connect:
		default:
			return fmt.Errorf("unknown operation %q", op)
		}
	}
	if r.Scope != nil {
		switch *r.Scope {
		case admissionregistrationv1.AllScopes, admissionregistrationv1.ClusterScope, admissionregistrationv1.NamespacedScope:
		default:
			return fmt.Errorf("unknown scope %q", *r.Scope)
		}
	}
	return nil
}

// compileSelector parses a webhook selector. An unset selector matches
// everything, as the API server defaults it to the empty selector.
func compileSelector(s *metav1.LabelSelector) (labels.Selector, error) {
	if s == nil {
		return labels.Everything(), nil
	}
	return metav1.LabelSelectorAsSelector(s)
}

// Matches evaluates req against every webhook, validating configurations
// first and then mutating ones, each in the order supplied to NewIndex. It
// returns one Result per webhook.
//
// With the default matchPolicy Equivalent, results are Indeterminate more
// often than with the real API server, whose equivalent-resource registry is
// not available here; see the package documentation.
//
// A request without an operation, version or resource makes every result
// Indeterminate with ReasonIncompleteRequest.
func (idx *Index) Matches(req Request) []Result {
	if idx == nil {
		return nil
	}
	out := make([]Result, 0, len(idx.webhooks))
	r, ok := newRequest(req)
	for _, w := range idx.webhooks {
		if !ok {
			out = append(out, Result{Configuration: w.configuration, Webhook: w.name, Type: w.kind,
				Verdict: Indeterminate, Reasons: []Reason{ReasonIncompleteRequest}})
			continue
		}
		out = append(out, w.match(r))
	}
	return out
}
