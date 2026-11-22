package webhookcoverage

import (
	"slices"

	"github.com/kubescape/kubescape/v4/core/pkg/namespaceselector"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/predicates/object"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/predicates/rules"
)

const (
	admissionRegistrationGroup = "admissionregistration.k8s.io"
	namespacesResource         = "namespaces"
)

// virtualResources are the non-persisted authentication and authorization
// review resources that kube-apiserver excludes from every webhook once the
// ExcludeAdmissionWebhookVirtualResources feature gate is enabled (see
// pkg/kubeapiserver/admission/exclusion and pkg/controlplane/apiserver/admission
// in kubernetes/kubernetes). The apiserver module the webhook predicates come
// from does not carry this list, so it is mirrored here.
var virtualResources = map[schema.GroupResource]struct{}{
	{Group: "authentication.k8s.io", Resource: "selfsubjectreviews"}:       {},
	{Group: "authentication.k8s.io", Resource: "tokenreviews"}:             {},
	{Group: "authorization.k8s.io", Resource: "localsubjectaccessreviews"}: {},
	{Group: "authorization.k8s.io", Resource: "selfsubjectaccessreviews"}:  {},
	{Group: "authorization.k8s.io", Resource: "selfsubjectrulesreviews"}:   {},
	{Group: "authorization.k8s.io", Resource: "subjectaccessreviews"}:      {},
}

// request is a validated Request prepared once for every webhook: the
// apiserver Attributes the rule and object predicates consume.
type request struct {
	Request
	attr admission.Attributes
	// namespace is what the apiserver reports as the request's namespace: the
	// object's own name for a Namespace, empty for other cluster-scoped objects
	// and when the namespace of a namespaced request is unknown.
	namespace string
	// namespaceUnknown is set for a namespaced request that names no namespace.
	namespaceUnknown bool
}

// unknownNamespace stands in for the namespace of a namespaced request that
// names none. Only the rule predicate's scope check reads it, to tell a
// namespaced request from a cluster-scoped one; no label or selector ever sees
// it.
const unknownNamespace = "namespace-not-supplied"

func newRequest(r Request) (*request, bool) {
	switch r.Operation {
	case admissionregistrationv1.Create, admissionregistrationv1.Update,
		admissionregistrationv1.Delete, admissionregistrationv1.Connect:
	default:
		return nil, false
	}
	if r.Version == "" || r.Resource == "" {
		return nil, false
	}
	if r.ClusterScoped && r.Namespace != "" && r.Resource != namespacesResource {
		return nil, false
	}

	namespace := r.Namespace
	if r.Resource == namespacesResource {
		namespace = r.Name
	}
	namespaceUnknown := r.Resource != namespacesResource && r.Namespace == "" && !r.ClusterScoped
	attrNamespace := namespace
	if namespaceUnknown {
		attrNamespace = unknownNamespace
	}

	var obj, old runtime.Object
	switch r.Operation {
	case admissionregistrationv1.Connect:
		// The apiserver admits the connect options (PodExecOptions and the
		// like) as the object and has no old object. Neither carries metadata,
		// so an objectSelector can never match whatever the target's labels.
		obj = &corev1.PodExecOptions{}
	case admissionregistrationv1.Create:
		obj = labelsObject(r.ObjectLabels, r.ObjectLabelsKnown)
	case admissionregistrationv1.Update:
		obj = labelsObject(r.ObjectLabels, r.ObjectLabelsKnown)
		old = labelsObject(r.OldObjectLabels, r.OldObjectLabelsKnown)
	case admissionregistrationv1.Delete:
		// DELETE carries only the stored object, as the old object.
		old = labelsObject(r.OldObjectLabels, r.OldObjectLabelsKnown)
	}

	attr := admission.NewAttributesRecord(obj, old,
		schema.GroupVersionKind{Group: r.Group, Version: r.Version, Kind: r.Kind},
		attrNamespace, r.Name,
		schema.GroupVersionResource{Group: r.Group, Version: r.Version, Resource: r.Resource},
		r.Subresource, admission.Operation(r.Operation), nil, false, nil)
	return &request{Request: r, attr: attr, namespace: namespace, namespaceUnknown: namespaceUnknown}, true
}

// labelsObject returns a metadata-only object carrying labels, or a nil
// interface when the labels were not supplied.
func labelsObject(l map[string]string, known bool) runtime.Object {
	if !known {
		return nil
	}
	return &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Labels: l}}
}

// filter is the outcome of one webhook filter: a definite verdict, or
// indeterminate with the reasons it could not be decided.
type filter struct {
	verdict Verdict
	reasons []Reason
}

var pass = filter{verdict: Matched}

func reject(r Reason) filter     { return filter{verdict: NotMatched, reasons: []Reason{r}} }
func unknown(r ...Reason) filter { return filter{verdict: Indeterminate, reasons: r} }

// combine applies the precedence rules: a definite rejection wins over any
// indeterminate filter, any indeterminate filter wins over a match, and only
// when every filter passes is the webhook matched. The reasons returned are
// those of the winning verdict, in filter order and without duplicates.
func combine(filters ...filter) (Verdict, []Reason) {
	var rejected, unresolved []Reason
	add := func(list []Reason, rs []Reason) []Reason {
		for _, r := range rs {
			if !slices.Contains(list, r) {
				list = append(list, r)
			}
		}
		return list
	}
	for _, f := range filters {
		switch f.verdict {
		case NotMatched:
			rejected = add(rejected, f.reasons)
		case Indeterminate:
			unresolved = add(unresolved, f.reasons)
		}
	}
	switch {
	case len(rejected) > 0:
		return NotMatched, rejected
	case len(unresolved) > 0:
		return Indeterminate, unresolved
	}
	return Matched, nil
}

func (req *request) exemption() filter {
	if req.Group == admissionRegistrationGroup {
		if req.Kind == "" {
			// The apiserver decides by kind, which was not supplied.
			return unknown(ReasonKindUnknown)
		}
		if rules.IsExemptAdmissionConfigurationResource(req.attr) {
			return reject(ReasonExemptResource)
		}
	}
	if _, ok := virtualResources[schema.GroupResource{Group: req.Group, Resource: req.Resource}]; ok {
		return unknown(ReasonVersionDependentExclusion)
	}
	return pass
}

func (w *webhook) rules(req *request) filter {
	for _, r := range w.ruleSet {
		if (&rules.Matcher{Rule: r, Attr: req.attr}).Matches() {
			return pass
		}
	}
	var reasons []Reason
	if w.equivalent {
		// Equivalent matchPolicy also tries the request's equivalent
		// group/versions, which only the apiserver's registry knows. Retry each
		// rule with group and version relaxed: a hit means the only thing
		// standing between the rule and the request is that equivalence. The
		// copy keeps the compiled rule untouched.
		for _, r := range w.ruleSet {
			r.APIGroups, r.APIVersions = []string{"*"}, []string{"*"}
			if (&rules.Matcher{Rule: r, Attr: req.attr}).Matches() {
				reasons = append(reasons, ReasonEquivalentResources)
				break
			}
		}
	}
	if w.invalidRules {
		// A rule with a value this package does not know matched nothing above,
		// but cannot be ruled out.
		reasons = append(reasons, ReasonInvalidRule)
	}
	if len(reasons) > 0 {
		return unknown(reasons...)
	}
	return reject(ReasonRulesDoNotMatch)
}

func (w *webhook) namespace(req *request) filter {
	// The apiserver never applies a namespaceSelector to a cluster-scoped
	// resource other than Namespace itself.
	if req.namespace == "" && !req.namespaceUnknown && req.Resource != namespacesResource {
		return pass
	}
	if w.namespaceErr != nil {
		return unknown(ReasonInvalidNamespaceSelector)
	}
	if w.namespaceSelector.Empty() {
		return pass
	}
	if req.namespaceUnknown {
		return unknown(ReasonNamespaceUnknown)
	}

	var matched, determinable bool
	switch {
	case req.Resource == namespacesResource && req.Name == "":
		return unknown(ReasonNamespaceLabelsUnknown)
	case req.Resource == namespacesResource && req.Subresource == "" &&
		(req.Operation == admissionregistrationv1.Create || req.Operation == admissionregistrationv1.Update):
		// The apiserver reads the labels of the Namespace being written from
		// the request object, not from storage.
		if w.kind == MutatingWebhook && req.Operation == admissionregistrationv1.Create && w.selectsNameLabel() &&
			req.ObjectLabels[corev1.LabelMetadataName] == "" {
			// The apiserver stamps kubernetes.io/metadata.name onto a new
			// Namespace when it stores it, which happens after mutating
			// admission. A mutating webhook may therefore not see the label
			// the selector asks for. This ordering is taken from the apiserver
			// handler and the namespace registry; k8s.io/kubernetes is not a
			// dependency, so it is not covered by this package's parity tests.
			return unknown(ReasonNamespaceLabelsUnknown)
		}
		matched, determinable = namespaceselector.Matches(w.namespaceSelector, req.Name, req.ObjectLabels, req.ObjectLabelsKnown)
	default:
		matched, determinable = namespaceselector.Matches(w.namespaceSelector, req.namespace, req.NamespaceLabels, req.NamespaceLabelsKnown)
	}
	switch {
	case !determinable:
		return unknown(ReasonNamespaceLabelsUnknown)
	case matched:
		return pass
	default:
		return reject(ReasonNamespaceSelectorExcludes)
	}
}

// selectsNameLabel reports whether the namespaceSelector has a requirement on
// the automatic kubernetes.io/metadata.name label.
func (w *webhook) selectsNameLabel() bool {
	requirements, _ := w.namespaceSelector.Requirements()
	for _, r := range requirements {
		if r.Key() == corev1.LabelMetadataName {
			return true
		}
	}
	return false
}

// selectorProvider adapts a parsed selector to the apiserver's
// object.ObjectSelectorProvider.
type selectorProvider struct{ labels.Selector }

func (p selectorProvider) GetParsedObjectSelector() (labels.Selector, error) { return p.Selector, nil }

func (w *webhook) object(req *request) filter {
	if w.objectErr != nil {
		return unknown(ReasonInvalidObjectSelector)
	}
	matched, err := (&object.Matcher{}).MatchObjectSelector(selectorProvider{w.objectSelector}, req.attr)
	if err != nil {
		return unknown(ReasonInvalidObjectSelector)
	}
	if matched {
		return pass
	}

	// A miss is only definite when every object the apiserver would test (new
	// and old match with OR) was supplied; a missing one may still match.
	switch req.Operation {
	case admissionregistrationv1.Create:
		if !req.ObjectLabelsKnown {
			return unknown(ReasonObjectLabelsUnknown)
		}
	case admissionregistrationv1.Update:
		if !req.ObjectLabelsKnown || !req.OldObjectLabelsKnown {
			return unknown(ReasonObjectLabelsUnknown)
		}
	case admissionregistrationv1.Delete:
		if !req.OldObjectLabelsKnown {
			return unknown(ReasonObjectLabelsUnknown)
		}
	}
	return reject(ReasonObjectSelectorExcludes)
}

func (w *webhook) match(req *request) Result {
	conditions := pass
	if w.hasMatchConditions {
		conditions = unknown(ReasonMatchConditions)
	}
	verdict, reasons := combine(req.exemption(), w.rules(req), w.namespace(req), w.object(req), conditions)
	return Result{Configuration: w.configuration, Webhook: w.name, Type: w.kind, Verdict: verdict, Reasons: reasons}
}
