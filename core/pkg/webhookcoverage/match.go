package webhookcoverage

import (
	"slices"
	"strings"

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

const admissionRegistrationGroup = "admissionregistration.k8s.io"

// namespaceGVR is the core Namespace resource. The apiserver's scope predicate
// identifies a Namespace by this complete GroupVersionResource, not by the
// resource name alone.
var namespaceGVR = schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}

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
	// clusterAttr is the same request taken as cluster-scoped, set only when the
	// resource scope is unknown. attr then carries unknownNamespace, which is
	// the namespaced reading.
	clusterAttr admission.Attributes
	// namespace is what the apiserver reports as the request's namespace: the
	// object's own name for a Namespace, empty for other cluster-scoped objects
	// and when the namespace of a namespaced request is unknown.
	namespace string
	// namespaceUnknown is set for a namespaced request that names no namespace.
	namespaceUnknown bool
	// isNamespace is set for the core Namespace resource only: a resource of
	// another group that happens to be called "namespaces" is not one.
	isNamespace bool
	// scopeUnknown is set when the caller does not know whether the resource is
	// namespaced.
	scopeUnknown bool
}

// validOperation reports whether op is one an admission request can carry.
func validOperation(op admissionregistrationv1.OperationType) bool {
	switch op {
	case admissionregistrationv1.Create, admissionregistrationv1.Update,
		admissionregistrationv1.Delete, admissionregistrationv1.Connect:
		return true
	}
	return false
}

// unknownNamespace stands in for the namespace of a namespaced request that
// names none. Only the rule predicate's scope check reads it, to tell a
// namespaced request from a cluster-scoped one; no label or selector ever sees
// it.
const unknownNamespace = "namespace-not-supplied"

func newRequest(r Request) (*request, bool) {
	if !validOperation(r.Operation) {
		return nil, false
	}
	if r.Version == "" || r.Resource == "" {
		return nil, false
	}
	isNamespace := schema.GroupVersionResource{Group: r.Group, Version: r.Version, Resource: r.Resource} == namespaceGVR
	if r.ClusterScoped && r.Namespace != "" && !isNamespace {
		return nil, false
	}
	if r.ClusterScoped && r.ScopeUnknown && !isNamespace {
		// The caller claims to know and not to know the scope.
		return nil, false
	}
	// A namespace name, or the Namespace resource itself, settles the scope.
	scopeUnknown := r.ScopeUnknown && !isNamespace && r.Namespace == "" && !r.ClusterScoped

	namespace := r.Namespace
	if isNamespace {
		namespace = r.Name
	}
	namespaceUnknown := !isNamespace && r.Namespace == "" && !r.ClusterScoped && !scopeUnknown
	attrNamespace := namespace
	if namespaceUnknown || scopeUnknown {
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

	newAttr := func(ns string) admission.Attributes {
		return admission.NewAttributesRecord(obj, old,
			schema.GroupVersionKind{Group: r.Group, Version: r.Version, Kind: r.Kind},
			ns, r.Name,
			schema.GroupVersionResource{Group: r.Group, Version: r.Version, Resource: r.Resource},
			r.Subresource, admission.Operation(r.Operation), nil, false, nil)
	}
	req := &request{Request: r, attr: newAttr(attrNamespace), namespace: namespace,
		namespaceUnknown: namespaceUnknown, isNamespace: isNamespace, scopeUnknown: scopeUnknown}
	if scopeUnknown {
		req.clusterAttr = newAttr("")
	}
	return req, true
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

// readings are the attributes the rule predicate is run against: the request
// itself, and also its cluster-scoped reading when the resource scope is
// unknown.
func (req *request) readings() []admission.Attributes {
	if req.clusterAttr != nil {
		return []admission.Attributes{req.attr, req.clusterAttr}
	}
	return []admission.Attributes{req.attr}
}

func (w *webhook) rules(req *request) filter {
	var reasons []Reason
	// covered[i] is whether some rule matches reading i. With an unknown scope
	// the webhook is matched only if every reading is covered, though not
	// necessarily by the same rule.
	readings := req.readings()
	covered := make([]bool, len(readings))
	nCovered := 0
	for _, r := range w.ruleSet {
		for i, attr := range readings {
			if !covered[i] && (&rules.Matcher{Rule: r, Attr: attr}).Matches() {
				covered[i] = true
				nCovered++
			}
		}
	}
	if nCovered == len(readings) {
		return pass
	}
	scopeDependent := nCovered > 0
	if scopeDependent {
		// Some rule matches the request only if the resource is of one scope.
		reasons = append(reasons, ReasonResourceScopeUnknown)
	}
	if w.equivalent && w.equivalentMatch(req) {
		// Equivalent matchPolicy also tries the resources the apiserver's
		// equivalent-resource registry lists for the request, which this
		// package cannot see. A hit on the relaxed rule (see
		// relaxForEquivalence) means the only thing standing between the rule
		// and the request is that equivalence.
		reasons = append(reasons, ReasonEquivalentResources)
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

// equivalentMatch reports whether some rule could match the request through a
// resource the apiserver's equivalent-resource registry might list for it.
func (w *webhook) equivalentMatch(req *request) bool {
	for _, r := range w.ruleSet {
		for _, attr := range req.readings() {
			if equivalentRuleMatches(r, attr) {
				return true
			}
		}
	}
	return false
}

// candidateAttributes is a request re-targeted at an equivalent resource; as in
// the apiserver, the operation, subresource and namespace stay.
type candidateAttributes struct {
	admission.Attributes
	resource schema.GroupVersionResource
}

func (a candidateAttributes) GetResource() schema.GroupVersionResource { return a.resource }

// equivalentRuleMatches reports whether rule r could match attr through an
// equivalent resource. The scope check reads only the resource and the
// namespace, and the namespace is the request's own, so it is evaluated here
// rather than relaxed:
//   - a Namespaced rule fails every candidate when the namespace is empty, and
//     passes every candidate other than the core Namespace otherwise;
//   - a Cluster rule passes every candidate when the namespace is empty, and
//     otherwise only the core Namespace, which the predicate treats as
//     cluster-scoped.
func equivalentRuleMatches(r admissionregistrationv1.RuleWithOperations, attr admission.Attributes) bool {
	if r.Scope != nil {
		switch *r.Scope {
		case admissionregistrationv1.NamespacedScope:
			if attr.GetNamespace() == "" {
				return false
			}
		case admissionregistrationv1.ClusterScope:
			if attr.GetNamespace() != "" {
				return (&rules.Matcher{Rule: r, Attr: candidateAttributes{attr, namespaceGVR}}).Matches()
			}
		}
	}
	return (&rules.Matcher{Rule: relaxForEquivalence(r), Attr: attr}).Matches()
}

// relaxForEquivalence returns a copy of r that matches every resource the
// apiserver could consider equivalent to a request, and only those. With
// matchPolicy Equivalent the apiserver re-runs the rules against each
// equivalent resource of the request, keeping the operation and the
// subresource, so those two stay as written.
//
// Group, version and resource name are all relaxed. The apiserver's registry
// groups resources by storage location (the etcd prefix, via
// NewEquivalentResourceRegistryWithIdentity), and a kube-apiserver can
// cohabit resources of different groups with AddCohabitatingResources, which
// does not require them to share a plural name. The scope is dropped because
// equivalentRuleMatches has already settled it. The input is left untouched.
func relaxForEquivalence(r admissionregistrationv1.RuleWithOperations) admissionregistrationv1.RuleWithOperations {
	r = relaxResources(r)
	r.APIGroups, r.APIVersions, r.Scope = []string{"*"}, []string{"*"}, nil
	return r
}

// relaxResources returns a copy of r that matches any resource name while
// keeping each rule resource's subresource.
func relaxResources(r admissionregistrationv1.RuleWithOperations) admissionregistrationv1.RuleWithOperations {
	resources := make([]string, 0, len(r.Resources))
	for _, res := range r.Resources {
		if _, sub, found := strings.Cut(res, "/"); found {
			resources = append(resources, "*/"+sub)
		} else {
			resources = append(resources, "*")
		}
	}
	r.Resources = resources
	return r
}

func (w *webhook) namespace(req *request) filter {
	// The apiserver never applies a namespaceSelector to a cluster-scoped
	// resource other than Namespace itself.
	if req.namespace == "" && !req.namespaceUnknown && !req.scopeUnknown && !req.isNamespace {
		return pass
	}
	if w.namespaceErr != nil {
		return unknown(ReasonInvalidNamespaceSelector)
	}
	if w.namespaceSelector.Empty() {
		return pass
	}
	if req.scopeUnknown {
		// A cluster-scoped resource is never filtered and a namespaced one is,
		// so the selector's effect depends on the scope.
		return unknown(ReasonResourceScopeUnknown)
	}
	if req.namespaceUnknown {
		return unknown(ReasonNamespaceUnknown)
	}

	var matched, determinable bool
	switch {
	case req.isNamespace && req.Subresource == "" &&
		(req.Operation == admissionregistrationv1.Create || req.Operation == admissionregistrationv1.Update):
		// The apiserver reads the labels of the Namespace being written from
		// the request object, not from storage. The name is not needed for
		// that: a Namespace created with generateName has its labels before it
		// has a name.
		return w.namespaceObjectLabels(req)
	case req.isNamespace && req.Name == "":
		return unknown(ReasonNamespaceLabelsUnknown)
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

// namespaceObjectLabels matches the namespaceSelector against the labels of the
// Namespace being created or updated, exactly as supplied: the name of the
// request is never added to them. Every requirement is evaluated, so a
// requirement that definitely fails rejects the request even when another one
// cannot be decided.
func (w *webhook) namespaceObjectLabels(req *request) filter {
	if !req.ObjectLabelsKnown {
		// Whatever the map holds, it was not supplied as the object's labels.
		return unknown(ReasonNamespaceLabelsUnknown)
	}
	requirements, selectable := w.namespaceSelector.Requirements()
	if !selectable {
		return reject(ReasonNamespaceSelectorExcludes)
	}
	set := labels.Set(req.ObjectLabels)
	unresolved := false
	for _, r := range requirements {
		if r.Key() == corev1.LabelMetadataName && req.ObjectLabels[corev1.LabelMetadataName] == "" {
			// UNVERIFIED PREMISE, so a requirement on the label stays
			// undecided while the object lacks it, for CREATE and UPDATE, and
			// for validating and mutating webhooks alike.
			//
			// Verified in k8s.io/apiserver v0.37.2:
			//   - the namespace matcher reads only the new object's labels
			//     (predicates/namespace/matcher.go, GetNamespaceLabels);
			//   - a create runs mutating admission (endpoints/handlers/create.go)
			//     before the store's BeforeCreate/PrepareForCreate and runs
			//     validating admission after them (registry/generic/registry/
			//     store.go, registry/rest/create.go);
			//   - an update runs mutating admission as a transformer inside
			//     UpdatedObject (endpoints/handlers/update.go), before the
			//     store's BeforeUpdate/PrepareForUpdate, and validating
			//     admission after them (registry/generic/registry/store.go);
			//   - nothing in k8s.io/apiserver mentions kubernetes.io/metadata.name.
			//
			// NOT verified: that the object the matcher sees carries the
			// label. For a create, that depends on the Namespace registry in
			// k8s.io/kubernetes adding it; for an update, on the request body
			// or patch keeping it and on that registry restoring it. That code
			// is not a dependency and was not checked. A caller who knows the
			// label is present sets it in ObjectLabels, which is then taken as
			// authoritative.
			unresolved = true
			continue
		}
		if !r.Matches(set) {
			return reject(ReasonNamespaceSelectorExcludes)
		}
	}
	if unresolved {
		return unknown(ReasonNamespaceLabelsUnknown)
	}
	return pass
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

// matchIncomplete answers for a request newRequest rejected. Missing or
// contradictory parts of the request do not undo a definite exclusion: the
// webhook is NotMatched when none of its rules could match the request
// whatever the missing parts are, and Indeterminate otherwise.
func (w *webhook) matchIncomplete(req Request) Result {
	res := Result{Configuration: w.configuration, Webhook: w.name, Type: w.kind,
		Verdict: Indeterminate, Reasons: []Reason{ReasonIncompleteRequest}}
	if w.invalidRules || w.couldMatchIncomplete(req) {
		return res
	}
	res.Verdict, res.Reasons = NotMatched, []Reason{ReasonRulesDoNotMatch}
	return res
}

// couldMatchIncomplete reports whether some rule could match req for some
// value of the parts it lacks. Each missing part is relaxed in a copy of the
// rule, which is then run through the apiserver's predicate against what the
// request does say. The scope is relaxed too, since it depends on the resource
// and the namespace, either of which may be what is missing or contradictory.
// Under matchPolicy Equivalent the group, version and resource are relaxed as
// well, as for a complete request.
func (w *webhook) couldMatchIncomplete(req Request) bool {
	attr := admission.NewAttributesRecord(nil, nil,
		schema.GroupVersionKind{Group: req.Group, Version: req.Version, Kind: req.Kind},
		req.Namespace, req.Name,
		schema.GroupVersionResource{Group: req.Group, Version: req.Version, Resource: req.Resource},
		req.Subresource, admission.Operation(req.Operation), nil, false, nil)
	for _, r := range w.ruleSet {
		r = *r.DeepCopy()
		r.Scope = nil
		if !validOperation(req.Operation) && len(r.Operations) > 0 {
			r.Operations = []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll}
		}
		if req.Version == "" {
			r.APIVersions = []string{"*"}
		}
		if req.Resource == "" {
			r = relaxResources(r)
		}
		if w.equivalent {
			r = relaxForEquivalence(r)
		}
		if (&rules.Matcher{Rule: r, Attr: attr}).Matches() {
			return true
		}
	}
	return false
}
