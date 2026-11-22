package webhookcoverage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	create  = admissionregistrationv1.Create
	update  = admissionregistrationv1.Update
	deleteO = admissionregistrationv1.Delete
	connect = admissionregistrationv1.Connect
)

func rule(groups, versions, resources []string, ops ...admissionregistrationv1.OperationType) admissionregistrationv1.RuleWithOperations {
	return admissionregistrationv1.RuleWithOperations{
		Operations: ops,
		Rule:       admissionregistrationv1.Rule{APIGroups: groups, APIVersions: versions, Resources: resources},
	}
}

func podRule(ops ...admissionregistrationv1.OperationType) admissionregistrationv1.RuleWithOperations {
	return rule([]string{""}, []string{"v1"}, []string{"pods"}, ops...)
}

func exact() *admissionregistrationv1.MatchPolicyType {
	p := admissionregistrationv1.Exact
	return &p
}

func selector(key string, op metav1.LabelSelectorOperator, values ...string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: key, Operator: op, Values: values}}}
}

// validatingIndex builds an Index holding a single validating webhook.
func validatingIndex(w admissionregistrationv1.ValidatingWebhook) *Index {
	idx, _ := validatingIndexErrs(w)
	return idx
}

func validatingIndexErrs(w admissionregistrationv1.ValidatingWebhook) (*Index, []error) {
	w.Name = "hook"
	return NewIndex([]admissionregistrationv1.ValidatingWebhookConfiguration{{
		ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
		Webhooks:   []admissionregistrationv1.ValidatingWebhook{w},
	}}, nil)
}

func podRequest(mod func(*Request)) Request {
	r := Request{
		Version: "v1", Resource: "pods", Kind: "Pod", Operation: create, Name: "web", Namespace: "ns1",
		ObjectLabels: map[string]string{"app": "web"}, ObjectLabelsKnown: true,
		NamespaceLabels: map[string]string{"env": "prod"}, NamespaceLabelsKnown: true,
	}
	if mod != nil {
		mod(&r)
	}
	return r
}

func verdict(t *testing.T, idx *Index, req Request) Result {
	t.Helper()
	results := idx.Matches(req)
	require.Len(t, results, 1)
	return results[0]
}

func TestRules(t *testing.T) {
	tests := []struct {
		name string
		rule admissionregistrationv1.RuleWithOperations
		mod  func(*Request)
		want Verdict
	}{
		{"exact match", podRule(create), nil, Matched},
		{"wildcard group", rule([]string{"*"}, []string{"v1"}, []string{"pods"}, create), nil, Matched},
		{"version mismatch under Exact", rule([]string{""}, []string{"v1beta1"}, []string{"pods"}, create), nil, NotMatched},
		{"wildcard version", rule([]string{""}, []string{"*"}, []string{"pods"}, create), nil, Matched},
		{"resource mismatch", rule([]string{""}, []string{"v1"}, []string{"secrets"}, create), nil, NotMatched},
		{"wildcard resource", rule([]string{""}, []string{"v1"}, []string{"*"}, create), nil, Matched},
		{"bare resource does not cover a subresource", podRule(create), func(r *Request) { r.Subresource = "exec" }, NotMatched},
		{"bare wildcard does not cover a subresource", rule([]string{""}, []string{"v1"}, []string{"*"}, create), func(r *Request) { r.Subresource = "exec" }, NotMatched},
		{"subresource match", rule([]string{""}, []string{"v1"}, []string{"pods/exec"}, create), func(r *Request) { r.Subresource = "exec" }, Matched},
		{"resource with subresource wildcard", rule([]string{""}, []string{"v1"}, []string{"pods/*"}, create), func(r *Request) { r.Subresource = "exec" }, Matched},
		{"all-resources wildcard", rule([]string{""}, []string{"v1"}, []string{"*/*"}, create), func(r *Request) { r.Subresource = "exec" }, Matched},
		{"operation mismatch", podRule(update), nil, NotMatched},
		{"all operations", podRule(admissionregistrationv1.OperationAll), nil, Matched},
		{"delete", podRule(deleteO), func(r *Request) { r.Operation = deleteO; r.OldObjectLabels, r.OldObjectLabelsKnown = nil, true }, Matched},
		{"connect", rule([]string{""}, []string{"v1"}, []string{"pods/exec"}, connect), func(r *Request) { r.Operation = connect; r.Subresource = "exec" }, Matched},
		{"namespaced scope on a namespaced request", scoped(podRule(create), admissionregistrationv1.NamespacedScope), nil, Matched},
		{"cluster scope on a namespaced request", scoped(podRule(create), admissionregistrationv1.ClusterScope), nil, NotMatched},
		{"no rules", admissionregistrationv1.RuleWithOperations{}, nil, NotMatched},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
				Rules: []admissionregistrationv1.RuleWithOperations{tt.rule}, MatchPolicy: exact(),
			})
			assert.Equal(t, tt.want, verdict(t, idx, podRequest(tt.mod)).Verdict)
		})
	}
}

func scoped(r admissionregistrationv1.RuleWithOperations, s admissionregistrationv1.ScopeType) admissionregistrationv1.RuleWithOperations {
	r.Scope = &s
	return r
}

func TestMatchPolicyEquivalent(t *testing.T) {
	apps := rule([]string{"apps"}, []string{"v1"}, []string{"deployments"}, create)
	deployment := func(version string) func(*Request) {
		return func(r *Request) {
			r.Group, r.Version, r.Resource, r.Kind = "apps", version, "deployments", "Deployment"
		}
	}
	tests := []struct {
		name   string
		policy *admissionregistrationv1.MatchPolicyType
		mod    func(*Request)
		want   Verdict
		reason Reason
	}{
		{"exact rule hit needs no equivalence", nil, deployment("v1"), Matched, ""},
		{"other version is ambiguous by default", nil, deployment("v1beta1"), Indeterminate, ReasonEquivalentResources},
		{"explicit Equivalent is ambiguous", equivalent(), deployment("v1beta1"), Indeterminate, ReasonEquivalentResources},
		{"Exact rejects the other version", exact(), deployment("v1beta1"), NotMatched, ReasonRulesDoNotMatch},
		{"unrelated resource is not ambiguous", nil, func(r *Request) {}, NotMatched, ReasonRulesDoNotMatch},
		{"operation mismatch is not ambiguous", nil, func(r *Request) { deployment("v1beta1")(r); r.Operation = update }, NotMatched, ReasonRulesDoNotMatch},
		{"other group is ambiguous", nil, func(r *Request) { deployment("v1")(r); r.Group = "extensions" }, Indeterminate, ReasonEquivalentResources},
		{"other subresource is not ambiguous", nil, func(r *Request) { deployment("v1beta1")(r); r.Subresource = "scale" }, NotMatched, ReasonRulesDoNotMatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
				Rules: []admissionregistrationv1.RuleWithOperations{apps}, MatchPolicy: tt.policy,
			})
			got := verdict(t, idx, podRequest(tt.mod))
			assert.Equal(t, tt.want, got.Verdict)
			if tt.reason != "" {
				assert.Equal(t, []Reason{tt.reason}, got.Reasons)
			} else {
				assert.Empty(t, got.Reasons)
			}
		})
	}
}

func equivalent() *admissionregistrationv1.MatchPolicyType {
	p := admissionregistrationv1.Equivalent
	return &p
}

func TestNamespaceSelector(t *testing.T) {
	prod := selector("env", metav1.LabelSelectorOpIn, "prod")
	tests := []struct {
		name   string
		sel    *metav1.LabelSelector
		mod    func(*Request)
		want   Verdict
		reason Reason
	}{
		{"unset selector", nil, nil, Matched, ""},
		{"empty selector", &metav1.LabelSelector{}, func(r *Request) { r.NamespaceLabelsKnown = false }, Matched, ""},
		{"selector matches", prod, nil, Matched, ""},
		{"selector does not match", prod, func(r *Request) { r.NamespaceLabels = map[string]string{"env": "dev"} }, NotMatched, ""},
		{"NotIn excludes", selector("env", metav1.LabelSelectorOpNotIn, "prod"), nil, NotMatched, ""},
		{"DoesNotExist satisfied by known empty labels", selector("env", metav1.LabelSelectorOpDoesNotExist), func(r *Request) { r.NamespaceLabels = nil }, Matched, ""},
		{"DoesNotExist is not assumed for unknown labels", selector("env", metav1.LabelSelectorOpDoesNotExist), func(r *Request) { r.NamespaceLabelsKnown = false }, Indeterminate, ReasonNamespaceLabelsUnknown},
		{"unknown labels", prod, func(r *Request) { r.NamespaceLabelsKnown = false }, Indeterminate, ReasonNamespaceLabelsUnknown},
		{"automatic name label is inferred", &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "ns1"}}, func(r *Request) { r.NamespaceLabelsKnown = false }, Matched, ""},
		{"wrong name label rejects without labels", &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "other"}}, func(r *Request) { r.NamespaceLabelsKnown = false }, NotMatched, ""},
		{"cluster-scoped resource is never filtered", prod, func(r *Request) {
			r.Resource, r.Namespace, r.ClusterScoped, r.NamespaceLabelsKnown = "nodes", "", true, false
		}, Matched, ""},
		{"namespaced request without a namespace is not cluster-scoped", prod, func(r *Request) { r.Namespace, r.NamespaceLabelsKnown = "", false }, Indeterminate, ReasonNamespaceUnknown},
		{"namespaced request without a namespace, empty selector", &metav1.LabelSelector{}, func(r *Request) { r.Namespace = "" }, Matched, ""},
		{"selector excludes, with a reason", prod, func(r *Request) { r.NamespaceLabels = map[string]string{"env": "dev"} }, NotMatched, ReasonNamespaceSelectorExcludes},
		{"malformed selector", selector("env", metav1.LabelSelectorOpIn), nil, Indeterminate, ReasonInvalidNamespaceSelector},
		{"Namespace create uses object labels", prod, func(r *Request) {
			r.Resource, r.Kind, r.Name, r.Namespace = "namespaces", "Namespace", "new", ""
			r.ObjectLabels, r.NamespaceLabels = map[string]string{"env": "prod"}, map[string]string{"env": "dev"}
		}, Matched, ""},
		{"Namespace delete uses stored labels", prod, func(r *Request) {
			r.Resource, r.Kind, r.Name, r.Namespace, r.Operation = "namespaces", "Namespace", "old", "", deleteO
			r.OldObjectLabelsKnown = true
			r.ObjectLabels = map[string]string{"env": "prod"}
			r.NamespaceLabels = map[string]string{"env": "dev"}
		}, NotMatched, ""},
		{"Namespace without a name", prod, func(r *Request) {
			r.Resource, r.Kind, r.Name, r.Namespace = "namespaces", "Namespace", "", ""
		}, Indeterminate, ReasonNamespaceLabelsUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := []admissionregistrationv1.RuleWithOperations{
				rule([]string{"*"}, []string{"*"}, []string{"*"}, admissionregistrationv1.OperationAll),
			}
			idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: rules, NamespaceSelector: tt.sel, MatchPolicy: exact()})
			got := verdict(t, idx, podRequest(tt.mod))
			assert.Equal(t, tt.want, got.Verdict)
			if tt.reason != "" {
				assert.Equal(t, []Reason{tt.reason}, got.Reasons)
			}
		})
	}
}

func TestObjectSelector(t *testing.T) {
	web := selector("app", metav1.LabelSelectorOpIn, "web")
	notWeb := selector("app", metav1.LabelSelectorOpNotIn, "web")
	noApp := selector("app", metav1.LabelSelectorOpDoesNotExist)
	labelled := map[string]string{"app": "web"}
	other := map[string]string{"app": "db"}

	tests := []struct {
		name string
		sel  *metav1.LabelSelector
		mod  func(*Request)
		want Verdict
	}{
		{"unset selector never needs labels", nil, func(r *Request) { r.ObjectLabelsKnown = false }, Matched},
		{"create matches", web, nil, Matched},
		{"create does not match", web, func(r *Request) { r.ObjectLabels = other }, NotMatched},
		{"NotIn matches other labels", notWeb, func(r *Request) { r.ObjectLabels = other }, Matched},
		{"NotIn excludes", notWeb, nil, NotMatched},
		{"DoesNotExist matches known unlabelled object", noApp, func(r *Request) { r.ObjectLabels = nil }, Matched},
		{"DoesNotExist is not assumed for an unsupplied object", noApp, func(r *Request) { r.ObjectLabelsKnown = false }, Indeterminate},
		{"create with unsupplied labels", web, func(r *Request) { r.ObjectLabelsKnown = false }, Indeterminate},
		{"create ignores old labels", web, func(r *Request) { r.ObjectLabels, r.OldObjectLabels, r.OldObjectLabelsKnown = other, labelled, true }, NotMatched},
		{"update matches on new", web, func(r *Request) { r.Operation = update; r.OldObjectLabels, r.OldObjectLabelsKnown = other, true }, Matched},
		{"update matches on old only", web, func(r *Request) {
			r.Operation, r.ObjectLabels, r.OldObjectLabels, r.OldObjectLabelsKnown = update, other, labelled, true
		}, Matched},
		{"update misses on both", web, func(r *Request) {
			r.Operation, r.ObjectLabels, r.OldObjectLabels, r.OldObjectLabelsKnown = update, other, other, true
		}, NotMatched},
		{"update miss with unsupplied old object", web, func(r *Request) { r.Operation, r.ObjectLabels = update, other }, Indeterminate},
		{"update match with unsupplied old object", web, func(r *Request) { r.Operation = update }, Matched},
		{"update NotIn miss with unsupplied old object", notWeb, func(r *Request) { r.Operation = update }, Indeterminate},
		{"delete matches on old object", web, func(r *Request) {
			r.Operation, r.ObjectLabelsKnown, r.OldObjectLabels, r.OldObjectLabelsKnown = deleteO, false, labelled, true
		}, Matched},
		{"delete ignores the new object", web, func(r *Request) {
			r.Operation, r.OldObjectLabels, r.OldObjectLabelsKnown = deleteO, other, true
		}, NotMatched},
		{"delete with unsupplied old object", web, func(r *Request) { r.Operation = deleteO }, Indeterminate},
		{"connect never matches a selector", web, func(r *Request) { r.Operation = connect; r.Subresource = "exec" }, NotMatched},
		{"connect never matches DoesNotExist", noApp, func(r *Request) { r.Operation, r.ObjectLabelsKnown = connect, false }, NotMatched},
		{"connect without selector", nil, func(r *Request) { r.Operation = connect }, Matched},
		{"malformed selector", selector("app", metav1.LabelSelectorOpIn), nil, Indeterminate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := []admissionregistrationv1.RuleWithOperations{
				rule([]string{""}, []string{"v1"}, []string{"pods", "pods/exec"}, admissionregistrationv1.OperationAll),
			}
			idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: rules, ObjectSelector: tt.sel, MatchPolicy: exact()})
			got := verdict(t, idx, podRequest(tt.mod))
			assert.Equal(t, tt.want, got.Verdict)
			if tt.want == Indeterminate {
				assert.NotEmpty(t, got.Reasons)
			}
		})
	}
}

func TestAdmissionConfigurationExemption(t *testing.T) {
	all := []admissionregistrationv1.RuleWithOperations{
		rule([]string{"*"}, []string{"*"}, []string{"*"}, admissionregistrationv1.OperationAll),
	}
	idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: all, MatchPolicy: exact()})
	reg := func(resource, kind string) func(*Request) {
		return func(r *Request) {
			r.Group, r.Resource, r.Kind, r.Namespace, r.ClusterScoped, r.Name = "admissionregistration.k8s.io", resource, kind, "", true, "x"
		}
	}

	for resource, kind := range map[string]string{
		"validatingwebhookconfigurations":   "ValidatingWebhookConfiguration",
		"mutatingwebhookconfigurations":     "MutatingWebhookConfiguration",
		"validatingadmissionpolicies":       "ValidatingAdmissionPolicy",
		"validatingadmissionpolicybindings": "ValidatingAdmissionPolicyBinding",
		"mutatingadmissionpolicies":         "MutatingAdmissionPolicy",
		"mutatingadmissionpolicybindings":   "MutatingAdmissionPolicyBinding",
	} {
		t.Run(resource, func(t *testing.T) {
			got := verdict(t, idx, podRequest(reg(resource, kind)))
			assert.Equal(t, NotMatched, got.Verdict)
			assert.Equal(t, []Reason{ReasonExemptResource}, got.Reasons)
		})
	}

	t.Run("other kinds in the group are not exempt", func(t *testing.T) {
		assert.Equal(t, Matched, verdict(t, idx, podRequest(reg("somethingelse", "Something"))).Verdict)
	})
	t.Run("missing kind is indeterminate", func(t *testing.T) {
		got := verdict(t, idx, podRequest(reg("validatingwebhookconfigurations", "")))
		assert.Equal(t, Indeterminate, got.Verdict)
		assert.Equal(t, []Reason{ReasonKindUnknown}, got.Reasons)
	})
	t.Run("kind is irrelevant outside the group", func(t *testing.T) {
		assert.Equal(t, Matched, verdict(t, idx, podRequest(func(r *Request) { r.Kind = "ValidatingWebhookConfiguration" })).Verdict)
	})
	t.Run("review resources depend on the apiserver version", func(t *testing.T) {
		got := verdict(t, idx, podRequest(func(r *Request) {
			r.Group, r.Resource, r.Kind, r.Namespace, r.ClusterScoped = "authorization.k8s.io", "subjectaccessreviews", "SubjectAccessReview", "", true
		}))
		assert.Equal(t, Indeterminate, got.Verdict)
		assert.Equal(t, []Reason{ReasonVersionDependentExclusion}, got.Reasons)
	})
}

func TestPrecedenceAndReasons(t *testing.T) {
	prod := selector("env", metav1.LabelSelectorOpIn, "prod")
	unknownNS := func(r *Request) { r.NamespaceLabelsKnown = false }

	t.Run("definite rule rejection beats unknown namespace labels", func(t *testing.T) {
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
			Rules:             []admissionregistrationv1.RuleWithOperations{rule([]string{""}, []string{"v1"}, []string{"secrets"}, create)},
			NamespaceSelector: prod, MatchPolicy: exact(),
		})
		assert.Equal(t, NotMatched, verdict(t, idx, podRequest(unknownNS)).Verdict)
	})
	t.Run("definite namespace rejection beats matchConditions and equivalence", func(t *testing.T) {
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
			Rules:             []admissionregistrationv1.RuleWithOperations{rule([]string{"apps"}, []string{"v1"}, []string{"pods"}, create)},
			NamespaceSelector: prod, MatchConditions: []admissionregistrationv1.MatchCondition{{Name: "c", Expression: "true"}},
		})
		assert.Equal(t, NotMatched, verdict(t, idx, podRequest(func(r *Request) { r.NamespaceLabels = map[string]string{"env": "dev"} })).Verdict)
	})
	t.Run("definite object rejection beats unknown namespace labels", func(t *testing.T) {
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
			Rules: []admissionregistrationv1.RuleWithOperations{podRule(create)}, NamespaceSelector: prod,
			ObjectSelector: selector("app", metav1.LabelSelectorOpIn, "db"), MatchPolicy: exact(),
		})
		assert.Equal(t, NotMatched, verdict(t, idx, podRequest(unknownNS)).Verdict)
	})
	t.Run("matchConditions keep an otherwise matching webhook indeterminate", func(t *testing.T) {
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
			Rules: []admissionregistrationv1.RuleWithOperations{podRule(create)}, MatchPolicy: exact(),
			MatchConditions: []admissionregistrationv1.MatchCondition{{Name: "c", Expression: "true"}},
		})
		got := verdict(t, idx, podRequest(nil))
		assert.Equal(t, Indeterminate, got.Verdict)
		assert.Equal(t, []Reason{ReasonMatchConditions}, got.Reasons)
	})
	t.Run("every unresolved filter is reported once, in order", func(t *testing.T) {
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
			Rules:             []admissionregistrationv1.RuleWithOperations{rule([]string{"apps"}, []string{"v1"}, []string{"pods"}, create)},
			NamespaceSelector: prod, ObjectSelector: selector("app", metav1.LabelSelectorOpIn, "web"),
			MatchConditions: []admissionregistrationv1.MatchCondition{{Name: "c", Expression: "true"}},
		})
		got := verdict(t, idx, podRequest(func(r *Request) { r.NamespaceLabelsKnown, r.ObjectLabelsKnown = false, false }))
		assert.Equal(t, Indeterminate, got.Verdict)
		assert.Equal(t, []Reason{ReasonEquivalentResources, ReasonNamespaceLabelsUnknown, ReasonObjectLabelsUnknown, ReasonMatchConditions}, got.Reasons)
	})
}

func TestIncompleteRequest(t *testing.T) {
	idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
		Rules: []admissionregistrationv1.RuleWithOperations{podRule(create)}, MatchPolicy: exact(),
	})
	for name, mod := range map[string]func(*Request){
		"no operation":      func(r *Request) { r.Operation = "" },
		"OperationAll":      func(r *Request) { r.Operation = admissionregistrationv1.OperationAll },
		"unknown operation": func(r *Request) { r.Operation = "PATCH" },
		"no version":        func(r *Request) { r.Version = "" },
		"no resource":       func(r *Request) { r.Resource = "" },
	} {
		t.Run(name, func(t *testing.T) {
			got := verdict(t, idx, podRequest(mod))
			assert.Equal(t, Indeterminate, got.Verdict)
			assert.Equal(t, []Reason{ReasonIncompleteRequest}, got.Reasons)
		})
	}
}

func TestIndexOrderingAndTypes(t *testing.T) {
	hook := func(name string, resources ...string) admissionregistrationv1.ValidatingWebhook {
		return admissionregistrationv1.ValidatingWebhook{
			Name: name, MatchPolicy: exact(),
			Rules: []admissionregistrationv1.RuleWithOperations{rule([]string{""}, []string{"v1"}, resources, create)},
		}
	}
	mutating := admissionregistrationv1.MutatingWebhook{
		Name: "m1", MatchPolicy: exact(),
		Rules: []admissionregistrationv1.RuleWithOperations{podRule(create)},
	}
	idx, errs := NewIndex(
		[]admissionregistrationv1.ValidatingWebhookConfiguration{
			{ObjectMeta: metav1.ObjectMeta{Name: "v-b"}, Webhooks: []admissionregistrationv1.ValidatingWebhook{hook("b1", "pods"), hook("b2", "secrets")}},
			{ObjectMeta: metav1.ObjectMeta{Name: "v-a"}, Webhooks: []admissionregistrationv1.ValidatingWebhook{hook("a1", "pods")}},
		},
		[]admissionregistrationv1.MutatingWebhookConfiguration{
			{ObjectMeta: metav1.ObjectMeta{Name: "m-a"}, Webhooks: []admissionregistrationv1.MutatingWebhook{mutating}},
		})

	want := []Result{
		{Configuration: "v-b", Webhook: "b1", Type: ValidatingWebhook, Verdict: Matched},
		{Configuration: "v-b", Webhook: "b2", Type: ValidatingWebhook, Verdict: NotMatched, Reasons: []Reason{ReasonRulesDoNotMatch}},
		{Configuration: "v-a", Webhook: "a1", Type: ValidatingWebhook, Verdict: Matched},
		{Configuration: "m-a", Webhook: "m1", Type: MutatingWebhook, Verdict: Matched},
	}
	assert.Empty(t, errs)
	for range 3 { // deterministic across repeated queries
		assert.Equal(t, want, idx.Matches(podRequest(nil)))
	}
}

func TestEmptyIndex(t *testing.T) {
	idx, errs := NewIndex(nil, nil)
	assert.Empty(t, errs)
	assert.Empty(t, idx.Matches(podRequest(nil)))
	idx, errs = NewIndex([]admissionregistrationv1.ValidatingWebhookConfiguration{{}}, []admissionregistrationv1.MutatingWebhookConfiguration{{}})
	assert.Empty(t, errs)
	assert.Empty(t, idx.Matches(podRequest(nil)))
}

func TestRequestIsNotModified(t *testing.T) {
	idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
		Rules: []admissionregistrationv1.RuleWithOperations{rule([]string{"apps"}, []string{"v1"}, []string{"pods"}, create)},
	})
	req := podRequest(nil)
	before := podRequest(nil)
	idx.Matches(req)
	assert.Equal(t, before, req)
	// The relaxed equivalence probe must not leak into the compiled rules.
	assert.Equal(t, []string{"apps"}, idx.webhooks[0].ruleSet[0].APIGroups)
}
