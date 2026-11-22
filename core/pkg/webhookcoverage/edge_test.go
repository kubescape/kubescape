package webhookcoverage

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func mutatingIndex(w admissionregistrationv1.MutatingWebhook) *Index {
	w.Name = "hook"
	idx, _ := NewIndex(nil, []admissionregistrationv1.MutatingWebhookConfiguration{{
		ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
		Webhooks:   []admissionregistrationv1.MutatingWebhook{w},
	}})
	return idx
}

func TestNotMatchedReportsEveryRejectingFilter(t *testing.T) {
	idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
		Rules:             []admissionregistrationv1.RuleWithOperations{podRule(update)},
		NamespaceSelector: selector("env", metav1.LabelSelectorOpIn, "dev"),
		ObjectSelector:    selector("app", metav1.LabelSelectorOpIn, "db"),
		MatchPolicy:       exact(),
		MatchConditions:   []admissionregistrationv1.MatchCondition{{Name: "c", Expression: "true"}},
	})
	got := verdict(t, idx, podRequest(nil))
	assert.Equal(t, NotMatched, got.Verdict)
	assert.Equal(t, []Reason{ReasonRulesDoNotMatch, ReasonNamespaceSelectorExcludes, ReasonObjectSelectorExcludes}, got.Reasons,
		"every rejecting filter is listed, and unresolved ones (matchConditions) are not")
}

func TestMatchedHasNoReasons(t *testing.T) {
	idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
		Rules: []admissionregistrationv1.RuleWithOperations{podRule(create)}, MatchPolicy: exact(),
	})
	got := verdict(t, idx, podRequest(nil))
	assert.Equal(t, Matched, got.Verdict)
	assert.Nil(t, got.Reasons)
}

func TestNamespacedRequestWithoutNamespace(t *testing.T) {
	prod := selector("env", metav1.LabelSelectorOpIn, "prod")
	noNS := func(r *Request) { r.Namespace, r.NamespaceLabelsKnown = "", false }
	hook := func(r admissionregistrationv1.RuleWithOperations, sel *metav1.LabelSelector) *Index {
		return validatingIndex(admissionregistrationv1.ValidatingWebhook{
			Rules: []admissionregistrationv1.RuleWithOperations{r}, NamespaceSelector: sel, MatchPolicy: exact(),
		})
	}

	t.Run("a missing namespace is never taken as cluster-scoped for the selector", func(t *testing.T) {
		got := verdict(t, hook(podRule(create), prod), podRequest(noNS))
		assert.Equal(t, Indeterminate, got.Verdict)
		assert.Equal(t, []Reason{ReasonNamespaceUnknown}, got.Reasons)
	})
	t.Run("a Namespaced-scope rule still covers it", func(t *testing.T) {
		got := verdict(t, hook(scoped(podRule(create), admissionregistrationv1.NamespacedScope), nil), podRequest(noNS))
		assert.Equal(t, Matched, got.Verdict)
	})
	t.Run("a Cluster-scope rule does not cover a namespaced resource", func(t *testing.T) {
		got := verdict(t, hook(scoped(podRule(create), admissionregistrationv1.ClusterScope), nil), podRequest(noNS))
		assert.Equal(t, NotMatched, got.Verdict)
		assert.Equal(t, []Reason{ReasonRulesDoNotMatch}, got.Reasons)
	})
	t.Run("a definite rule rejection beats the unknown namespace", func(t *testing.T) {
		secrets := rule([]string{""}, []string{"v1"}, []string{"secrets"}, create)
		assert.Equal(t, NotMatched, verdict(t, hook(secrets, prod), podRequest(noNS)).Verdict)
	})
	t.Run("a ClusterScoped request that names a namespace contradicts itself", func(t *testing.T) {
		got := verdict(t, hook(podRule(create), nil), podRequest(func(r *Request) { r.ClusterScoped = true }))
		assert.Equal(t, Indeterminate, got.Verdict)
		assert.Equal(t, []Reason{ReasonIncompleteRequest}, got.Reasons)
	})
	t.Run("a Namespace is identified by name, not by ClusterScoped", func(t *testing.T) {
		nsReq := func(r *Request) {
			r.Resource, r.Kind, r.Name, r.Namespace, r.ClusterScoped = "namespaces", "Namespace", "ns1", "", false
			r.ObjectLabels = map[string]string{"env": "prod"}
		}
		got := verdict(t, hook(rule([]string{""}, []string{"v1"}, []string{"namespaces"}, create), prod), podRequest(nsReq))
		assert.Equal(t, Matched, got.Verdict, "labels come from the Namespace object's own labels")
	})
}

func TestMutatingWebhooksFollowTheSameRules(t *testing.T) {
	web := selector("app", metav1.LabelSelectorOpIn, "web")
	all := []admissionregistrationv1.RuleWithOperations{
		rule([]string{""}, []string{"v1"}, []string{"pods", "pods/exec"}, admissionregistrationv1.OperationAll),
	}
	tests := []struct {
		name string
		mod  func(*Request)
		want Verdict
	}{
		{"create matches", nil, Matched},
		{"connect never matches an objectSelector", func(r *Request) { r.Operation, r.Subresource = connect, "exec" }, NotMatched},
		{"delete tests the old object", func(r *Request) {
			r.Operation, r.ObjectLabelsKnown, r.OldObjectLabels, r.OldObjectLabelsKnown = deleteO, false, map[string]string{"app": "web"}, true
		}, Matched},
		{"delete without the old object", func(r *Request) { r.Operation, r.ObjectLabelsKnown = deleteO, false }, Indeterminate},
		{"update miss with an unsupplied old object", func(r *Request) { r.Operation, r.ObjectLabels = update, map[string]string{"app": "db"} }, Indeterminate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx := mutatingIndex(admissionregistrationv1.MutatingWebhook{Rules: all, ObjectSelector: web, MatchPolicy: exact()})
			got := verdict(t, idx, podRequest(tt.mod))
			assert.Equal(t, tt.want, got.Verdict)
			assert.Equal(t, MutatingWebhook, got.Type)
		})
	}
}

// Whether a Namespace being created or updated carries the automatic
// kubernetes.io/metadata.name label is not verified, so a selector on it is
// indeterminate unless the caller supplies the label.
func TestNamespaceCreateAndTheAutomaticNameLabel(t *testing.T) {
	byName := &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "new"}}
	rules := []admissionregistrationv1.RuleWithOperations{rule([]string{""}, []string{"v1"}, []string{"namespaces", "namespaces/status"}, admissionregistrationv1.OperationAll)}
	nsReq := func(op admissionregistrationv1.OperationType, labels map[string]string) func(*Request) {
		return func(r *Request) {
			r.Resource, r.Kind, r.Name, r.Namespace, r.Operation = "namespaces", "Namespace", "new", "", op
			r.ObjectLabels, r.ObjectLabelsKnown = labels, true
			r.OldObjectLabels, r.OldObjectLabelsKnown = map[string]string{"kubernetes.io/metadata.name": "new"}, true
			r.NamespaceLabelsKnown = false
		}
	}
	hooks := map[string]*Index{
		"validating": validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: rules, NamespaceSelector: byName, MatchPolicy: exact()}),
		"mutating":   mutatingIndex(admissionregistrationv1.MutatingWebhook{Rules: rules, NamespaceSelector: byName, MatchPolicy: exact()}),
	}
	for kind, idx := range hooks {
		t.Run(kind+" create without the label is indeterminate", func(t *testing.T) {
			got := verdict(t, idx, podRequest(nsReq(create, nil)))
			assert.Equal(t, Indeterminate, got.Verdict)
			assert.Equal(t, []Reason{ReasonNamespaceLabelsUnknown}, got.Reasons)
		})
		t.Run(kind+" create with the label supplied is authoritative", func(t *testing.T) {
			got := verdict(t, idx, podRequest(nsReq(create, map[string]string{"kubernetes.io/metadata.name": "new"})))
			assert.Equal(t, Matched, got.Verdict)
		})
		t.Run(kind+" update without the label is indeterminate, whatever the old object says", func(t *testing.T) {
			// nsReq gives the old object the label; only the new object counts.
			got := verdict(t, idx, podRequest(nsReq(update, nil)))
			assert.Equal(t, Indeterminate, got.Verdict)
			assert.Equal(t, []Reason{ReasonNamespaceLabelsUnknown}, got.Reasons)
		})
		t.Run(kind+" update with the label supplied is authoritative", func(t *testing.T) {
			got := verdict(t, idx, podRequest(nsReq(update, map[string]string{"kubernetes.io/metadata.name": "new"})))
			assert.Equal(t, Matched, got.Verdict)
		})
		t.Run(kind+" update of a subresource uses the stored labels", func(t *testing.T) {
			got := verdict(t, idx, podRequest(func(r *Request) {
				nsReq(update, nil)(r)
				r.Subresource, r.NamespaceLabelsKnown = "status", false
			}))
			assert.Equal(t, Matched, got.Verdict, "only the stored namespace is read for a subresource, and its name label is inferred")
		})
		t.Run(kind+" delete uses the stored labels", func(t *testing.T) {
			got := verdict(t, idx, podRequest(func(r *Request) {
				nsReq(deleteO, nil)(r)
				r.NamespaceLabelsKnown = false
			}))
			assert.Equal(t, Matched, got.Verdict)
		})
	}
	t.Run("a definite rule rejection still wins", func(t *testing.T) {
		got := verdict(t, hooks["validating"], podRequest(func(r *Request) { nsReq(create, nil)(r); r.Resource = "secrets" }))
		assert.Equal(t, NotMatched, got.Verdict)
	})
	t.Run("another selector key is unaffected", func(t *testing.T) {
		for _, idx := range []*Index{
			validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: rules, NamespaceSelector: selector("env", metav1.LabelSelectorOpIn, "prod"), MatchPolicy: exact()}),
			mutatingIndex(admissionregistrationv1.MutatingWebhook{Rules: rules, NamespaceSelector: selector("env", metav1.LabelSelectorOpIn, "prod"), MatchPolicy: exact()}),
		} {
			assert.Equal(t, Matched, verdict(t, idx, podRequest(nsReq(create, map[string]string{"env": "prod"}))).Verdict)
		}
	})
}

func TestInvalidRules(t *testing.T) {
	podsOnly := podRule(create)
	badOp := rule([]string{""}, []string{"v1"}, []string{"pods"}, "PATCH")
	badScope := scoped(podRule(create), "Everywhere")

	t.Run("unknown operation is reported and cannot be ruled out", func(t *testing.T) {
		idx, errs := validatingIndexErrs(admissionregistrationv1.ValidatingWebhook{
			Rules: []admissionregistrationv1.RuleWithOperations{badOp}, MatchPolicy: exact(),
		})
		require.Len(t, errs, 1)
		assert.ErrorContains(t, errs[0], `unknown operation "PATCH"`)
		assert.ErrorContains(t, errs[0], `webhook "hook"`)
		got := verdict(t, idx, podRequest(nil))
		assert.Equal(t, Indeterminate, got.Verdict)
		assert.Equal(t, []Reason{ReasonInvalidRule}, got.Reasons)
	})
	t.Run("unknown scope is reported and cannot be ruled out", func(t *testing.T) {
		idx, errs := validatingIndexErrs(admissionregistrationv1.ValidatingWebhook{
			Rules: []admissionregistrationv1.RuleWithOperations{badScope}, MatchPolicy: exact(),
		})
		require.Len(t, errs, 1)
		assert.ErrorContains(t, errs[0], `unknown scope "Everywhere"`)
		assert.Equal(t, Indeterminate, verdict(t, idx, podRequest(nil)).Verdict)
	})
	t.Run("a valid rule that matches still wins", func(t *testing.T) {
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
			Rules: []admissionregistrationv1.RuleWithOperations{badOp, podsOnly}, MatchPolicy: exact(),
		})
		assert.Equal(t, Matched, verdict(t, idx, podRequest(nil)).Verdict)
	})
	t.Run("a definite rejection elsewhere still wins", func(t *testing.T) {
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
			Rules: []admissionregistrationv1.RuleWithOperations{badOp}, MatchPolicy: exact(),
			NamespaceSelector: selector("env", metav1.LabelSelectorOpIn, "dev"),
		})
		assert.Equal(t, NotMatched, verdict(t, idx, podRequest(nil)).Verdict)
	})
	t.Run("empty fields are not invalid values", func(t *testing.T) {
		idx, errs := validatingIndexErrs(admissionregistrationv1.ValidatingWebhook{
			Rules: []admissionregistrationv1.RuleWithOperations{{}}, MatchPolicy: exact(),
		})
		assert.Empty(t, errs)
		assert.Equal(t, NotMatched, verdict(t, idx, podRequest(nil)).Verdict)
	})
	t.Run("invalid rule and equivalence are both reported", func(t *testing.T) {
		apps := rule([]string{"apps"}, []string{"v1"}, []string{"pods"}, create)
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: []admissionregistrationv1.RuleWithOperations{apps, badOp}})
		got := verdict(t, idx, podRequest(nil))
		assert.Equal(t, []Reason{ReasonEquivalentResources, ReasonInvalidRule}, got.Reasons)
	})
}

func TestMalformedSelectorsAreReportedAndKeepTheWebhook(t *testing.T) {
	bad := selector("env", metav1.LabelSelectorOpIn) // In needs values
	idx, errs := validatingIndexErrs(admissionregistrationv1.ValidatingWebhook{
		Rules: []admissionregistrationv1.RuleWithOperations{podRule(create)}, MatchPolicy: exact(),
		NamespaceSelector: bad, ObjectSelector: bad,
	})
	require.Len(t, errs, 2)
	assert.ErrorContains(t, errs[0], "invalid namespaceSelector")
	assert.ErrorContains(t, errs[1], "invalid objectSelector")

	got := verdict(t, idx, podRequest(nil))
	assert.Equal(t, Indeterminate, got.Verdict)
	assert.Equal(t, []Reason{ReasonInvalidNamespaceSelector, ReasonInvalidObjectSelector}, got.Reasons)

	t.Run("a definite rule rejection still wins", func(t *testing.T) {
		got := verdict(t, idx, podRequest(func(r *Request) { r.Operation = update }))
		assert.Equal(t, NotMatched, got.Verdict)
		assert.Equal(t, []Reason{ReasonRulesDoNotMatch}, got.Reasons)
	})
}

func TestZeroValueConfigurationsDoNotPanic(t *testing.T) {
	idx, errs := NewIndex(
		[]admissionregistrationv1.ValidatingWebhookConfiguration{{}, {Webhooks: []admissionregistrationv1.ValidatingWebhook{{}}}},
		[]admissionregistrationv1.MutatingWebhookConfiguration{{Webhooks: []admissionregistrationv1.MutatingWebhook{{}}}})
	assert.Empty(t, errs)
	for _, got := range idx.Matches(podRequest(nil)) {
		assert.Equal(t, NotMatched, got.Verdict, "a webhook with no rules is never called")
		assert.Equal(t, []Reason{ReasonRulesDoNotMatch}, got.Reasons)
	}
	assert.NotPanics(t, func() { idx.Matches(Request{}) })
	assert.Empty(t, (&Index{}).Matches(podRequest(nil)))
	var nilIdx *Index
	assert.NotPanics(t, func() { assert.Nil(t, nilIdx.Matches(podRequest(nil))) })
}

func TestUnknownMatchPolicyIsNeverTreatedAsExact(t *testing.T) {
	odd := admissionregistrationv1.MatchPolicyType("Fuzzy")
	apps := rule([]string{"apps"}, []string{"v1"}, []string{"deployments"}, create)
	idx, errs := validatingIndexErrs(admissionregistrationv1.ValidatingWebhook{
		Rules: []admissionregistrationv1.RuleWithOperations{apps}, MatchPolicy: &odd,
	})
	require.Len(t, errs, 1)
	assert.ErrorContains(t, errs[0], `unknown matchPolicy "Fuzzy"`)
	got := verdict(t, idx, podRequest(nil))
	assert.Equal(t, Indeterminate, got.Verdict)
	assert.Equal(t, []Reason{ReasonEquivalentResources}, got.Reasons)
}

func TestIndexDoesNotAliasItsInputs(t *testing.T) {
	rules := []admissionregistrationv1.RuleWithOperations{podRule(create)}
	idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: rules, MatchPolicy: exact()})
	rules[0].Resources[0] = "secrets"
	rules[0].Operations[0] = update

	assert.Equal(t, Matched, verdict(t, idx, podRequest(nil)).Verdict, "later edits to the caller's rules do not leak in")
	assert.Equal(t, "secrets", rules[0].Resources[0], "and the caller's rules were not reset either")
}

func TestMatchesIsSafeForConcurrentUse(t *testing.T) {
	idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
		Rules:             []admissionregistrationv1.RuleWithOperations{rule([]string{"apps"}, []string{"v1"}, []string{"pods"}, create)},
		NamespaceSelector: selector("env", metav1.LabelSelectorOpIn, "prod"),
	})
	want := idx.Matches(podRequest(nil))
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				assert.Equal(t, want, idx.Matches(podRequest(nil)))
			}
		}()
	}
	wg.Wait()
}

// Equivalent matchPolicy must not rely on equivalent resources keeping their
// plural name: only the operation and the subresource survive the lookup.
func TestEquivalentKeepsOnlyOperationAndSubresource(t *testing.T) {
	pods := rule([]string{""}, []string{"v1"}, []string{"pods"}, create)
	exec := rule([]string{""}, []string{"v1"}, []string{"pods/exec"}, connect)
	tests := []struct {
		name   string
		rule   admissionregistrationv1.RuleWithOperations
		policy *admissionregistrationv1.MatchPolicyType
		mod    func(*Request)
		want   Verdict
	}{
		{"a different resource name stays ambiguous", pods, nil, func(r *Request) { r.Resource = "secrets" }, Indeterminate},
		{"a different group stays ambiguous", pods, nil, func(r *Request) { r.Group = "apps" }, Indeterminate},
		// The request keeps its namespace, so only the core Namespace, which the
		// scope predicate treats as cluster-scoped, can satisfy a Cluster rule.
		{"a Cluster rule for the core Namespace stays ambiguous", scoped(rule([]string{""}, []string{"v1"}, []string{"namespaces"}, create), admissionregistrationv1.ClusterScope), nil, nil, Indeterminate},
		{"a Cluster rule for another resource is definite", scoped(pods, admissionregistrationv1.ClusterScope), nil, nil, NotMatched},
		{"a Namespaced-only rule is definite for a cluster-scoped request", scoped(rule([]string{"*"}, []string{"*"}, []string{"*"}, create), admissionregistrationv1.NamespacedScope), nil, func(r *Request) {
			r.Resource, r.Kind, r.Name, r.Namespace, r.ClusterScoped = "nodes", "Node", "n", "", true
		}, NotMatched},
		{"another operation is definite", pods, nil, func(r *Request) { r.Operation = update }, NotMatched},
		{"a bare resource does not cover a subresource", pods, nil, func(r *Request) { r.Resource, r.Subresource = "secrets", "status" }, NotMatched},
		{"another subresource is definite", exec, nil, func(r *Request) {
			r.Operation, r.Resource, r.Subresource = connect, "services", "proxy"
		}, NotMatched},
		{"the same subresource of another resource is ambiguous", exec, nil, func(r *Request) {
			r.Operation, r.Resource, r.Subresource = connect, "services", "exec"
		}, Indeterminate},
		{"Exact never consults equivalents", pods, exact(), func(r *Request) { r.Resource = "secrets" }, NotMatched},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
				Rules: []admissionregistrationv1.RuleWithOperations{tt.rule}, MatchPolicy: tt.policy,
			})
			got := verdict(t, idx, podRequest(tt.mod))
			assert.Equal(t, tt.want, got.Verdict, "reasons: %v", got.Reasons)
		})
	}
}

func TestRelaxForEquivalenceLeavesItsInputAlone(t *testing.T) {
	r := rule([]string{"apps"}, []string{"v1"}, []string{"deployments", "deployments/scale"}, create)
	s := admissionregistrationv1.NamespacedScope
	r.Scope = &s
	got := relaxForEquivalence(r)

	assert.Equal(t, []string{"*"}, got.APIGroups)
	assert.Equal(t, []string{"*"}, got.APIVersions)
	assert.Equal(t, []string{"*", "*/scale"}, got.Resources)
	assert.Nil(t, got.Scope)
	assert.Equal(t, r.Operations, got.Operations)

	assert.Equal(t, []string{"apps"}, r.APIGroups)
	assert.Equal(t, []string{"deployments", "deployments/scale"}, r.Resources)
	assert.Equal(t, &s, r.Scope)
}

func TestNamespaceIsTheCoreResourceOnly(t *testing.T) {
	clusterRule := scoped(rule([]string{"example.io"}, []string{"v1"}, []string{"namespaces"}, admissionregistrationv1.OperationAll), admissionregistrationv1.ClusterScope)
	idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
		Rules: []admissionregistrationv1.RuleWithOperations{clusterRule}, MatchPolicy: exact(),
	})
	got := verdict(t, idx, Request{
		Group: "example.io", Version: "v1", Resource: "namespaces", Kind: "Namespace", Operation: create,
		Name: "x", ClusterScoped: true, ObjectLabelsKnown: true,
	})
	assert.Equal(t, Matched, got.Verdict, "a cluster-scoped resource of another group is not a Namespace, so its name is not a namespace")
	assert.Empty(t, got.Reasons)

	t.Run("it is not given the core Namespace's exception to the Namespaced scope", func(t *testing.T) {
		namespaced := scoped(rule([]string{"example.io"}, []string{"v1"}, []string{"namespaces"}, admissionregistrationv1.OperationAll), admissionregistrationv1.NamespacedScope)
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
			Rules: []admissionregistrationv1.RuleWithOperations{namespaced}, MatchPolicy: exact(),
		})
		got := verdict(t, idx, Request{
			Group: "example.io", Version: "v1", Resource: "namespaces", Kind: "Namespace", Operation: create,
			Name: "x", ClusterScoped: true, ObjectLabelsKnown: true,
		})
		assert.Equal(t, NotMatched, got.Verdict)
	})
	t.Run("without ClusterScoped it is a namespaced resource of unknown namespace", func(t *testing.T) {
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
			Rules:             []admissionregistrationv1.RuleWithOperations{rule([]string{"example.io"}, []string{"v1"}, []string{"namespaces"}, admissionregistrationv1.OperationAll)},
			NamespaceSelector: selector("env", metav1.LabelSelectorOpIn, "prod"), MatchPolicy: exact(),
		})
		// DELETE takes the labels from the stored namespace, so the missing
		// namespace matters. (CREATE and UPDATE read the request object, see
		// TestNamespacesPluralFollowsTheAPIServerDispatch.)
		got := verdict(t, idx, Request{
			Group: "example.io", Version: "v1", Resource: "namespaces", Kind: "Namespace", Operation: deleteO,
			Name: "x", OldObjectLabelsKnown: true,
		})
		assert.Equal(t, Indeterminate, got.Verdict)
		assert.Equal(t, []Reason{ReasonNamespaceUnknown}, got.Reasons)
	})
}

func TestNamespaceCreateObjectLabels(t *testing.T) {
	byEnvAndName := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"prod"}},
		{Key: "kubernetes.io/metadata.name", Operator: metav1.LabelSelectorOpIn, Values: []string{"new"}},
	}}
	byName := func(name string) *metav1.LabelSelector {
		return &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": name}}
	}
	nsCreate := func(labels map[string]string, known bool) func(*Request) {
		return func(r *Request) {
			r.Resource, r.Kind, r.Name, r.Namespace, r.Operation = "namespaces", "Namespace", "new", "", create
			r.ObjectLabels, r.ObjectLabelsKnown = labels, known
			r.NamespaceLabelsKnown = false
		}
	}
	rules := []admissionregistrationv1.RuleWithOperations{rule([]string{""}, []string{"v1"}, []string{"namespaces"}, admissionregistrationv1.OperationAll)}
	tests := []struct {
		name   string
		sel    *metav1.LabelSelector
		mod    func(*Request)
		want   Verdict
		reason Reason
	}{
		{"a known rejection wins over an unknown name label", byEnvAndName, nsCreate(map[string]string{"env": "dev"}, true), NotMatched, ReasonNamespaceSelectorExcludes},
		{"an unknown name label with the other requirements met is indeterminate", byEnvAndName, nsCreate(map[string]string{"env": "prod"}, true), Indeterminate, ReasonNamespaceLabelsUnknown},
		{"unknown labels, matching label in the map, are ignored", byName("new"), nsCreate(map[string]string{"kubernetes.io/metadata.name": "new"}, false), Indeterminate, ReasonNamespaceLabelsUnknown},
		{"unknown labels, nil map", byName("new"), nsCreate(nil, false), Indeterminate, ReasonNamespaceLabelsUnknown},
		{"known labels, supplied matching label", byName("new"), nsCreate(map[string]string{"kubernetes.io/metadata.name": "new"}, true), Matched, ""},
		{"known labels, supplied differing label", byName("other"), nsCreate(map[string]string{"kubernetes.io/metadata.name": "new"}, true), NotMatched, ReasonNamespaceSelectorExcludes},
		{"the supplied name label is not overwritten by the request name", byName("other"), nsCreate(map[string]string{"kubernetes.io/metadata.name": "other"}, true), Matched, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: rules, NamespaceSelector: tt.sel, MatchPolicy: exact()})
			got := verdict(t, idx, podRequest(tt.mod))
			assert.Equal(t, tt.want, got.Verdict)
			if tt.reason != "" {
				assert.Equal(t, []Reason{tt.reason}, got.Reasons)
			}
		})
	}

	t.Run("update keeps the supplied name label too", func(t *testing.T) {
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: rules, NamespaceSelector: byName("other"), MatchPolicy: exact()})
		got := verdict(t, idx, podRequest(func(r *Request) {
			nsCreate(map[string]string{"kubernetes.io/metadata.name": "other"}, true)(r)
			r.Operation = update
			r.OldObjectLabels, r.OldObjectLabelsKnown = map[string]string{"kubernetes.io/metadata.name": "other"}, true
		}))
		assert.Equal(t, Matched, got.Verdict)
	})
}

// A resource scope is one of three states: known namespaced, known
// cluster-scoped, or unknown. A namespaced resource whose namespace is missing
// is a different thing from an unknown scope.
func TestResourceScopeStates(t *testing.T) {
	widgets := func(s *admissionregistrationv1.ScopeType) admissionregistrationv1.RuleWithOperations {
		r := rule([]string{"example.org"}, []string{"v1"}, []string{"widgets"}, admissionregistrationv1.OperationAll)
		r.Scope = s
		return r
	}
	scopeOf := func(s admissionregistrationv1.ScopeType) *admissionregistrationv1.ScopeType { return &s }
	namespacedOnly := widgets(scopeOf(admissionregistrationv1.NamespacedScope))
	clusterOnly := widgets(scopeOf(admissionregistrationv1.ClusterScope))

	ruleSets := []struct {
		name  string
		rules []admissionregistrationv1.RuleWithOperations
	}{
		{"Namespaced", []admissionregistrationv1.RuleWithOperations{namespacedOnly}},
		{"Cluster", []admissionregistrationv1.RuleWithOperations{clusterOnly}},
		{"unset scope", []admissionregistrationv1.RuleWithOperations{widgets(nil)}},
		{"all scopes", []admissionregistrationv1.RuleWithOperations{widgets(scopeOf(admissionregistrationv1.AllScopes))}},
		{"a Namespaced rule and a Cluster rule", []admissionregistrationv1.RuleWithOperations{namespacedOnly, clusterOnly}},
	}
	states := []struct {
		name string
		mod  func(*Request)
	}{
		{"known namespaced", func(r *Request) { r.Namespace = "ns1" }},
		{"known cluster-scoped", func(r *Request) { r.ClusterScoped = true }},
		{"unknown scope", func(r *Request) { r.ScopeUnknown = true }},
		{"namespaced, namespace missing", func(r *Request) {}},
	}
	type outcome struct {
		verdict Verdict
		reasons []Reason
	}
	scopeUnknown := outcome{Indeterminate, []Reason{ReasonResourceScopeUnknown}}
	matched, notMatched := outcome{Matched, nil}, outcome{NotMatched, []Reason{ReasonRulesDoNotMatch}}
	want := map[string][]outcome{ // by rule set, in the order of states
		"Namespaced":                           {matched, notMatched, scopeUnknown, matched},
		"Cluster":                              {notMatched, matched, scopeUnknown, notMatched},
		"unset scope":                          {matched, matched, matched, matched},
		"all scopes":                           {matched, matched, matched, matched},
		"a Namespaced rule and a Cluster rule": {matched, matched, matched, matched},
	}
	for _, rs := range ruleSets {
		for i, st := range states {
			t.Run(rs.name+"/"+st.name, func(t *testing.T) {
				idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: rs.rules, MatchPolicy: exact()})
				got := verdict(t, idx, Request{Group: "example.org", Version: "v1", Resource: "widgets", Kind: "Widget", Operation: create, Name: "w"}.with(st.mod))
				assert.Equal(t, want[rs.name][i].verdict, got.Verdict)
				assert.Equal(t, want[rs.name][i].reasons, got.Reasons)
			})
		}
	}

	t.Run("a namespaceSelector depends on the scope, and the reason says so", func(t *testing.T) {
		sel := selector("env", metav1.LabelSelectorOpIn, "prod")
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: []admissionregistrationv1.RuleWithOperations{widgets(nil)}, NamespaceSelector: sel, MatchPolicy: exact()})
		base := Request{Group: "example.org", Version: "v1", Resource: "widgets", Kind: "Widget", Operation: create, Name: "w"}
		got := verdict(t, idx, base.with(func(r *Request) { r.ScopeUnknown = true }))
		assert.Equal(t, Indeterminate, got.Verdict)
		assert.Equal(t, []Reason{ReasonResourceScopeUnknown}, got.Reasons)
		got = verdict(t, idx, base)
		assert.Equal(t, []Reason{ReasonNamespaceUnknown}, got.Reasons, "a missing namespace is not an unknown scope")
		got = verdict(t, idx, base.with(func(r *Request) { r.ClusterScoped = true }))
		assert.Equal(t, Matched, got.Verdict, "a cluster-scoped resource is never filtered by namespace")
	})
	t.Run("an empty namespaceSelector does not depend on the scope", func(t *testing.T) {
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: []admissionregistrationv1.RuleWithOperations{widgets(nil)}, NamespaceSelector: &metav1.LabelSelector{}, MatchPolicy: exact()})
		got := verdict(t, idx, Request{Group: "example.org", Version: "v1", Resource: "widgets", Kind: "Widget", Operation: create, Name: "w", ScopeUnknown: true})
		assert.Equal(t, Matched, got.Verdict)
	})
	t.Run("a namespace settles the scope", func(t *testing.T) {
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: []admissionregistrationv1.RuleWithOperations{clusterOnly}, MatchPolicy: exact()})
		got := verdict(t, idx, Request{Group: "example.org", Version: "v1", Resource: "widgets", Kind: "Widget", Operation: create, Name: "w", Namespace: "ns1", ScopeUnknown: true})
		assert.Equal(t, NotMatched, got.Verdict)
	})
	t.Run("claiming both scopes is contradictory", func(t *testing.T) {
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: []admissionregistrationv1.RuleWithOperations{widgets(nil)}, MatchPolicy: exact()})
		got := verdict(t, idx, Request{Group: "example.org", Version: "v1", Resource: "widgets", Kind: "Widget", Operation: create, Name: "w", ClusterScoped: true, ScopeUnknown: true})
		assert.Equal(t, Indeterminate, got.Verdict)
		assert.Equal(t, []Reason{ReasonIncompleteRequest}, got.Reasons)
	})
	t.Run("the core Namespace has a known scope", func(t *testing.T) {
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: []admissionregistrationv1.RuleWithOperations{
			scoped(rule([]string{""}, []string{"v1"}, []string{"namespaces"}, admissionregistrationv1.OperationAll), admissionregistrationv1.ClusterScope)}, MatchPolicy: exact()})
		got := verdict(t, idx, Request{Version: "v1", Resource: "namespaces", Kind: "Namespace", Operation: create, Name: "new", ScopeUnknown: true})
		assert.Equal(t, Matched, got.Verdict)
	})
}

func (r Request) with(mod func(*Request)) Request {
	if mod != nil {
		mod(&r)
	}
	return r
}

// A missing part of the request does not override a rule exclusion that holds
// whatever that part is.
func TestIncompleteRequestKeepsDefiniteRuleExclusions(t *testing.T) {
	noVersion := func(r *Request) { r.Version = "" }
	tests := []struct {
		name   string
		rules  []admissionregistrationv1.RuleWithOperations
		mod    func(*Request)
		want   Verdict
		reason Reason
	}{
		{"DELETE-only rule", []admissionregistrationv1.RuleWithOperations{podRule(deleteO)}, noVersion, NotMatched, ReasonRulesDoNotMatch},
		{"no rules", nil, noVersion, NotMatched, ReasonRulesDoNotMatch},
		{"CREATE rule restricted to v1", []admissionregistrationv1.RuleWithOperations{podRule(create)}, noVersion, Indeterminate, ReasonIncompleteRequest},
		{"CREATE rule for any version", []admissionregistrationv1.RuleWithOperations{rule([]string{""}, []string{"*"}, []string{"pods"}, create)}, noVersion, Indeterminate, ReasonIncompleteRequest},
		{"other group, version missing", []admissionregistrationv1.RuleWithOperations{rule([]string{"apps"}, []string{"v1"}, []string{"pods"}, create)}, noVersion, NotMatched, ReasonRulesDoNotMatch},
		{"other resource, version missing", []admissionregistrationv1.RuleWithOperations{rule([]string{""}, []string{"v1"}, []string{"secrets"}, create)}, noVersion, NotMatched, ReasonRulesDoNotMatch},
		{"DELETE-only rule, resource missing", []admissionregistrationv1.RuleWithOperations{podRule(deleteO)}, func(r *Request) { r.Resource = "" }, NotMatched, ReasonRulesDoNotMatch},
		{"other subresource, resource missing", []admissionregistrationv1.RuleWithOperations{podRule(create)}, func(r *Request) { r.Resource, r.Subresource = "", "exec" }, NotMatched, ReasonRulesDoNotMatch},
		{"no rules, operation missing", nil, func(r *Request) { r.Operation = "" }, NotMatched, ReasonRulesDoNotMatch},
		{"any rule, operation missing", []admissionregistrationv1.RuleWithOperations{podRule(deleteO)}, func(r *Request) { r.Operation = "" }, Indeterminate, ReasonIncompleteRequest},
		{"contradictory scope, DELETE-only rule", []admissionregistrationv1.RuleWithOperations{podRule(deleteO)}, func(r *Request) { r.ClusterScoped = true }, NotMatched, ReasonRulesDoNotMatch},
		{"contradictory scope, matching rule", []admissionregistrationv1.RuleWithOperations{podRule(create)}, func(r *Request) { r.ClusterScoped = true }, Indeterminate, ReasonIncompleteRequest},
	}
	for _, policy := range []*admissionregistrationv1.MatchPolicyType{exact(), equivalent()} {
		for _, tt := range tests {
			want, reason := tt.want, tt.reason
			if *policy == admissionregistrationv1.Equivalent {
				// Equivalent also relaxes group, version and resource, but never
				// the operation or the subresource.
				if tt.name == "other group, version missing" || tt.name == "other resource, version missing" {
					want, reason = Indeterminate, ReasonIncompleteRequest
				}
			}
			t.Run(string(*policy)+"/"+tt.name, func(t *testing.T) {
				idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: tt.rules, MatchPolicy: policy})
				got := verdict(t, idx, podRequest(tt.mod))
				assert.Equal(t, want, got.Verdict)
				assert.Equal(t, []Reason{reason}, got.Reasons)
			})
		}
	}
	t.Run("a rule value this package does not know cannot be ruled out", func(t *testing.T) {
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
			Rules: []admissionregistrationv1.RuleWithOperations{rule([]string{""}, []string{"v1"}, []string{"pods"}, "PATCH")}, MatchPolicy: exact()})
		assert.Equal(t, Indeterminate, verdict(t, idx, podRequest(noVersion)).Verdict)
	})
}

func widgetRule(scope admissionregistrationv1.ScopeType) admissionregistrationv1.RuleWithOperations {
	return scoped(rule([]string{"example.org"}, []string{"v1"}, []string{"widgets"}, create), scope)
}

func widgetRequest(mod func(*Request)) Request {
	return Request{Group: "example.org", Version: "v1", Resource: "widgets", Kind: "Widget", Operation: create, Name: "w"}.with(mod)
}

// The Equivalent probe only runs for a scope reading no rule covers directly.
func TestEquivalentProbeSkipsCoveredScopeReadings(t *testing.T) {
	idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
		Rules: []admissionregistrationv1.RuleWithOperations{widgetRule(admissionregistrationv1.NamespacedScope)}, MatchPolicy: equivalent(),
	})
	got := verdict(t, idx, widgetRequest(func(r *Request) { r.ScopeUnknown = true }))
	assert.Equal(t, Indeterminate, got.Verdict)
	assert.Equal(t, []Reason{ReasonResourceScopeUnknown}, got.Reasons,
		"the Namespaced reading is covered directly and the cluster reading cannot be reached by a Namespaced rule")

	t.Run("an uncovered reading an equivalent could cover keeps the reason", func(t *testing.T) {
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
			Rules: []admissionregistrationv1.RuleWithOperations{
				widgetRule(admissionregistrationv1.NamespacedScope),
				scoped(rule([]string{"other.io"}, []string{"v1"}, []string{"gadgets"}, create), admissionregistrationv1.ClusterScope),
			}, MatchPolicy: equivalent(),
		})
		got := verdict(t, idx, widgetRequest(func(r *Request) { r.ScopeUnknown = true }))
		assert.Equal(t, Indeterminate, got.Verdict)
		assert.Equal(t, []Reason{ReasonResourceScopeUnknown, ReasonEquivalentResources}, got.Reasons)
	})
}

// Rule and namespaceSelector are judged together for each possible scope.
func TestUnknownScopeCombinesRuleAndNamespaceSelectorPerScope(t *testing.T) {
	prod := selector("env", metav1.LabelSelectorOpIn, "prod")
	unknownScope := func(r *Request) {
		r.ScopeUnknown = true
		r.NamespaceLabels, r.NamespaceLabelsKnown = map[string]string{"env": "dev"}, true
	}
	hook := func(rules ...admissionregistrationv1.RuleWithOperations) *Index {
		return validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: rules, NamespaceSelector: prod, MatchPolicy: exact()})
	}

	t.Run("both readings are definitely excluded", func(t *testing.T) {
		got := verdict(t, hook(widgetRule(admissionregistrationv1.NamespacedScope)), widgetRequest(unknownScope))
		assert.Equal(t, NotMatched, got.Verdict)
		assert.Equal(t, []Reason{ReasonNamespaceSelectorExcludes, ReasonRulesDoNotMatch}, got.Reasons)
	})
	t.Run("a Cluster rule keeps the cluster reading, which no selector filters", func(t *testing.T) {
		got := verdict(t, hook(widgetRule(admissionregistrationv1.ClusterScope)), widgetRequest(unknownScope))
		assert.Equal(t, Indeterminate, got.Verdict)
		assert.Equal(t, []Reason{ReasonResourceScopeUnknown}, got.Reasons)
	})
	t.Run("a requirement the known labels satisfy leaves the namespaced reading standing", func(t *testing.T) {
		got := verdict(t, hook(widgetRule(admissionregistrationv1.NamespacedScope)), widgetRequest(func(r *Request) {
			unknownScope(r)
			r.NamespaceLabels = map[string]string{"env": "prod"}
		}))
		assert.Equal(t, Indeterminate, got.Verdict)
		assert.Equal(t, []Reason{ReasonResourceScopeUnknown}, got.Reasons)
	})
	t.Run("a requirement on the unknown namespace name stays undecided", func(t *testing.T) {
		byName := selector(corev1.LabelMetadataName, metav1.LabelSelectorOpIn, "prod")
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
			Rules: []admissionregistrationv1.RuleWithOperations{widgetRule(admissionregistrationv1.NamespacedScope)}, NamespaceSelector: byName, MatchPolicy: exact()})
		got := verdict(t, idx, widgetRequest(unknownScope))
		assert.Equal(t, Indeterminate, got.Verdict)
	})
}

// kube-apiserver dispatches the namespaceSelector on the resource plural.
func TestNamespacesPluralFollowsTheAPIServerDispatch(t *testing.T) {
	prod := selector("env", metav1.LabelSelectorOpIn, "prod")
	idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
		Rules:             []admissionregistrationv1.RuleWithOperations{rule([]string{"example.org"}, []string{"v1"}, []string{"namespaces"}, create)},
		NamespaceSelector: prod, MatchPolicy: exact(),
	})
	base := Request{
		Group: "example.org", Version: "v1", Resource: "namespaces", Kind: "Namespace", Operation: create, Name: "n", Namespace: "ns1",
		ObjectLabels: map[string]string{"env": "dev"}, ObjectLabelsKnown: true,
		NamespaceLabels: map[string]string{"env": "prod"}, NamespaceLabelsKnown: true,
	}

	got := verdict(t, idx, base)
	assert.Equal(t, NotMatched, got.Verdict, "the object's labels are read, not the stored namespace's")
	assert.Equal(t, []Reason{ReasonNamespaceSelectorExcludes}, got.Reasons)

	got = verdict(t, idx, base.with(func(r *Request) { r.ObjectLabels = map[string]string{"env": "prod"}; r.NamespaceLabels = nil }))
	assert.Equal(t, Matched, got.Verdict)

	t.Run("an empty namespace is not bypassed", func(t *testing.T) {
		got := verdict(t, idx, base.with(func(r *Request) { r.Namespace, r.ClusterScoped = "", true }))
		assert.Equal(t, NotMatched, got.Verdict, "a cluster-scoped resource called namespaces still has its selector evaluated")
		assert.Equal(t, []Reason{ReasonNamespaceSelectorExcludes}, got.Reasons)
	})
	t.Run("a resource with another plural is bypassed when it has no namespace", func(t *testing.T) {
		other := validatingIndex(admissionregistrationv1.ValidatingWebhook{
			Rules:             []admissionregistrationv1.RuleWithOperations{rule([]string{"example.org"}, []string{"v1"}, []string{"widgets"}, create)},
			NamespaceSelector: prod, MatchPolicy: exact(),
		})
		got := verdict(t, other, widgetRequest(func(r *Request) { r.ClusterScoped = true }))
		assert.Equal(t, Matched, got.Verdict)
	})
	t.Run("the core Namespace is still identified by its full GVR for the rule scope", func(t *testing.T) {
		clusterRule := validatingIndex(admissionregistrationv1.ValidatingWebhook{
			Rules: []admissionregistrationv1.RuleWithOperations{scoped(rule([]string{""}, []string{"v1"}, []string{"namespaces"}, create), admissionregistrationv1.ClusterScope)}, MatchPolicy: exact()})
		assert.Equal(t, Matched, verdict(t, clusterRule, Request{Version: "v1", Resource: "namespaces", Kind: "Namespace", Operation: create, Name: "n"}).Verdict)
		other := validatingIndex(admissionregistrationv1.ValidatingWebhook{
			Rules: []admissionregistrationv1.RuleWithOperations{scoped(rule([]string{"example.org"}, []string{"v1"}, []string{"namespaces"}, create), admissionregistrationv1.NamespacedScope)}, MatchPolicy: exact()})
		assert.Equal(t, Matched, verdict(t, other, base).Verdict, "a namespaced resource called namespaces satisfies a Namespaced rule")
	})
}

// A label that is present with an empty value is not an absent label.
func TestNamespaceLabelPresentWithEmptyValue(t *testing.T) {
	idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
		Rules:             []admissionregistrationv1.RuleWithOperations{rule([]string{""}, []string{"v1"}, []string{"namespaces"}, create)},
		NamespaceSelector: selector(corev1.LabelMetadataName, metav1.LabelSelectorOpExists), MatchPolicy: exact(),
	})
	req := Request{Version: "v1", Resource: "namespaces", Kind: "Namespace", Operation: create, Name: "n", ObjectLabelsKnown: true}

	got := verdict(t, idx, req.with(func(r *Request) { r.ObjectLabels = map[string]string{corev1.LabelMetadataName: ""} }))
	assert.Equal(t, Matched, got.Verdict)

	got = verdict(t, idx, req.with(func(r *Request) { r.ObjectLabels = map[string]string{} }))
	assert.Equal(t, Indeterminate, got.Verdict, "an absent key may still be added by the apiserver")
	assert.Equal(t, []Reason{ReasonNamespaceLabelsUnknown}, got.Reasons)
}

// A missing API version does not undo a scope exclusion the request settles.
func TestIncompleteRequestKeepsKnownScope(t *testing.T) {
	noVersion := func(r *Request) { r.Version = "" }
	for _, policy := range []*admissionregistrationv1.MatchPolicyType{exact(), equivalent()} {
		idx := func(scope admissionregistrationv1.ScopeType) *Index {
			return validatingIndex(admissionregistrationv1.ValidatingWebhook{
				Rules: []admissionregistrationv1.RuleWithOperations{widgetRule(scope)}, MatchPolicy: policy})
		}
		t.Run(string(*policy), func(t *testing.T) {
			got := verdict(t, idx(admissionregistrationv1.NamespacedScope), widgetRequest(func(r *Request) { noVersion(r); r.ClusterScoped = true }))
			assert.Equal(t, NotMatched, got.Verdict, "a cluster-scoped request cannot satisfy a Namespaced rule")
			assert.Equal(t, []Reason{ReasonRulesDoNotMatch}, got.Reasons)

			got = verdict(t, idx(admissionregistrationv1.ClusterScope), widgetRequest(func(r *Request) { noVersion(r); r.Namespace = "ns1" }))
			assert.Equal(t, NotMatched, got.Verdict, "a namespaced request cannot satisfy a Cluster rule")

			got = verdict(t, idx(admissionregistrationv1.NamespacedScope), widgetRequest(func(r *Request) { noVersion(r); r.Namespace = "ns1" }))
			assert.Equal(t, Indeterminate, got.Verdict)
			assert.Equal(t, []Reason{ReasonIncompleteRequest}, got.Reasons)

			got = verdict(t, idx(admissionregistrationv1.NamespacedScope), widgetRequest(func(r *Request) { noVersion(r); r.ScopeUnknown = true }))
			assert.Equal(t, Indeterminate, got.Verdict, "an unknown scope is not settled")
		})
	}
	t.Run("the core Namespace may be the missing version's resource", func(t *testing.T) {
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{
			Rules: []admissionregistrationv1.RuleWithOperations{scoped(rule([]string{""}, []string{"v1"}, []string{"namespaces"}, create), admissionregistrationv1.ClusterScope)}, MatchPolicy: exact()})
		got := verdict(t, idx, Request{Resource: "namespaces", Kind: "Namespace", Operation: create, Name: "n", Namespace: "x"})
		assert.Equal(t, Indeterminate, got.Verdict)
	})
}
