package webhookcoverage

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
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

// The apiserver stamps kubernetes.io/metadata.name onto a new Namespace after
// mutating admission, so only mutating webhooks are held back.
func TestNamespaceCreateAndTheAutomaticNameLabel(t *testing.T) {
	byName := &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "new"}}
	rules := []admissionregistrationv1.RuleWithOperations{rule([]string{""}, []string{"v1"}, []string{"namespaces"}, admissionregistrationv1.OperationAll)}
	nsReq := func(op admissionregistrationv1.OperationType, labels map[string]string) func(*Request) {
		return func(r *Request) {
			r.Resource, r.Kind, r.Name, r.Namespace, r.Operation = "namespaces", "Namespace", "new", "", op
			r.ObjectLabels, r.ObjectLabelsKnown = labels, true
			r.OldObjectLabels, r.OldObjectLabelsKnown = map[string]string{"kubernetes.io/metadata.name": "new"}, true
			r.NamespaceLabelsKnown = false
		}
	}

	t.Run("validating create sees the label", func(t *testing.T) {
		idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: rules, NamespaceSelector: byName, MatchPolicy: exact()})
		assert.Equal(t, Matched, verdict(t, idx, podRequest(nsReq(create, nil))).Verdict)
	})
	t.Run("mutating create may not", func(t *testing.T) {
		idx := mutatingIndex(admissionregistrationv1.MutatingWebhook{Rules: rules, NamespaceSelector: byName, MatchPolicy: exact()})
		got := verdict(t, idx, podRequest(nsReq(create, nil)))
		assert.Equal(t, Indeterminate, got.Verdict)
		assert.Equal(t, []Reason{ReasonNamespaceLabelsUnknown}, got.Reasons)
	})
	t.Run("mutating create with the label supplied", func(t *testing.T) {
		idx := mutatingIndex(admissionregistrationv1.MutatingWebhook{Rules: rules, NamespaceSelector: byName, MatchPolicy: exact()})
		got := verdict(t, idx, podRequest(nsReq(create, map[string]string{"kubernetes.io/metadata.name": "new"})))
		assert.Equal(t, Matched, got.Verdict)
	})
	t.Run("mutating update has the stored label", func(t *testing.T) {
		idx := mutatingIndex(admissionregistrationv1.MutatingWebhook{Rules: rules, NamespaceSelector: byName, MatchPolicy: exact()})
		assert.Equal(t, Matched, verdict(t, idx, podRequest(nsReq(update, nil))).Verdict)
	})
	t.Run("mutating create with another selector key is unaffected", func(t *testing.T) {
		idx := mutatingIndex(admissionregistrationv1.MutatingWebhook{
			Rules: rules, NamespaceSelector: selector("env", metav1.LabelSelectorOpIn, "prod"), MatchPolicy: exact(),
		})
		assert.Equal(t, Matched, verdict(t, idx, podRequest(nsReq(create, map[string]string{"env": "prod"}))).Verdict)
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
	var nilIdx *Index
	assert.NotPanics(t, func() { _ = (&Index{}).Matches(Request{}) })
	_ = nilIdx
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
