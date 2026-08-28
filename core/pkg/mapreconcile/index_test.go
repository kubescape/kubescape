package mapreconcile

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1alpha1 "k8s.io/api/admissionregistration/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func policy(name string, matchConstraints *admissionregistrationv1alpha1.MatchResources, mutations ...admissionregistrationv1alpha1.Mutation) admissionregistrationv1alpha1.MutatingAdmissionPolicy {
	return admissionregistrationv1alpha1.MutatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: admissionregistrationv1alpha1.MutatingAdmissionPolicySpec{
			MatchConstraints: matchConstraints,
			Mutations:        mutations,
		},
	}
}

func binding(name, policyName string, matchResources *admissionregistrationv1alpha1.MatchResources) admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding {
	return admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: admissionregistrationv1alpha1.MutatingAdmissionPolicyBindingSpec{
			PolicyName:     policyName,
			MatchResources: matchResources,
		},
	}
}

func jsonPatchMutation(expr string) admissionregistrationv1alpha1.Mutation {
	return admissionregistrationv1alpha1.Mutation{
		PatchType: admissionregistrationv1alpha1.PatchTypeJSONPatch,
		JSONPatch: &admissionregistrationv1alpha1.JSONPatch{Expression: expr},
	}
}

func allPods() *admissionregistrationv1alpha1.MatchResources {
	return &admissionregistrationv1alpha1.MatchResources{
		ResourceRules: []admissionregistrationv1alpha1.NamedRuleWithOperations{pods(admissionregistrationv1alpha1.OperationAll)},
	}
}

func TestMatches_UnboundPolicyNeverReported(t *testing.T) {
	p := policy("add-label", allPods(), jsonPatchMutation(`[JSONPatch{op: "add", path: "/metadata/labels/x", value: "y"}]`))
	idx, errs := NewIndex([]admissionregistrationv1alpha1.MutatingAdmissionPolicy{p}, nil)
	require.Empty(t, errs)

	matches := idx.Matches(obj(nil))
	assert.Empty(t, matches, "a policy with no binding must never be reported as matching")
}

func TestMatches_BoundPolicyMatchingObjectIsReported(t *testing.T) {
	p := policy("add-label", allPods(), jsonPatchMutation(`[JSONPatch{op: "add", path: "/metadata/labels/x", value: "y"}]`))
	b := binding("add-label-binding", "add-label", nil)
	idx, errs := NewIndex([]admissionregistrationv1alpha1.MutatingAdmissionPolicy{p}, []admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding{b})
	require.Empty(t, errs)

	matches := idx.Matches(obj(nil))
	require.Len(t, matches, 1)
	assert.Equal(t, "add-label", matches[0].PolicyName)
	assert.Equal(t, "add-label-binding", matches[0].BindingName)
	require.Len(t, matches[0].Mutations, 1)
	assert.Equal(t, admissionregistrationv1alpha1.PatchTypeJSONPatch, matches[0].Mutations[0].PatchType)
	assert.Contains(t, matches[0].Mutations[0].Expression, "/metadata/labels/x")
	assert.True(t, matches[0].Determinable)
}

func TestMatches_BindingMatchResourcesFurtherRestrictsPolicy(t *testing.T) {
	p := policy("add-label", allPods())
	restrictive := &admissionregistrationv1alpha1.MatchResources{
		ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"mutate": "yes"}},
	}
	b := binding("only-opted-in", "add-label", restrictive)
	idx, errs := NewIndex([]admissionregistrationv1alpha1.MutatingAdmissionPolicy{p}, []admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding{b})
	require.Empty(t, errs)

	notOptedIn := idx.Matches(obj(func(o *ObjectInfo) { o.Labels = map[string]string{"mutate": "no"} }))
	assert.Empty(t, notOptedIn, "the binding's own matchResources must further restrict what the policy's matchConstraints already allowed")

	optedIn := idx.Matches(obj(func(o *ObjectInfo) { o.Labels = map[string]string{"mutate": "yes"} }))
	assert.Len(t, optedIn, 1)
}

func TestMatches_PolicyNotMatchingConstraintsExcludesEveryBinding(t *testing.T) {
	configmapsOnly := &admissionregistrationv1alpha1.MatchResources{
		ResourceRules: []admissionregistrationv1alpha1.NamedRuleWithOperations{
			rule([]string{""}, []string{"v1"}, []string{"configmaps"}, admissionregistrationv1alpha1.OperationAll),
		},
	}
	p := policy("configmap-only", configmapsOnly)
	b := binding("b", "configmap-only", nil)
	idx, errs := NewIndex([]admissionregistrationv1alpha1.MutatingAdmissionPolicy{p}, []admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding{b})
	require.Empty(t, errs)

	matches := idx.Matches(obj(func(o *ObjectInfo) { o.Resource = "pods" }))
	assert.Empty(t, matches, "the policy's matchConstraints excluding the object must exclude every binding of it")
}

func TestMatches_MultipleBindingsOnOnePolicyEachReported(t *testing.T) {
	p := policy("add-label", allPods())
	b1 := binding("b1", "add-label", nil)
	b2 := binding("b2", "add-label", nil)
	idx, errs := NewIndex([]admissionregistrationv1alpha1.MutatingAdmissionPolicy{p}, []admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding{b1, b2})
	require.Empty(t, errs)

	matches := idx.Matches(obj(nil))
	assert.Len(t, matches, 2)
}

func TestMatches_MultiplePoliciesEachReported(t *testing.T) {
	p1 := policy("p1", allPods())
	p2 := policy("p2", allPods())
	b1 := binding("b1", "p1", nil)
	b2 := binding("b2", "p2", nil)
	idx, errs := NewIndex([]admissionregistrationv1alpha1.MutatingAdmissionPolicy{p1, p2}, []admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding{b1, b2})
	require.Empty(t, errs)

	matches := idx.Matches(obj(nil))
	assert.Len(t, matches, 2)
}

func TestNewIndex_MalformedPolicySelectorIsReportedAndSkipped(t *testing.T) {
	bad := policy("bad", &admissionregistrationv1alpha1.MatchResources{
		ObjectSelector: &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "x", Operator: "NotARealOperator"}},
		},
	})
	good := policy("good", allPods())
	b1 := binding("bad-binding", "bad", nil)
	b2 := binding("good-binding", "good", nil)

	idx, errs := NewIndex(
		[]admissionregistrationv1alpha1.MutatingAdmissionPolicy{bad, good},
		[]admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding{b1, b2},
	)
	require.Len(t, errs, 1)

	matches := idx.Matches(obj(nil))
	require.Len(t, matches, 1)
	assert.Equal(t, "good", matches[0].PolicyName)
}

func TestNewIndex_MalformedBindingSelectorIsReportedAndSkipped(t *testing.T) {
	p := policy("p", allPods())
	badBinding := binding("bad-binding", "p", &admissionregistrationv1alpha1.MatchResources{
		ObjectSelector: &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "x", Operator: "NotARealOperator"}},
		},
	})
	goodBinding := binding("good-binding", "p", nil)

	idx, errs := NewIndex(
		[]admissionregistrationv1alpha1.MutatingAdmissionPolicy{p},
		[]admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding{badBinding, goodBinding},
	)
	require.Len(t, errs, 1)

	matches := idx.Matches(obj(nil))
	require.Len(t, matches, 1)
	assert.Equal(t, "good-binding", matches[0].BindingName)
}

func TestMatches_FailurePolicyDefaultsToFail(t *testing.T) {
	p := policy("p", allPods())
	b := binding("b", "p", nil)
	idx, errs := NewIndex([]admissionregistrationv1alpha1.MutatingAdmissionPolicy{p}, []admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding{b})
	require.Empty(t, errs)

	matches := idx.Matches(obj(nil))
	require.Len(t, matches, 1)
	assert.Equal(t, admissionregistrationv1alpha1.Fail, matches[0].FailurePolicy)
}

func TestMatches_HasParamsReflectsParamKind(t *testing.T) {
	p := policy("p", allPods())
	p.Spec.ParamKind = &admissionregistrationv1alpha1.ParamKind{APIVersion: "v1", Kind: "ConfigMap"}
	b := binding("b", "p", nil)
	idx, errs := NewIndex([]admissionregistrationv1alpha1.MutatingAdmissionPolicy{p}, []admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding{b})
	require.Empty(t, errs)

	matches := idx.Matches(obj(nil))
	require.Len(t, matches, 1)
	assert.True(t, matches[0].HasParams)
}

func TestMatches_IndeterminateNamespaceSelectorPropagatesToResult(t *testing.T) {
	p := policy("p", &admissionregistrationv1alpha1.MatchResources{
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
		ResourceRules:     []admissionregistrationv1alpha1.NamedRuleWithOperations{pods(admissionregistrationv1alpha1.OperationAll)},
	})
	b := binding("b", "p", nil)
	idx, errs := NewIndex([]admissionregistrationv1alpha1.MutatingAdmissionPolicy{p}, []admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding{b})
	require.Empty(t, errs)

	matches := idx.Matches(obj(func(o *ObjectInfo) { o.NamespaceLabelsKnown = false }))
	require.Len(t, matches, 1, "an indeterminate namespaceSelector must still be reported as a possible match")
	assert.False(t, matches[0].Determinable)
}

func TestMatches_ApplyConfigurationMutationExpressionIsCarried(t *testing.T) {
	p := policy("p", allPods(), admissionregistrationv1alpha1.Mutation{
		PatchType: admissionregistrationv1alpha1.PatchTypeApplyConfiguration,
		ApplyConfiguration: &admissionregistrationv1alpha1.ApplyConfiguration{
			Expression: `Object{spec: Object.spec{serviceAccountName: "restricted"}}`,
		},
	})
	b := binding("b", "p", nil)
	idx, errs := NewIndex([]admissionregistrationv1alpha1.MutatingAdmissionPolicy{p}, []admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding{b})
	require.Empty(t, errs)

	matches := idx.Matches(obj(nil))
	require.Len(t, matches, 1)
	require.Len(t, matches[0].Mutations, 1)
	assert.Equal(t, admissionregistrationv1alpha1.PatchTypeApplyConfiguration, matches[0].Mutations[0].PatchType)
	assert.Contains(t, matches[0].Mutations[0].Expression, "serviceAccountName")
}

// TestMatches_PolicyConstrainedToEveryResourceIsReported covers the headline
// case for the subresource form: "*/*" is the documented way to scope a policy
// to every resource, so a policy written that way mutates the queried object.
func TestMatches_PolicyConstrainedToEveryResourceIsReported(t *testing.T) {
	everything := &admissionregistrationv1alpha1.MatchResources{
		ResourceRules: []admissionregistrationv1alpha1.NamedRuleWithOperations{
			rule([]string{"*"}, []string{"*"}, []string{"*/*"}, admissionregistrationv1alpha1.OperationAll),
		},
	}
	p := policy("mutate-everything", everything, jsonPatchMutation(`[JSONPatch{op: "add", path: "/metadata/labels/x", value: "y"}]`))
	b := binding("mutate-everything-binding", "mutate-everything", nil)
	idx, errs := NewIndex([]admissionregistrationv1alpha1.MutatingAdmissionPolicy{p}, []admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding{b})
	require.Empty(t, errs)

	matches := idx.Matches(obj(nil))
	require.Len(t, matches, 1)
	assert.Equal(t, "mutate-everything", matches[0].PolicyName)
	assert.True(t, matches[0].Determinable)
}

// TestMatches_ExcludeRuleWithSubresourceWildcardExcludes is the same root cause
// in the direction that reports a mutation which will not happen: "pods/*" on
// the exclude side reaches the bare pod too.
func TestMatches_ExcludeRuleWithSubresourceWildcardExcludes(t *testing.T) {
	constraints := allPods()
	constraints.ExcludeResourceRules = []admissionregistrationv1alpha1.NamedRuleWithOperations{
		rule([]string{""}, []string{"v1"}, []string{"pods/*"}, admissionregistrationv1alpha1.OperationAll),
	}
	p := policy("mutate-pods", constraints)
	b := binding("mutate-pods-binding", "mutate-pods", nil)
	idx, errs := NewIndex([]admissionregistrationv1alpha1.MutatingAdmissionPolicy{p}, []admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding{b})
	require.Empty(t, errs)

	assert.Empty(t, idx.Matches(obj(nil)), "an exclude rule covering every pod subresource covers the pod itself")
}

// TestMatches_BindingExcludeRuleWithSubresourceWildcardExcludes is the same
// exclusion arriving on the binding's matchResources, which compiles
// separately from the policy's matchConstraints.
func TestMatches_BindingExcludeRuleWithSubresourceWildcardExcludes(t *testing.T) {
	p := policy("mutate-pods", allPods())
	b := binding("mutate-pods-binding", "mutate-pods", &admissionregistrationv1alpha1.MatchResources{
		ExcludeResourceRules: []admissionregistrationv1alpha1.NamedRuleWithOperations{
			rule([]string{""}, []string{"v1"}, []string{"pods/*"}, admissionregistrationv1alpha1.OperationAll),
		},
	})
	idx, errs := NewIndex([]admissionregistrationv1alpha1.MutatingAdmissionPolicy{p}, []admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding{b})
	require.Empty(t, errs)

	assert.Empty(t, idx.Matches(obj(nil)))
}

// TestMatches_SubresourceRequestNotCoveredByBareResourceRule is the other half
// of the split: a policy scoped to "pods" does not mutate a pods/status
// request, so a subresource query must not inherit the parent's match.
func TestMatches_SubresourceRequestNotCoveredByBareResourceRule(t *testing.T) {
	p := policy("mutate-pods", allPods())
	b := binding("mutate-pods-binding", "mutate-pods", nil)
	idx, errs := NewIndex([]admissionregistrationv1alpha1.MutatingAdmissionPolicy{p}, []admissionregistrationv1alpha1.MutatingAdmissionPolicyBinding{b})
	require.Empty(t, errs)

	assert.Empty(t, idx.Matches(obj(func(o *ObjectInfo) { o.Subresource = "status" })))
	assert.Len(t, idx.Matches(obj(nil)), 1)
}
