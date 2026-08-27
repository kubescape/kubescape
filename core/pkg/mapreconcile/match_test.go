package mapreconcile

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1alpha1 "k8s.io/api/admissionregistration/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func rule(groups, versions, resources []string, ops ...admissionregistrationv1alpha1.OperationType) admissionregistrationv1alpha1.NamedRuleWithOperations {
	return admissionregistrationv1alpha1.NamedRuleWithOperations{
		RuleWithOperations: admissionregistrationv1alpha1.RuleWithOperations{
			Operations: ops,
			Rule: admissionregistrationv1alpha1.Rule{
				APIGroups:   groups,
				APIVersions: versions,
				Resources:   resources,
			},
		},
	}
}

func pods(ops ...admissionregistrationv1alpha1.OperationType) admissionregistrationv1alpha1.NamedRuleWithOperations {
	return rule([]string{""}, []string{"v1"}, []string{"pods"}, ops...)
}

func obj(overrides func(*ObjectInfo)) ObjectInfo {
	o := ObjectInfo{
		Group:     "",
		Version:   "v1",
		Resource:  "pods",
		Namespace: "default",
		Operation: admissionregistrationv1alpha1.Create,
	}
	if overrides != nil {
		overrides(&o)
	}
	return o
}

func TestRuleMatches_ExactGroupVersionResourceOperation(t *testing.T) {
	r := pods(admissionregistrationv1alpha1.Create)
	assert.True(t, ruleMatches(r, obj(nil)))
}

func TestRuleMatches_WrongResourceDoesNotMatch(t *testing.T) {
	r := rule([]string{""}, []string{"v1"}, []string{"configmaps"}, admissionregistrationv1alpha1.Create)
	assert.False(t, ruleMatches(r, obj(nil)))
}

func TestRuleMatches_WildcardGroupVersionResource(t *testing.T) {
	r := rule([]string{"*"}, []string{"*"}, []string{"*"}, admissionregistrationv1alpha1.OperationAll)
	assert.True(t, ruleMatches(r, obj(func(o *ObjectInfo) { o.Group = "apps"; o.Version = "v1"; o.Resource = "deployments" })))
}

func TestRuleMatches_OperationAllMatchesEveryOperation(t *testing.T) {
	r := pods(admissionregistrationv1alpha1.OperationAll)
	for _, op := range []admissionregistrationv1alpha1.OperationType{admissionregistrationv1alpha1.Create, admissionregistrationv1alpha1.Update, admissionregistrationv1alpha1.Connect} {
		assert.True(t, ruleMatches(r, obj(func(o *ObjectInfo) { o.Operation = op })), "operation %s", op)
	}
}

func TestRuleMatches_SpecificOperationExcludesOthers(t *testing.T) {
	r := pods(admissionregistrationv1alpha1.Update)
	assert.False(t, ruleMatches(r, obj(func(o *ObjectInfo) { o.Operation = admissionregistrationv1alpha1.Create })))
}

func TestRuleMatches_EmptyRuleNeverMatches(t *testing.T) {
	assert.False(t, ruleMatches(admissionregistrationv1alpha1.NamedRuleWithOperations{}, obj(nil)))
}

func TestCompileMatchResources_NilMatchesEverything(t *testing.T) {
	c, err := compileMatchResources(nil)
	require.NoError(t, err)

	matched, determinable := c.matches(obj(nil))
	assert.True(t, matched)
	assert.True(t, determinable)
}

func TestCompileMatchResources_EmptyResourceRulesMatchesEverything(t *testing.T) {
	c, err := compileMatchResources(&admissionregistrationv1alpha1.MatchResources{})
	require.NoError(t, err)

	matched, determinable := c.matches(obj(nil))
	assert.True(t, matched)
	assert.True(t, determinable)
}

func TestCompileMatchResources_ResourceRuleMustMatch(t *testing.T) {
	c, err := compileMatchResources(&admissionregistrationv1alpha1.MatchResources{
		ResourceRules: []admissionregistrationv1alpha1.NamedRuleWithOperations{pods(admissionregistrationv1alpha1.Create)},
	})
	require.NoError(t, err)

	matched, determinable := c.matches(obj(func(o *ObjectInfo) { o.Resource = "secrets" }))
	assert.False(t, matched)
	assert.True(t, determinable)
}

func TestCompileMatchResources_ExcludeTakesPrecedenceOverInclude(t *testing.T) {
	c, err := compileMatchResources(&admissionregistrationv1alpha1.MatchResources{
		ResourceRules:        []admissionregistrationv1alpha1.NamedRuleWithOperations{pods(admissionregistrationv1alpha1.OperationAll)},
		ExcludeResourceRules: []admissionregistrationv1alpha1.NamedRuleWithOperations{pods(admissionregistrationv1alpha1.OperationAll)},
	})
	require.NoError(t, err)

	matched, determinable := c.matches(obj(nil))
	assert.False(t, matched)
	assert.True(t, determinable)
}

func TestCompileMatchResources_ObjectSelectorMustMatchLabels(t *testing.T) {
	c, err := compileMatchResources(&admissionregistrationv1alpha1.MatchResources{
		ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
	})
	require.NoError(t, err)

	notMatched, determinable := c.matches(obj(func(o *ObjectInfo) { o.Labels = map[string]string{"env": "dev"} }))
	assert.False(t, notMatched)
	assert.True(t, determinable)

	matched, determinable := c.matches(obj(func(o *ObjectInfo) { o.Labels = map[string]string{"env": "prod"} }))
	assert.True(t, matched)
	assert.True(t, determinable)
}

func TestCompileMatchResources_NamespaceSelectorRequiresKnownLabels(t *testing.T) {
	c, err := compileMatchResources(&admissionregistrationv1alpha1.MatchResources{
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
	})
	require.NoError(t, err)

	_, determinable := c.matches(obj(func(o *ObjectInfo) { o.NamespaceLabelsKnown = false }))
	assert.False(t, determinable, "an unresolved namespaceSelector must report indeterminate, not a confident non-match")

	matched, determinable := c.matches(obj(func(o *ObjectInfo) {
		o.NamespaceLabelsKnown = true
		o.NamespaceLabels = map[string]string{"env": "prod"}
	}))
	assert.True(t, matched)
	assert.True(t, determinable)
}

func TestCompileMatchResources_ClusterScopedObjectIgnoresNamespaceSelector(t *testing.T) {
	c, err := compileMatchResources(&admissionregistrationv1alpha1.MatchResources{
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
	})
	require.NoError(t, err)

	matched, determinable := c.matches(obj(func(o *ObjectInfo) {
		o.ClusterScoped = true
		o.NamespaceLabelsKnown = false
	}))
	assert.True(t, matched, "a namespaceSelector never skips a cluster-scoped object, per MatchResources' own doc comment")
	assert.True(t, determinable)
}

func TestCompileMatchResources_EmptyNamespaceSelectorMatchesEvenWithoutLabels(t *testing.T) {
	c, err := compileMatchResources(&admissionregistrationv1alpha1.MatchResources{
		NamespaceSelector: &metav1.LabelSelector{},
	})
	require.NoError(t, err)

	matched, determinable := c.matches(obj(func(o *ObjectInfo) { o.NamespaceLabelsKnown = false }))
	assert.True(t, matched)
	assert.True(t, determinable, "an empty selector matches everything regardless of whether labels were resolved")
}

func TestCompileMatchResources_MalformedSelectorIsReported(t *testing.T) {
	_, err := compileMatchResources(&admissionregistrationv1alpha1.MatchResources{
		ObjectSelector: &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "x", Operator: "NotARealOperator"}},
		},
	})
	assert.Error(t, err)
}

func TestCompileMatchResources_EquivalentMatchPolicyVersionMismatchIsIndeterminate(t *testing.T) {
	equivalent := admissionregistrationv1alpha1.Equivalent
	// The rule names "deployments" under apps/v1 only; a request arriving via
	// apps/v1beta1 for the same resource name is exactly the case Equivalent
	// is meant to resolve via API-version-equivalence data this package does
	// not have.
	c, err := compileMatchResources(&admissionregistrationv1alpha1.MatchResources{
		ResourceRules: []admissionregistrationv1alpha1.NamedRuleWithOperations{
			rule([]string{"apps"}, []string{"v1"}, []string{"deployments"}, admissionregistrationv1alpha1.Create),
		},
		MatchPolicy: &equivalent,
	})
	require.NoError(t, err)

	matched, determinable := c.matches(obj(func(o *ObjectInfo) {
		o.Group = "apps"
		o.Version = "v1beta1"
		o.Resource = "deployments"
	}))
	assert.False(t, matched)
	assert.False(t, determinable, "a resource+operation match with a differing group/version is exactly what Equivalent cannot be confidently resolved without API-version-equivalence data")
}

func TestCompileMatchResources_EquivalentMatchPolicyUnrelatedResourceIsAConfidentNonMatch(t *testing.T) {
	equivalent := admissionregistrationv1alpha1.Equivalent
	c, err := compileMatchResources(&admissionregistrationv1alpha1.MatchResources{
		ResourceRules: []admissionregistrationv1alpha1.NamedRuleWithOperations{pods(admissionregistrationv1alpha1.Create)},
		MatchPolicy:   &equivalent,
	})
	require.NoError(t, err)

	matched, determinable := c.matches(obj(func(o *ObjectInfo) { o.Resource = "secrets" }))
	assert.False(t, matched)
	assert.True(t, determinable, "an entirely unrelated resource kind is never equivalent, under any matchPolicy")
}

func TestCompileMatchResources_ExactMatchPolicyMissIsAConfidentNonMatch(t *testing.T) {
	exact := admissionregistrationv1alpha1.Exact
	c, err := compileMatchResources(&admissionregistrationv1alpha1.MatchResources{
		ResourceRules: []admissionregistrationv1alpha1.NamedRuleWithOperations{pods(admissionregistrationv1alpha1.Create)},
		MatchPolicy:   &exact,
	})
	require.NoError(t, err)

	matched, determinable := c.matches(obj(func(o *ObjectInfo) { o.Resource = "secrets" }))
	assert.False(t, matched)
	assert.True(t, determinable, "Exact matchPolicy has no equivalence expansion to be uncertain about")
}
