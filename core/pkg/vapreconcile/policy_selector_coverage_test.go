package vapreconcile

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func policyWithSelectors(name string, namespace, object any) unstructured.Unstructured {
	policy := makeVAP(name, "C-0001")
	constraints := map[string]any{
		"resourceRules": []any{map[string]any{
			"apiGroups": []any{"*"}, "apiVersions": []any{"*"},
			"operations": []any{"CREATE", "UPDATE"}, "resources": []any{"*"},
		}},
	}
	if namespace != nil {
		constraints["namespaceSelector"] = namespace
	}
	if object != nil {
		constraints["objectSelector"] = object
	}
	policy.Object["spec"] = map[string]any{"matchConstraints": constraints}
	return policy
}

func TestCoverageHonorsPolicySelectors(t *testing.T) {
	prod := matchLabels("env", "prod")
	critical := matchLabels("tier", "critical")
	pod := ResourceInfo{
		ResourceID: "pod", APIVersion: "v1", Kind: "Pod", Namespace: "prod",
		Labels: map[string]string{"tier": "critical"},
	}
	for _, tc := range []struct {
		name      string
		namespace any
		object    any
		resource  ResourceInfo
		inventory map[string]map[string]string
		covered   bool
	}{
		{
			name:      "policy namespace excludes an otherwise matching binding",
			namespace: prod, resource: pod,
			inventory: map[string]map[string]string{"prod": {"env": "dev"}},
		},
		{
			name:   "policy object excludes an otherwise matching binding",
			object: matchLabels("tier", "internal"), resource: pod,
		},
		{
			name: "both policy selectors match", namespace: prod, object: critical, resource: pod,
			inventory: map[string]map[string]string{"prod": {"env": "prod"}}, covered: true,
		},
		{
			name: "missing namespace inventory stays uncertain", namespace: prod, resource: pod,
		},
		{
			name:      "immutable namespace identity needs no inventory",
			namespace: matchLabels("kubernetes.io/metadata.name", "prod"), resource: pod, covered: true,
		},
		{
			name:      "immutable namespace identity can exclude",
			namespace: matchLabels("kubernetes.io/metadata.name", "dev"), resource: pod,
		},
		{
			name: "cluster scoped resource ignores namespace selector", namespace: prod,
			resource: ResourceInfo{ResourceID: "role", APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"},
			covered:  true,
		},
		{
			name: "cluster scoped resource still checks object selector", namespace: prod, object: critical,
			resource: ResourceInfo{ResourceID: "role", APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"},
		},
		{
			name: "Namespace uses its own labels", namespace: prod,
			resource:  ResourceInfo{ResourceID: "ns", APIVersion: "v1", Kind: "Namespace", Name: "prod", Labels: map[string]string{"env": "dev"}},
			inventory: map[string]map[string]string{"prod": {"env": "prod"}},
		},
		{
			name:      "empty policy selectors remain unrestricted",
			namespace: map[string]any{}, object: map[string]any{}, resource: pod, covered: true,
		},
		{
			name:      "invalid namespace selector never grants coverage",
			namespace: map[string]any{"matchExpressions": []any{map[string]any{"key": "env", "operator": "invalid"}}}, resource: pod,
		},
		{
			name:   "invalid object selector never grants coverage",
			object: map[string]any{"matchLabels": map[string]any{"tier": int64(1)}}, resource: pod,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := policyWithSelectors("policy", tc.namespace, tc.object)
			binding := makeVAPB("binding", "policy", []string{"Deny"})
			before := policy.DeepCopy()
			coverage := BuildCoverage([]unstructured.Unstructured{policy}, []unstructured.Unstructured{binding},
				map[string][]ResourceInfo{"C-0001": {tc.resource}}, tc.inventory)["C-0001"]
			require.NotNil(t, coverage)
			require.True(t, coverage.Bound, "binding existence is independent of its effective scope")
			require.Len(t, coverage.Resources, 1)
			require.Equal(t, tc.covered, coverage.Resources[0].Covered)
			require.Equal(t, tc.covered, coverage.FullyCovered())
			if !tc.covered {
				require.Contains(t, coverage.Resources[0].Reason, "policy")
			}
			require.Equal(t, before.Object, policy.Object, "scope evaluation must not mutate collected policies")
		})
	}
}

func TestCoverageIntersectsPolicyAndBindingWithinEachPair(t *testing.T) {
	// Neither pair covers the Pod: borrowing the matching policy from one
	// pair and the matching binding from the other must not produce coverage.
	policies := []unstructured.Unstructured{
		policyWithSelectors("a", nil, matchLabels("app", "web")),
		policyWithSelectors("b", nil, matchLabels("app", "worker")),
	}
	bindings := []unstructured.Unstructured{
		makeVAPBScoped("a-binding", "a", nil, matchLabels("stage", "test")),
		makeVAPBScoped("b-binding", "b", nil, matchLabels("stage", "prod")),
	}
	resources := map[string][]ResourceInfo{"C-0001": {{
		ResourceID: "pod", Namespace: "prod", Labels: map[string]string{"app": "web", "stage": "prod"},
	}}}
	result := BuildCoverage(policies, bindings, resources, nil)["C-0001"]
	require.False(t, result.FullyCovered())
	require.Zero(t, result.CoveredCount())

	// Adding a matching binding for policy a supplies one complete pair.
	bindings = append(bindings, makeVAPBScoped("a-prod", "a", nil, matchLabels("stage", "prod")))
	result = BuildCoverage(policies, bindings, resources, nil)["C-0001"]
	require.True(t, result.FullyCovered())
	require.Equal(t, 1, result.CoveredCount())
}

func TestCoverageCanBePartialBecauseOfPolicyScope(t *testing.T) {
	policy := policyWithSelectors("policy", nil, matchLabels("tier", "critical"))
	binding := makeVAPB("binding", "policy", []string{"Deny"})
	resources := map[string][]ResourceInfo{"C-0001": {
		{ResourceID: "critical", Namespace: "prod", Labels: map[string]string{"tier": "critical"}},
		{ResourceID: "internal", Namespace: "prod", Labels: map[string]string{"tier": "internal"}},
	}}
	result := BuildCoverage([]unstructured.Unstructured{policy}, []unstructured.Unstructured{binding}, resources, nil)["C-0001"]
	require.True(t, result.Bound)
	require.True(t, result.PartiallyCovered())
	require.False(t, result.FullyCovered())
	require.Equal(t, 1, result.CoveredCount())
	require.Equal(t, 2, result.TotalFailing())
}

func TestCoverageIgnoresUnlabelledPolicyCopies(t *testing.T) {
	policy := policyWithSelectors("policy", nil, matchLabels("tier", "critical"))
	unlabelled := makeVAP("policy", "")
	binding := makeVAPB("binding", "policy", []string{"Deny"})
	resources := map[string][]ResourceInfo{"C-0001": {{ResourceID: "internal", Labels: map[string]string{"tier": "internal"}}}}
	result := BuildCoverage([]unstructured.Unstructured{unlabelled, policy}, []unstructured.Unstructured{binding}, resources, nil)["C-0001"]
	require.False(t, result.FullyCovered(), "the policy/control join and selector lookup must use the same labelled policy")
	require.Contains(t, result.Resources[0].Reason, "policy objectSelector")
}

func TestCoverageMalformedPolicyDoesNotHideAnotherMatchingPolicy(t *testing.T) {
	invalid := policyWithSelectors("a", nil, map[string]any{"matchLabels": map[string]any{"tier": int64(1)}})
	valid := policyWithSelectors("b", nil, matchLabels("tier", "critical"))
	bindings := []unstructured.Unstructured{
		makeVAPB("a-binding", "a", []string{"Deny"}),
		makeVAPB("b-binding", "b", []string{"Deny"}),
	}
	resources := map[string][]ResourceInfo{"C-0001": {{ResourceID: "critical", Labels: map[string]string{"tier": "critical"}}}}
	result := BuildCoverage([]unstructured.Unstructured{invalid, valid}, bindings, resources, nil)["C-0001"]
	require.True(t, result.FullyCovered(), "one invalid policy must not blind the other complete policy/binding pairs")
	require.Empty(t, result.Resources[0].Reason)
}
