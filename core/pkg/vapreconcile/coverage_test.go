package vapreconcile

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// makeVAPBScoped extends makeVAPB with a matchResources.namespaceSelector
// and/or matchResources.objectSelector. A nil selector omits that key
// entirely, matching how a real binding without that field decodes.
func makeVAPBScoped(name, policyName string, namespaceSelector, objectSelector map[string]any) unstructured.Unstructured {
	matchResources := map[string]any{}
	if namespaceSelector != nil {
		matchResources["namespaceSelector"] = namespaceSelector
	}
	if objectSelector != nil {
		matchResources["objectSelector"] = objectSelector
	}

	u := unstructured.Unstructured{
		Object: map[string]any{
			"spec": map[string]any{
				"policyName":     policyName,
				"matchResources": matchResources,
			},
		},
	}
	u.SetName(name)
	return u
}

func matchLabels(kv ...string) map[string]any {
	m := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return map[string]any{"matchLabels": m}
}

func TestBuildCoverage_FullyCoveredWhenNoSelectors(t *testing.T) {
	policies := []unstructured.Unstructured{makeVAP("policy-a", "C-0001")}
	bindings := []unstructured.Unstructured{makeVAPB("binding-a", "policy-a", []string{"Deny"})}
	failing := map[string][]ResourceInfo{
		"C-0001": {{ResourceID: "res-1", Namespace: "default"}},
	}

	coverage := BuildCoverage(policies, bindings, failing, nil)

	c := coverage["C-0001"]
	require.NotNil(t, c)
	assert.True(t, c.Bound)
	assert.True(t, c.FullyCovered())
	assert.False(t, c.PartiallyCovered())
	require.Len(t, c.Resources, 1)
	assert.True(t, c.Resources[0].Covered)
	assert.Empty(t, c.Resources[0].Reason)
}

func TestBuildCoverage_NamespaceSelectorExcludesResource(t *testing.T) {
	policies := []unstructured.Unstructured{makeVAP("policy-a", "C-0001")}
	bindings := []unstructured.Unstructured{
		makeVAPBScoped("binding-a", "policy-a", matchLabels("env", "prod"), nil),
	}
	failing := map[string][]ResourceInfo{
		"C-0001": {{ResourceID: "res-1", Namespace: "dev"}},
	}
	nsLabels := map[string]map[string]string{
		"dev": {"env": "dev"},
	}

	coverage := BuildCoverage(policies, bindings, failing, nsLabels)

	c := coverage["C-0001"]
	require.NotNil(t, c)
	assert.True(t, c.Bound)
	assert.False(t, c.FullyCovered())
	require.Len(t, c.Resources, 1)
	assert.False(t, c.Resources[0].Covered)
	assert.Contains(t, c.Resources[0].Reason, "namespaceSelector")
}

func TestBuildCoverage_NamespaceSelectorIncludesResource(t *testing.T) {
	policies := []unstructured.Unstructured{makeVAP("policy-a", "C-0001")}
	bindings := []unstructured.Unstructured{
		makeVAPBScoped("binding-a", "policy-a", matchLabels("env", "prod"), nil),
	}
	failing := map[string][]ResourceInfo{
		"C-0001": {{ResourceID: "res-1", Namespace: "prod"}},
	}
	nsLabels := map[string]map[string]string{
		"prod": {"env": "prod"},
	}

	coverage := BuildCoverage(policies, bindings, failing, nsLabels)

	c := coverage["C-0001"]
	require.NotNil(t, c)
	assert.True(t, c.FullyCovered())
}

func TestBuildCoverage_ObjectSelectorExcludesResource(t *testing.T) {
	policies := []unstructured.Unstructured{makeVAP("policy-a", "C-0001")}
	bindings := []unstructured.Unstructured{
		makeVAPBScoped("binding-a", "policy-a", nil, matchLabels("tier", "critical")),
	}
	failing := map[string][]ResourceInfo{
		"C-0001": {{ResourceID: "res-1", Namespace: "default", Labels: map[string]string{"tier": "internal"}}},
	}

	coverage := BuildCoverage(policies, bindings, failing, nil)

	c := coverage["C-0001"]
	require.NotNil(t, c)
	assert.False(t, c.FullyCovered())
	assert.False(t, c.Resources[0].Covered)
	assert.Contains(t, c.Resources[0].Reason, "objectSelector")
}

func TestBuildCoverage_ObjectSelectorIncludesResource(t *testing.T) {
	policies := []unstructured.Unstructured{makeVAP("policy-a", "C-0001")}
	bindings := []unstructured.Unstructured{
		makeVAPBScoped("binding-a", "policy-a", nil, matchLabels("tier", "critical")),
	}
	failing := map[string][]ResourceInfo{
		"C-0001": {{ResourceID: "res-1", Namespace: "default", Labels: map[string]string{"tier": "critical"}}},
	}

	coverage := BuildCoverage(policies, bindings, failing, nil)

	c := coverage["C-0001"]
	require.NotNil(t, c)
	assert.True(t, c.FullyCovered())
}

func TestBuildCoverage_UnknownNamespaceTreatedAsNotCovered(t *testing.T) {
	policies := []unstructured.Unstructured{makeVAP("policy-a", "C-0001")}
	bindings := []unstructured.Unstructured{
		makeVAPBScoped("binding-a", "policy-a", matchLabels("env", "prod"), nil),
	}
	failing := map[string][]ResourceInfo{
		"C-0001": {{ResourceID: "res-1", Namespace: "prod"}},
	}

	// namespaceLabels does not contain "prod" at all -- the scan never
	// collected the Namespace object, so coverage cannot be determined and
	// must not be assumed.
	coverage := BuildCoverage(policies, bindings, failing, map[string]map[string]string{})

	c := coverage["C-0001"]
	require.NotNil(t, c)
	assert.False(t, c.Resources[0].Covered)
	assert.Contains(t, c.Resources[0].Reason, "not collected")
}

func TestBuildCoverage_ClusterScopedResourceIsNeverExemptedByNamespaceSelector(t *testing.T) {
	policies := []unstructured.Unstructured{makeVAP("policy-a", "C-0001")}
	bindings := []unstructured.Unstructured{
		makeVAPBScoped("binding-a", "policy-a", matchLabels("env", "prod"), nil),
	}
	failing := map[string][]ResourceInfo{
		"C-0001": {{ResourceID: "res-1", APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"}},
	}

	coverage := BuildCoverage(policies, bindings, failing, nil)

	c := coverage["C-0001"]
	require.NotNil(t, c)
	assert.True(t, c.FullyCovered(), "the apiserver enforces the binding on a cluster-scoped resource whatever the namespaceSelector says")
}

func TestBuildCoverage_ClusterScopedResourceStillHonorsObjectSelector(t *testing.T) {
	policies := []unstructured.Unstructured{makeVAP("policy-a", "C-0001")}
	bindings := []unstructured.Unstructured{
		makeVAPBScoped("binding-a", "policy-a", matchLabels("env", "prod"), matchLabels("tier", "critical")),
	}
	failing := map[string][]ResourceInfo{
		"C-0001": {{
			ResourceID: "res-1",
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "ClusterRole",
			Labels:     map[string]string{"tier": "internal"},
		}},
	}

	coverage := BuildCoverage(policies, bindings, failing, nil)

	c := coverage["C-0001"]
	require.NotNil(t, c)
	assert.False(t, c.Resources[0].Covered, "the namespaceSelector does not apply, but the objectSelector still does")
	assert.Contains(t, c.Resources[0].Reason, "objectSelector")
}

func TestBuildCoverage_NamespaceMatchedOnItsOwnLabels(t *testing.T) {
	policies := []unstructured.Unstructured{makeVAP("policy-a", "C-0001")}
	bindings := []unstructured.Unstructured{
		makeVAPBScoped("binding-a", "policy-a", matchLabels("env", "prod"), nil),
	}
	failing := map[string][]ResourceInfo{
		"C-0001": {{
			ResourceID: "res-1",
			APIVersion: "v1",
			Kind:       "Namespace",
			Labels:     map[string]string{"env": "prod"},
		}},
	}

	// The collected-namespace index is deliberately empty: a Namespace is
	// matched on the labels it carries itself, never through this map.
	coverage := BuildCoverage(policies, bindings, failing, nil)

	c := coverage["C-0001"]
	require.NotNil(t, c)
	assert.True(t, c.FullyCovered())
}

func TestBuildCoverage_NamespaceExcludedByItsOwnLabels(t *testing.T) {
	policies := []unstructured.Unstructured{makeVAP("policy-a", "C-0001")}
	bindings := []unstructured.Unstructured{
		makeVAPBScoped("binding-a", "policy-a", matchLabels("env", "prod"), nil),
	}
	failing := map[string][]ResourceInfo{
		"C-0001": {{
			ResourceID: "res-1",
			APIVersion: "v1",
			Kind:       "Namespace",
			Labels:     map[string]string{"env": "dev"},
		}},
	}

	coverage := BuildCoverage(policies, bindings, failing, nil)

	c := coverage["C-0001"]
	require.NotNil(t, c)
	assert.False(t, c.Resources[0].Covered)
	assert.Contains(t, c.Resources[0].Reason, "own labels")
}

func TestBuildCoverage_MultipleBindingsOrSemantics(t *testing.T) {
	policies := []unstructured.Unstructured{makeVAP("policy-a", "C-0001")}
	bindings := []unstructured.Unstructured{
		makeVAPBScoped("binding-narrow", "policy-a", matchLabels("env", "prod"), nil),
		makeVAPBScoped("binding-broad", "policy-a", nil, nil), // matches everything
	}
	failing := map[string][]ResourceInfo{
		"C-0001": {{ResourceID: "res-1", Namespace: "dev"}},
	}
	nsLabels := map[string]map[string]string{"dev": {"env": "dev"}}

	coverage := BuildCoverage(policies, bindings, failing, nsLabels)

	c := coverage["C-0001"]
	require.NotNil(t, c)
	// The narrow binding excludes it, but the broad one covers it -- any
	// one bound binding enforcing is enough for the resource to be covered.
	assert.True(t, c.FullyCovered())
}

func TestBuildCoverage_NotBoundReturnsAllUncovered(t *testing.T) {
	policies := []unstructured.Unstructured{makeVAP("policy-a", "C-0001")}
	failing := map[string][]ResourceInfo{
		"C-0001": {{ResourceID: "res-1", Namespace: "default"}},
	}

	coverage := BuildCoverage(policies, nil, failing, nil)

	c := coverage["C-0001"]
	require.NotNil(t, c)
	assert.False(t, c.Bound)
	assert.False(t, c.FullyCovered())
	assert.False(t, c.PartiallyCovered())
	assert.False(t, c.Resources[0].Covered)
	assert.Contains(t, c.Resources[0].Reason, "no bound binding")
}

func TestBuildCoverage_NoVAPForControlOmittedFromMap(t *testing.T) {
	failing := map[string][]ResourceInfo{
		"C-9999": {{ResourceID: "res-1", Namespace: "default"}},
	}

	coverage := BuildCoverage(nil, nil, failing, nil)

	_, ok := coverage["C-9999"]
	assert.False(t, ok)
}

func TestBuildCoverage_MalformedSelectorDoesNotCrashAndCoversNothing(t *testing.T) {
	policies := []unstructured.Unstructured{makeVAP("policy-a", "C-0001")}
	// "In" requires a Values list; omitting it makes the selector invalid.
	badSelector := map[string]any{
		"matchExpressions": []any{
			map[string]any{"key": "env", "operator": "In"},
		},
	}
	bindings := []unstructured.Unstructured{
		makeVAPBScoped("binding-a", "policy-a", badSelector, nil),
	}
	failing := map[string][]ResourceInfo{
		"C-0001": {{ResourceID: "res-1", Namespace: "default"}},
	}

	require.NotPanics(t, func() {
		coverage := BuildCoverage(policies, bindings, failing, map[string]map[string]string{"default": {}})
		c := coverage["C-0001"]
		require.NotNil(t, c)
		assert.True(t, c.Bound) // the binding still binds the policy
		assert.False(t, c.Resources[0].Covered)
	})
}

func TestBuildCoverage_PartiallyCoveredAcrossMultipleResources(t *testing.T) {
	policies := []unstructured.Unstructured{makeVAP("policy-a", "C-0001")}
	bindings := []unstructured.Unstructured{
		makeVAPBScoped("binding-a", "policy-a", matchLabels("env", "prod"), nil),
	}
	failing := map[string][]ResourceInfo{
		"C-0001": {
			{ResourceID: "res-prod", Namespace: "prod"},
			{ResourceID: "res-dev", Namespace: "dev"},
		},
	}
	nsLabels := map[string]map[string]string{
		"prod": {"env": "prod"},
		"dev":  {"env": "dev"},
	}

	coverage := BuildCoverage(policies, bindings, failing, nsLabels)

	c := coverage["C-0001"]
	require.NotNil(t, c)
	assert.True(t, c.PartiallyCovered())
	assert.False(t, c.FullyCovered())
	assert.Equal(t, 1, c.CoveredCount())
	assert.Equal(t, 2, c.TotalFailing())
}

func TestControlCoverage_NilReceiverIsSafe(t *testing.T) {
	var c *ControlCoverage
	assert.Equal(t, 0, c.TotalFailing())
	assert.Equal(t, 0, c.CoveredCount())
	assert.False(t, c.FullyCovered())
	assert.False(t, c.PartiallyCovered())
}

func TestControlCoverage_FullyCoveredRequiresAtLeastOneResource(t *testing.T) {
	c := &ControlCoverage{ControlID: "C-0001", Bound: true}
	assert.False(t, c.FullyCovered(), "a bound control with zero failing resources has nothing to be 'fully covered' about")
}

func TestCollectFailingResourcesByControl_OnlyIncludesFailedControls(t *testing.T) {
	wl := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      "app",
			"namespace": "default",
			"labels":    map[string]any{"tier": "critical"},
		},
	})
	resourceID := wl.GetID()

	resourcesResult := map[string]resourcesresults.Result{
		resourceID: {
			ResourceID: resourceID,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{ControlID: "C-0001", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}},
				{ControlID: "C-0002", Status: apis.StatusInfo{InnerStatus: apis.StatusPassed}},
			},
		},
		"missing-from-allresources": {
			ResourceID: "missing-from-allresources",
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{ControlID: "C-0003", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}},
			},
		},
	}
	allResources := map[string]workloadinterface.IMetadata{resourceID: wl}

	byControl := CollectFailingResourcesByControl(resourcesResult, allResources)

	require.Contains(t, byControl, "C-0001")
	require.Len(t, byControl["C-0001"], 1)
	assert.Equal(t, resourceID, byControl["C-0001"][0].ResourceID)
	assert.Equal(t, "default", byControl["C-0001"][0].Namespace)
	assert.Equal(t, "apps/v1", byControl["C-0001"][0].APIVersion)
	assert.Equal(t, "Deployment", byControl["C-0001"][0].Kind)
	assert.Equal(t, map[string]string{"tier": "critical"}, byControl["C-0001"][0].Labels)

	assert.NotContains(t, byControl, "C-0002", "passed controls must not be reported as failing")
	assert.NotContains(t, byControl, "C-0003", "a resource missing from allResources must be skipped, not panic")
}

func TestCollectNamespaceLabels_OnlyNamespaceKind(t *testing.T) {
	ns := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]any{
			"name":   "prod",
			"labels": map[string]any{"env": "prod"},
		},
	})
	pod := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "app",
			"namespace": "prod",
		},
	})

	allResources := map[string]workloadinterface.IMetadata{
		ns.GetID():  ns,
		pod.GetID(): pod,
	}

	nsLabels := CollectNamespaceLabels(allResources)

	require.Contains(t, nsLabels, "prod")
	assert.Equal(t, map[string]string{"env": "prod"}, nsLabels["prod"])
	assert.Len(t, nsLabels, 1, "only the Namespace object should contribute, not the Pod")
}

func TestParseSelector_AbsentSelectorMatchesEverything(t *testing.T) {
	sel, err := parseSelector(nil)
	require.NoError(t, err)
	assert.True(t, sel.Empty())
}

func TestParseSelector_EmptySelectorMatchesEverything(t *testing.T) {
	sel, err := parseSelector(map[string]any{})
	require.NoError(t, err)
	assert.True(t, sel.Empty())
}

func TestParseSelector_InvalidSelectorReturnsError(t *testing.T) {
	_, err := parseSelector(map[string]any{
		"matchExpressions": []any{
			map[string]any{"key": "env", "operator": "NotARealOperator"},
		},
	})
	assert.Error(t, err)
}
