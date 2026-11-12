package vapreconcile

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
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

// TestBuildCoverage_ClusterScopedResourceIsNeverExemptedByNamespaceSelector asserts that
// standard Kubernetes cluster-scoped kinds (ClusterRole, ServiceCIDR, IPAddress, ClusterIssuer,
// ClusterTrustBundle, ClusterRoleBinding) are always covered regardless of namespaceSelector.
func TestBuildCoverage_ClusterScopedResourceIsNeverExemptedByNamespaceSelector(t *testing.T) {
	policies := []unstructured.Unstructured{makeVAP("policy-a", "C-0001")}
	bindings := []unstructured.Unstructured{
		makeVAPBScoped("binding-a", "policy-a", matchLabels("env", "prod"), nil),
	}
	failing := map[string][]ResourceInfo{
		"C-0001": {
			{ResourceID: "res-1", APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"},
			{ResourceID: "res-2", APIVersion: "networking.k8s.io/v1beta1", Kind: "ServiceCIDR"},
			{ResourceID: "res-3", APIVersion: "networking.k8s.io/v1beta1", Kind: "IPAddress"},
			{ResourceID: "res-4", APIVersion: "cert-manager.io/v1", Kind: "ClusterIssuer"},
			{ResourceID: "res-5", APIVersion: "certificates.k8s.io/v1alpha1", Kind: "ClusterTrustBundle"},
			{ResourceID: "res-6", APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"},
		},
	}

	coverage := BuildCoverage(policies, bindings, failing, nil)

	c := coverage["C-0001"]
	require.NotNil(t, c)
	assert.True(t, c.FullyCovered(), "the apiserver enforces the binding on a cluster-scoped resource whatever the namespaceSelector says")
	require.Len(t, c.Resources, 6)
	for _, res := range c.Resources {
		assert.True(t, res.Covered)
		assert.Empty(t, res.Reason)
	}
}

// TestBuildCoverage_EcosystemClusterScopedKinds_CoveredUnderNamespaceSelector asserts that
// common ecosystem cluster-scoped CRDs (Kyverno ClusterPolicy, ExternalSecrets ClusterExternalSecret/
// ClusterSecretStore, Tekton ClusterTask/ClusterInterceptor, SPIRE ClusterSPIFFEID, and Policy WG
// ClusterPolicyReport) remain covered under namespaceSelector.
func TestBuildCoverage_EcosystemClusterScopedKinds_CoveredUnderNamespaceSelector(t *testing.T) {
	policies := []unstructured.Unstructured{makeVAP("policy-a", "C-0001")}
	bindings := []unstructured.Unstructured{
		makeVAPBScoped("binding-a", "policy-a", matchLabels("env", "prod"), nil),
	}
	failing := map[string][]ResourceInfo{
		"C-0001": {
			{ResourceID: "kp-1", APIVersion: "kyverno.io/v1", Kind: "ClusterPolicy"},
			{ResourceID: "ces-1", APIVersion: "external-secrets.io/v1beta1", Kind: "ClusterExternalSecret"},
			{ResourceID: "css-1", APIVersion: "external-secrets.io/v1beta1", Kind: "ClusterSecretStore"},
			{ResourceID: "ct-1", APIVersion: "tekton.dev/v1beta1", Kind: "ClusterTask"},
			{ResourceID: "ci-1", APIVersion: "triggers.tekton.dev/v1alpha1", Kind: "ClusterInterceptor"},
			{ResourceID: "cspiffe-1", APIVersion: "spiffeid.spiffe.io/v1beta1", Kind: "ClusterSPIFFEID"},
			{ResourceID: "cpr-1", APIVersion: "wgpolicyk8s.io/v1alpha2", Kind: "ClusterPolicyReport"},
		},
	}

	coverage := BuildCoverage(policies, bindings, failing, nil)

	c := coverage["C-0001"]
	require.NotNil(t, c)
	assert.True(t, c.FullyCovered(), "ecosystem cluster-scoped CRDs must remain covered under a namespaceSelector")
	require.Len(t, c.Resources, 7)
	for _, res := range c.Resources {
		assert.True(t, res.Covered, "resource %s of kind should be covered", res.ResourceID)
		assert.Empty(t, res.Reason)
	}
}

// TestBuildCoverage_UncatalogedClusterPrefixedKind_ScopeUndetermined asserts that an
// uncataloged CRD whose Kind starts with "Cluster" but is not in knownClusterScopedKinds
// has an undetermined scope when metadata.namespace is omitted, and is reported as uncovered
// rather than falsely assumed to be cluster-scoped.
func TestBuildCoverage_UncatalogedClusterPrefixedKind_ScopeUndetermined(t *testing.T) {
	policies := []unstructured.Unstructured{makeVAP("policy-a", "C-0001")}
	bindings := []unstructured.Unstructured{
		makeVAPBScoped("binding-a", "policy-a", matchLabels("env", "prod"), nil),
	}
	failing := map[string][]ResourceInfo{
		"C-0001": {
			{ResourceID: "cgeneric-1", APIVersion: "custom.io/v1", Kind: "ClusterCustomResource"},
		},
	}

	coverage := BuildCoverage(policies, bindings, failing, nil)

	c := coverage["C-0001"]
	require.NotNil(t, c)
	assert.False(t, c.FullyCovered())
	require.Len(t, c.Resources, 1)
	assert.False(t, c.Resources[0].Covered)
	assert.Equal(t, "namespaceSelector is set but the resource's scope could not be determined and it has no namespace", c.Resources[0].Reason)
}

// TestBuildCoverage_ClusterPrefixedNamespacedCRDs_NotOverCredited asserts that namespaced CRDs
// whose Kind begins with or equals "Cluster" (such as ClusterServiceVersion and Cluster)
// are not falsely over-credited as cluster-scoped when metadata.namespace is omitted.
func TestBuildCoverage_ClusterPrefixedNamespacedCRDs_NotOverCredited(t *testing.T) {
	policies := []unstructured.Unstructured{makeVAP("policy-a", "C-0001")}
	bindings := []unstructured.Unstructured{
		makeVAPBScoped("binding-a", "policy-a", matchLabels("env", "prod"), nil),
	}
	failing := map[string][]ResourceInfo{
		"C-0001": {
			// Namespaced CRDs lacking metadata.namespace: must NOT be treated as cluster-scoped
			{ResourceID: "csv-1", APIVersion: "operators.coreos.com/v1alpha1", Kind: "ClusterServiceVersion", Name: "my-operator.v1.0.0", Namespace: ""},
			{ResourceID: "cnpg-1", APIVersion: "postgresql.cnpg.io/v1", Kind: "Cluster", Name: "pg-cluster", Namespace: ""},
			{ResourceID: "capi-1", APIVersion: "cluster.x-k8s.io/v1beta1", Kind: "Cluster", Name: "k8s-cluster", Namespace: ""},
			// Same resources with matching explicit namespace: must be covered
			{ResourceID: "csv-prod", APIVersion: "operators.coreos.com/v1alpha1", Kind: "ClusterServiceVersion", Name: "my-operator.v1.0.0", Namespace: "prod"},
			// Same resources with non-matching explicit namespace: must be uncovered with selector mismatch
			{ResourceID: "csv-dev", APIVersion: "operators.coreos.com/v1alpha1", Kind: "ClusterServiceVersion", Name: "my-operator.v1.0.0", Namespace: "dev"},
		},
	}
	nsLabels := map[string]map[string]string{
		"prod": {"env": "prod"},
		"dev":  {"env": "dev"},
	}

	coverage := BuildCoverage(policies, bindings, failing, nsLabels)

	c := coverage["C-0001"]
	require.NotNil(t, c)
	assert.True(t, c.Bound)
	assert.False(t, c.FullyCovered())
	assert.True(t, c.PartiallyCovered())
	require.Len(t, c.Resources, 5)

	// csv-1, cnpg-1, capi-1: recognized as namespaced CRDs lacking namespace, must not be over-credited as cluster-scoped
	for i := 0; i < 3; i++ {
		assert.False(t, c.Resources[i].Covered, "namespaced CRD %s lacking namespace must not be over-credited", c.Resources[i].ResourceID)
		assert.Equal(t, "namespaceSelector is set but namespaced resource has no namespace specified", c.Resources[i].Reason)
	}

	// csv-prod: matching namespace -> covered
	assert.True(t, c.Resources[3].Covered)
	assert.Empty(t, c.Resources[3].Reason)

	// csv-dev: non-matching namespace -> uncovered with selector mismatch
	assert.False(t, c.Resources[4].Covered)
	assert.Contains(t, c.Resources[4].Reason, "namespaceSelector does not match")
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

	byControl := CollectFailingResourcesByControl(nil, resourcesResult, allResources)

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

type trackingCatalog struct {
	resources map[string]workloadinterface.IMetadata
	getCalls  map[string]int
}

func (tc *trackingCatalog) Get(id string) (workloadinterface.IMetadata, bool) {
	if tc.getCalls == nil {
		tc.getCalls = make(map[string]int)
	}
	tc.getCalls[id]++
	res, ok := tc.resources[id]
	return res, ok
}

func (tc *trackingCatalog) ForEach(fn func(id string, res workloadinterface.IMetadata) bool) {
	for k, v := range tc.resources {
		if !fn(k, v) {
			break
		}
	}
}

func TestCollectFailingResourcesByControlFromCatalog_OnDemandLookup(t *testing.T) {
	failingWL := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      "fail-app",
			"namespace": "default",
			"labels":    map[string]any{"tier": "critical"},
		},
	})
	passingWL := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      "pass-app",
			"namespace": "default",
		},
	})

	tc := &trackingCatalog{
		resources: map[string]workloadinterface.IMetadata{
			failingWL.GetID(): failingWL,
			passingWL.GetID(): passingWL,
		},
	}

	resourcesResult := map[string]resourcesresults.Result{
		failingWL.GetID(): {
			ResourceID: failingWL.GetID(),
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{
					ControlID: "C-0001",
					Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
				},
			},
		},
		passingWL.GetID(): {
			ResourceID: passingWL.GetID(),
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{
					ControlID: "C-0002",
					Status:    apis.StatusInfo{InnerStatus: apis.StatusPassed},
				},
			},
		},
	}

	byControl := CollectFailingResourcesByControlFromCatalog(nil, resourcesResult, tc)
	require.Contains(t, byControl, "C-0001")
	assert.Equal(t, 1, tc.getCalls[failingWL.GetID()], "failing workload should be retrieved on demand")
	assert.Equal(t, 0, tc.getCalls[passingWL.GetID()], "passing workload without failures should never be retrieved from catalog")

	// Nil catalog handling
	assert.Empty(t, CollectFailingResourcesByControlFromCatalog(nil, resourcesResult, nil))
}

func TestCollectNamespaceLabelsFromCatalog_IteratesNamespaces(t *testing.T) {
	ns := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]any{
			"name":   "stage",
			"labels": map[string]any{"env": "staging"},
		},
	})
	pod := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "app",
			"namespace": "stage",
		},
	})

	tc := &trackingCatalog{
		resources: map[string]workloadinterface.IMetadata{
			ns.GetID():  ns,
			pod.GetID(): pod,
		},
	}

	nsLabels := CollectNamespaceLabelsFromCatalog(tc)
	require.Contains(t, nsLabels, "stage")
	assert.Equal(t, map[string]string{"env": "staging"}, nsLabels["stage"])
	assert.Len(t, nsLabels, 1)

	// Nil catalog handling
	assert.Empty(t, CollectNamespaceLabelsFromCatalog(nil))
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

func TestCollectFailingResourcesByControl_FrameworkScopedException(t *testing.T) {
	controlID := "C-0041"
	otherControlID := "C-0017"
	workload := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      "test-app",
			"namespace": "default",
		},
	})
	resourceID := workload.GetID()

	exceptedRule := resourcesresults.ResourceAssociatedRule{
		Name:   "rule-1",
		Status: apis.StatusFailed,
		Exception: []armotypes.PostureExceptionPolicy{
			{
				PortalBase:      armotypes.PortalBase{Name: "nsa-exception"},
				Actions:         []armotypes.PostureExceptionPolicyActions{armotypes.Disable},
				PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: controlID}},
			},
		},
	}

	resourcesResult := map[string]resourcesresults.Result{
		resourceID: {
			ResourceID: resourceID,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{
					ControlID:               controlID,
					Status:                  apis.StatusInfo{InnerStatus: apis.StatusFailed},
					ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{exceptedRule},
				},
				{
					ControlID:               otherControlID,
					Status:                  apis.StatusInfo{InnerStatus: apis.StatusFailed},
					ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Name: "rule-2", Status: apis.StatusFailed}},
				},
			},
		},
	}
	allResources := map[string]workloadinterface.IMetadata{resourceID: workload}

	// 1. Scanned with framework "NSA":
	// The exception applies to C-0041, so C-0041 must NOT include the workload.
	// C-0017 has no exception, so it MUST include the workload.
	nsaSummary := &reportsummary.SummaryDetails{
		Frameworks: []reportsummary.FrameworkSummary{
			{
				Name: "NSA",
				Controls: reportsummary.ControlSummaries{
					controlID:      reportsummary.ControlSummary{ControlID: controlID},
					otherControlID: reportsummary.ControlSummary{ControlID: otherControlID},
				},
			},
		},
	}
	byControlNSA := CollectFailingResourcesByControl(nsaSummary, resourcesResult, allResources)
	assert.NotContains(t, byControlNSA, controlID, "excepted control must not be collected as failing")
	assert.Contains(t, byControlNSA, otherControlID, "unexcepted failing control must still be collected")
	assert.Len(t, byControlNSA[otherControlID], 1)

	// 2. Scanned with another framework (e.g. "MITRE") where the exception does not apply:
	// Both controls must include the workload.
	mitreSummary := &reportsummary.SummaryDetails{
		Frameworks: []reportsummary.FrameworkSummary{
			{
				Name: "MITRE",
				Controls: reportsummary.ControlSummaries{
					controlID:      reportsummary.ControlSummary{ControlID: controlID},
					otherControlID: reportsummary.ControlSummary{ControlID: otherControlID},
				},
			},
		},
	}
	byControlMITRE := CollectFailingResourcesByControl(mitreSummary, resourcesResult, allResources)
	assert.Contains(t, byControlMITRE, controlID, "control without matching exception must be collected as failing")
	assert.Contains(t, byControlMITRE, otherControlID)

	// 3. Without framework context (summary == nil):
	// Framework-scoped exception does not apply, so both controls are collected as failing.
	byControlNil := CollectFailingResourcesByControl(nil, resourcesResult, allResources)
	assert.Contains(t, byControlNil, controlID)
	assert.Contains(t, byControlNil, otherControlID)
}

func TestBuildCoverage_NamespacedResourceWithoutNamespaceNotCoveredByNamespaceSelector(t *testing.T) {
	policies := []unstructured.Unstructured{makeVAP("policy-a", "C-0001")}
	bindings := []unstructured.Unstructured{
		makeVAPBScoped("binding-a", "policy-a", matchLabels("env", "prod"), nil),
	}
	failing := map[string][]ResourceInfo{
		"C-0001": {
			{ResourceID: "deploy-1", APIVersion: "apps/v1", Kind: "Deployment", Name: "my-deploy", Namespace: ""},
			{ResourceID: "pod-1", APIVersion: "v1", Kind: "Pod", Name: "my-pod", Namespace: ""},
			{ResourceID: "service-1", APIVersion: "v1", Kind: "Service", Name: "my-svc", Namespace: ""},
			{ResourceID: "custom-1", APIVersion: "example.com/v1", Kind: "Widget", Name: "my-widget", Namespace: ""},
		},
	}
	nsLabels := map[string]map[string]string{
		"prod": {"env": "prod"},
	}

	coverage := BuildCoverage(policies, bindings, failing, nsLabels)

	c := coverage["C-0001"]
	require.NotNil(t, c)
	assert.True(t, c.Bound)
	assert.False(t, c.FullyCovered())
	assert.False(t, c.PartiallyCovered())
	require.Len(t, c.Resources, 4)

	for i := 0; i < 3; i++ {
		assert.False(t, c.Resources[i].Covered)
		assert.Equal(t, "namespaceSelector is set but namespaced resource has no namespace specified", c.Resources[i].Reason)
	}
	assert.False(t, c.Resources[3].Covered)
	assert.Equal(t, "namespaceSelector is set but the resource's scope could not be determined and it has no namespace", c.Resources[3].Reason)
}

func TestBuildCoverage_NamespacedResourceWithoutNamespaceCoveredWhenNoNamespaceSelector(t *testing.T) {
	policies := []unstructured.Unstructured{makeVAP("policy-a", "C-0001")}
	bindings := []unstructured.Unstructured{
		makeVAPBScoped("binding-a", "policy-a", nil, nil),
	}
	failing := map[string][]ResourceInfo{
		"C-0001": {
			{ResourceID: "deploy-1", APIVersion: "apps/v1", Kind: "Deployment", Name: "my-deploy", Namespace: ""},
		},
	}

	coverage := BuildCoverage(policies, bindings, failing, nil)

	c := coverage["C-0001"]
	require.NotNil(t, c)
	assert.True(t, c.Bound)
	assert.True(t, c.FullyCovered())
	require.Len(t, c.Resources, 1)
	assert.True(t, c.Resources[0].Covered)
	assert.Empty(t, c.Resources[0].Reason)
}
