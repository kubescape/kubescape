package vapreconcile

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	discoveryfake "k8s.io/client-go/discovery/fake"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	discoveryfake "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func makeVAP(name, controlID string) unstructured.Unstructured {
	u := unstructured.Unstructured{}
	u.SetName(name)
	if controlID != "" {
		u.SetLabels(map[string]string{"controlId": controlID})
	}
	return u
}

func makeVAPB(name, policyName string, actions []string) unstructured.Unstructured {
	u := unstructured.Unstructured{
		Object: map[string]any{
			"spec": map[string]any{
				"policyName":        policyName,
				"validationActions": toInterfaceSlice(actions),
			},
		},
	}
	u.SetName(name)
	return u
}

func toInterfaceSlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// discoveryServing returns a discovery client advertising the VAP API on every
// given version, plus the webhook resources every supported cluster serves.
func discoveryServing(versions ...string) *discoveryfake.FakeDiscovery {
	client := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	for _, version := range versions {
		client.Resources = append(client.Resources, &metav1.APIResourceList{
			GroupVersion: vapGroup + "/" + version,
			APIResources: []metav1.APIResource{
				{Name: "validatingwebhookconfigurations", Kind: "ValidatingWebhookConfiguration"},
				{Name: vapResource, Kind: "ValidatingAdmissionPolicy"},
				{Name: vapBindingResource, Kind: "ValidatingAdmissionPolicyBinding"},
			},
		})
	}
	return client
}

// dynamicServing returns a dynamic client holding the given objects under the
// VAP resources of one version.
func dynamicServing(version string, objects ...runtime.Object) *dynamicfake.FakeDynamicClient {
	listKinds := map[schema.GroupVersionResource]string{
		{Group: vapGroup, Version: version, Resource: vapResource}:        "ValidatingAdmissionPolicyList",
		{Group: vapGroup, Version: version, Resource: vapBindingResource}: "ValidatingAdmissionPolicyBindingList",
	}
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objects...)
}

func servedVAP(version, name, controlID string) *unstructured.Unstructured {
	vap := makeVAP(name, controlID)
	vap.SetAPIVersion(vapGroup + "/" + version)
	vap.SetKind("ValidatingAdmissionPolicy")
	return &vap
}

func TestResolveVersion_PrefersNewestServedVersion(t *testing.T) {
	version, err := resolveVersion(discoveryServing("v1", "v1beta1", "v1alpha1"))

	require.NoError(t, err)
	assert.Equal(t, "v1", version)
}

func TestResolveVersion_FallsBackToOlderVersions(t *testing.T) {
	for _, served := range []string{"v1beta1", "v1alpha1"} {
		t.Run(served, func(t *testing.T) {
			version, err := resolveVersion(discoveryServing(served))

			require.NoError(t, err)
			assert.Equal(t, served, version)
		})
	}
}

func TestResolveVersion_GroupWithoutPolicyResources(t *testing.T) {
	// pre-1.26 clusters serve the group for webhook configurations only
	client := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	client.Resources = []*metav1.APIResourceList{{
		GroupVersion: vapGroup + "/v1",
		APIResources: []metav1.APIResource{
			{Name: "validatingwebhookconfigurations", Kind: "ValidatingWebhookConfiguration"},
		},
	}}

	_, err := resolveVersion(client)

	assert.ErrorIs(t, err, ErrUnsupported)
}

func TestResolveVersion_BindingsNotServed(t *testing.T) {
	client := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	client.Resources = []*metav1.APIResourceList{{
		GroupVersion: vapGroup + "/v1",
		APIResources: []metav1.APIResource{{Name: vapResource, Kind: "ValidatingAdmissionPolicy"}},
	}}

	_, err := resolveVersion(client)

	assert.ErrorIs(t, err, ErrUnsupported)
}

func TestResolveVersion_NoGroupAtAll(t *testing.T) {
	_, err := resolveVersion(&discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}})

	assert.ErrorIs(t, err, ErrUnsupported)
}

func TestResolveVersion_WithoutDiscoveryClient(t *testing.T) {
	version, err := resolveVersion(nil)

	require.NoError(t, err)
	assert.Equal(t, "v1", version)
}

func TestCollect_ReadsFromServedVersion(t *testing.T) {
	k8s := &k8sinterface.KubernetesApi{
		DiscoveryClient: discoveryServing("v1beta1"),
		DynamicClient:   dynamicServing("v1beta1", servedVAP("v1beta1", "kubescape-c-0041", "C-0041")),
	}

	policies, bindings, err := Collect(context.Background(), k8s)

	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, "kubescape-c-0041", policies[0].GetName())
	assert.Empty(t, bindings)
}

func TestCollect_UnsupportedClusterIsNotAFailure(t *testing.T) {
	k8s := &k8sinterface.KubernetesApi{
		DiscoveryClient: &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}},
		DynamicClient:   dynamicServing("v1"),
	}

	policies, bindings, err := Collect(context.Background(), k8s)

	assert.ErrorIs(t, err, ErrUnsupported)
	assert.Nil(t, policies)
	assert.Nil(t, bindings)
}

func TestBuildIndex_BoundDeny(t *testing.T) {
	policies := []unstructured.Unstructured{
		makeVAP("kubescape-c-0041-deny-host-network", "C-0041"),
	}
	bindings := []unstructured.Unstructured{
		makeVAPB("c0041-binding", "kubescape-c-0041-deny-host-network", []string{"Deny"}),
	}

	index := BuildIndex(policies, bindings)

	assert.Contains(t, index, "C-0041")
	assert.Equal(t, "kubescape-c-0041-deny-host-network", index["C-0041"].PolicyName)
	assert.True(t, index["C-0041"].Bound)
	assert.Equal(t, []string{"Deny"}, index["C-0041"].Actions)
}

func TestBuildIndex_BoundWarn(t *testing.T) {
	policies := []unstructured.Unstructured{
		makeVAP("kubescape-c-0016-privilege-escalation", "C-0016"),
	}
	bindings := []unstructured.Unstructured{
		makeVAPB("c0016-binding", "kubescape-c-0016-privilege-escalation", []string{"Warn"}),
	}

	index := BuildIndex(policies, bindings)

	assert.True(t, index["C-0016"].Bound)
	assert.Equal(t, []string{"Warn"}, index["C-0016"].Actions)
}

func TestBuildIndex_VAPWithNoBinding(t *testing.T) {
	policies := []unstructured.Unstructured{
		makeVAP("kubescape-c-0038-host-ipc", "C-0038"),
	}

	index := BuildIndex(policies, nil)

	assert.Contains(t, index, "C-0038")
	assert.False(t, index["C-0038"].Bound)
	assert.Nil(t, index["C-0038"].Actions)
}

func TestBuildIndex_VAPWithNoControlIDLabel(t *testing.T) {
	// VAPs without controlId label (e.g. runtime policies) should be ignored
	policies := []unstructured.Unstructured{
		makeVAP("cluster-policy-deny-exec", ""),
	}

	index := BuildIndex(policies, nil)

	assert.Empty(t, index)
}

func TestBuildIndex_BindingForUnknownPolicy(t *testing.T) {
	// binding points to a policy not in our VAP list — should not panic or error
	policies := []unstructured.Unstructured{
		makeVAP("kubescape-c-0041-deny-host-network", "C-0041"),
	}
	bindings := []unstructured.Unstructured{
		makeVAPB("unknown-binding", "some-other-policy", []string{"Deny"}),
	}

	index := BuildIndex(policies, bindings)

	assert.False(t, index["C-0041"].Bound)
}

func TestBuildIndex_MultipleControls(t *testing.T) {
	policies := []unstructured.Unstructured{
		makeVAP("kubescape-c-0041-deny-host-network", "C-0041"),
		makeVAP("kubescape-c-0016-privilege-escalation", "C-0016"),
		makeVAP("kubescape-c-0038-host-ipc", "C-0038"),
	}
	bindings := []unstructured.Unstructured{
		makeVAPB("c0041-binding", "kubescape-c-0041-deny-host-network", []string{"Warn"}),
		makeVAPB("c0016-binding", "kubescape-c-0016-privilege-escalation", []string{"Deny"}),
		// C-0038 has no binding
	}

	index := BuildIndex(policies, bindings)

	assert.Len(t, index, 3)
	assert.True(t, index["C-0041"].Bound)
	assert.Equal(t, []string{"Warn"}, index["C-0041"].Actions)
	assert.True(t, index["C-0016"].Bound)
	assert.Equal(t, []string{"Deny"}, index["C-0016"].Actions)
	assert.False(t, index["C-0038"].Bound)
}

func TestBuildIndex_SameControlMultipleBindings(t *testing.T) {
	// two bindings pointing at the same policy — actions should be merged, not overwritten
	policies := []unstructured.Unstructured{
		makeVAP("kubescape-c-0041-deny-host-network", "C-0041"),
	}
	bindings := []unstructured.Unstructured{
		makeVAPB("c0041-binding-deny", "kubescape-c-0041-deny-host-network", []string{"Deny"}),
		makeVAPB("c0041-binding-audit", "kubescape-c-0041-deny-host-network", []string{"Audit"}),
	}

	index := BuildIndex(policies, bindings)

	assert.True(t, index["C-0041"].Bound)
	assert.ElementsMatch(t, []string{"Deny", "Audit"}, index["C-0041"].Actions)
}

func TestEnrichSummary_AttachesStatus(t *testing.T) {
	controls := reportsummary.ControlSummaries{
		"C-0041": reportsummary.ControlSummary{ControlID: "C-0041"},
		"C-0016": reportsummary.ControlSummary{ControlID: "C-0016"},
	}
	index := map[string]*reportsummary.VAPEnforcementStatus{
		"C-0041": {PolicyName: "kubescape-c-0041", Bound: true, Actions: []string{"Warn"}},
	}

	EnrichSummary(controls, index)

	assert.NotNil(t, controls["C-0041"].VAPEnforcement)
	assert.Equal(t, "kubescape-c-0041", controls["C-0041"].VAPEnforcement.PolicyName)
	assert.True(t, controls["C-0041"].VAPEnforcement.Bound)
	// C-0016 has no VAP — field should remain nil
	assert.Nil(t, controls["C-0016"].VAPEnforcement)
}

func TestEnrichSummary_NoMatchingControl(t *testing.T) {
	// index has a controlId that isn't in the scan results — should not panic
	controls := reportsummary.ControlSummaries{
		"C-0041": reportsummary.ControlSummary{ControlID: "C-0041"},
	}
	index := map[string]*reportsummary.VAPEnforcementStatus{
		"C-9999": {PolicyName: "some-policy", Bound: true, Actions: []string{"Deny"}},
	}

	assert.NotPanics(t, func() {
		EnrichSummary(controls, index)
	})
	assert.Nil(t, controls["C-0041"].VAPEnforcement)
}

func TestCollect_GracefulSkip(t *testing.T) {
	discovery := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discovery.Resources = []*metav1.APIResourceList{} // No resources

	k8s := &k8sinterface.KubernetesApi{
		DiscoveryClient: discovery,
	}

	vaps, vapbs, err := Collect(context.Background(), k8s)

	assert.NoError(t, err)
	assert.Nil(t, vaps)
	assert.Nil(t, vapbs)
}

func TestCollect_GracefulSkip_Incomplete(t *testing.T) {
	discovery := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discovery.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "admissionregistration.k8s.io/v1beta1",
			APIResources: []metav1.APIResource{
				{Name: "validatingadmissionpolicies"},
				// missing validatingadmissionpolicybindings
			},
		},
	}

	k8s := &k8sinterface.KubernetesApi{
		DiscoveryClient: discovery,
	}

	vaps, vapbs, err := Collect(context.Background(), k8s)

	assert.NoError(t, err)
	assert.Nil(t, vaps)
	assert.Nil(t, vapbs)
}

func TestCollect_GracefulSkip_Fallback_Unavailable(t *testing.T) {
	discovery := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	// Both missing
	discovery.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "admissionregistration.k8s.io/v1beta1",
			APIResources: []metav1.APIResource{
				{Name: "other"},
			},
		},
		{
			GroupVersion: "admissionregistration.k8s.io/v1",
			APIResources: []metav1.APIResource{
				{Name: "other"},
			},
		},
	}

	k8s := &k8sinterface.KubernetesApi{
		DiscoveryClient: discovery,
	}

	vaps, vapbs, err := Collect(context.Background(), k8s)

	assert.NoError(t, err)
	assert.Nil(t, vaps)
	assert.Nil(t, vapbs)
}
