package mapreconcile

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1alpha1 "k8s.io/api/admissionregistration/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	discoveryfake "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func discoveryServing(versions ...string) *discoveryfake.FakeDiscovery {
	client := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	for _, version := range versions {
		client.Resources = append(client.Resources, &metav1.APIResourceList{
			GroupVersion: mapGroup + "/" + version,
			APIResources: []metav1.APIResource{
				{Name: mapResource, Kind: "MutatingAdmissionPolicy"},
				{Name: mapBindingResource, Kind: "MutatingAdmissionPolicyBinding"},
			},
		})
	}
	return client
}

func dynamicServing(version string, objects ...runtime.Object) *dynamicfake.FakeDynamicClient {
	listKinds := map[schema.GroupVersionResource]string{
		{Group: mapGroup, Version: version, Resource: mapResource}:        "MutatingAdmissionPolicyList",
		{Group: mapGroup, Version: version, Resource: mapBindingResource}: "MutatingAdmissionPolicyBindingList",
	}
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objects...)
}

func unstructuredMAP(name string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": mapGroup + "/v1alpha1",
		"kind":       "MutatingAdmissionPolicy",
		"metadata":   map[string]any{"name": name},
		"spec": map[string]any{
			"matchConstraints": map[string]any{
				"resourceRules": []any{
					map[string]any{
						"apiGroups":   []any{""},
						"apiVersions": []any{"v1"},
						"resources":   []any{"pods"},
						"operations":  []any{"CREATE"},
					},
				},
			},
			"mutations": []any{
				map[string]any{
					"patchType": "JSONPatch",
					"jsonPatch": map[string]any{"expression": `[JSONPatch{op: "add", path: "/metadata/labels/x", value: "y"}]`},
				},
			},
			"reinvocationPolicy": "Never",
		},
	}}
	return u
}

func unstructuredMAPBinding(name, policyName string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": mapGroup + "/v1alpha1",
		"kind":       "MutatingAdmissionPolicyBinding",
		"metadata":   map[string]any{"name": name},
		"spec": map[string]any{
			"policyName": policyName,
		},
	}}
}

func TestResolveVersion_ServedVersion(t *testing.T) {
	version, err := resolveVersion(discoveryServing("v1alpha1"))

	require.NoError(t, err)
	assert.Equal(t, "v1alpha1", version)
}

func TestResolveVersion_UnservedGroupIsUnsupported(t *testing.T) {
	_, err := resolveVersion(&discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}})

	assert.ErrorIs(t, err, ErrUnsupported)
}

func TestResolveVersion_GroupWithoutBindingsIsUnsupported(t *testing.T) {
	client := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	client.Resources = []*metav1.APIResourceList{{
		GroupVersion: mapGroup + "/v1alpha1",
		APIResources: []metav1.APIResource{{Name: mapResource, Kind: "MutatingAdmissionPolicy"}},
	}}

	_, err := resolveVersion(client)

	assert.ErrorIs(t, err, ErrUnsupported)
}

func TestResolveVersion_WithoutDiscoveryClient(t *testing.T) {
	version, err := resolveVersion(nil)

	require.NoError(t, err)
	assert.Equal(t, "v1alpha1", version)
}

func TestCollect_ReadsFromServedVersion(t *testing.T) {
	k8s := &k8sinterface.KubernetesApi{
		DiscoveryClient: discoveryServing("v1alpha1"),
		DynamicClient:   dynamicServing("v1alpha1", unstructuredMAP("policy-a"), unstructuredMAPBinding("binding-a", "policy-a")),
	}

	policies, bindings, decodeErrs, err := Collect(context.Background(), k8s)

	require.NoError(t, err)
	require.Empty(t, decodeErrs)
	require.Len(t, policies, 1)
	assert.Equal(t, "policy-a", policies[0].Name)
	require.Len(t, policies[0].Spec.Mutations, 1)
	assert.Equal(t, admissionregistrationv1alpha1.PatchTypeJSONPatch, policies[0].Spec.Mutations[0].PatchType)
	require.Len(t, bindings, 1)
	assert.Equal(t, "policy-a", bindings[0].Spec.PolicyName)
}

func TestCollect_UnsupportedClusterIsNotAFailure(t *testing.T) {
	k8s := &k8sinterface.KubernetesApi{
		DiscoveryClient: &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}},
		DynamicClient:   dynamicServing("v1alpha1"),
	}

	policies, bindings, decodeErrs, err := Collect(context.Background(), k8s)

	assert.ErrorIs(t, err, ErrUnsupported)
	assert.Nil(t, policies)
	assert.Nil(t, bindings)
	assert.Nil(t, decodeErrs)
}

func TestCollect_MalformedPolicyIsSkippedNotFatal(t *testing.T) {
	bad := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": mapGroup + "/v1alpha1",
		"kind":       "MutatingAdmissionPolicy",
		"metadata":   map[string]any{"name": "bad"},
		"spec": map[string]any{
			// reinvocationPolicy must decode to a string; a nested object here
			// makes the whole object fail its JSON round-trip.
			"reinvocationPolicy": map[string]any{"not": "a string"},
		},
	}}
	good := unstructuredMAP("good")

	k8s := &k8sinterface.KubernetesApi{
		DiscoveryClient: discoveryServing("v1alpha1"),
		DynamicClient:   dynamicServing("v1alpha1", bad, good),
	}

	policies, _, decodeErrs, err := Collect(context.Background(), k8s)

	require.NoError(t, err)
	require.Len(t, decodeErrs, 1)
	require.Len(t, policies, 1)
	assert.Equal(t, "good", policies[0].Name)
}
