package mcpserver

import (
	"encoding/json"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	discoveryfake "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

var (
	mutatingAdmissionPolicyGVR        = schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1alpha1", Resource: "mutatingadmissionpolicies"}
	mutatingAdmissionPolicyBindingGVR = schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1alpha1", Resource: "mutatingadmissionpolicybindings"}
	testPodGVR                        = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
)

func unstructuredTestPod(namespace, name string, labels map[string]any) *unstructured.Unstructured {
	obj := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
		},
	}
	if labels != nil {
		obj["metadata"].(map[string]any)["labels"] = labels
	}
	return &unstructured.Unstructured{Object: obj}
}

func newMutatingPolicyTestServer(t *testing.T, objects ...runtime.Object) *KubescapeMcpserver {
	t.Helper()
	listKinds := map[schema.GroupVersionResource]string{
		mutatingAdmissionPolicyGVR:        "MutatingAdmissionPolicyList",
		mutatingAdmissionPolicyBindingGVR: "MutatingAdmissionPolicyBindingList",
		namespaceGVR:                      "NamespaceList",
		testPodGVR:                        "PodList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objects...)

	discovery := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discovery.Resources = []*metav1.APIResourceList{{
		GroupVersion: "admissionregistration.k8s.io/v1alpha1",
		APIResources: []metav1.APIResource{
			{Name: "mutatingadmissionpolicies", Kind: "MutatingAdmissionPolicy"},
			{Name: "mutatingadmissionpolicybindings", Kind: "MutatingAdmissionPolicyBinding"},
		},
	}}

	ksServer := &KubescapeMcpserver{
		s: server.NewMCPServer(
			"kubescape-test",
			"test",
			server.WithToolCapabilities(false),
			server.WithRecovery(),
		),
		k8sClient: &k8sinterface.KubernetesApi{DynamicClient: dyn, DiscoveryClient: discovery},
	}
	createMutatingAdmissionPolicyTools(ksServer)
	return ksServer
}

func unstructuredMutatingPolicy(name string, matchConstraints map[string]any, mutations ...map[string]any) *unstructured.Unstructured {
	spec := map[string]any{
		"matchConstraints": matchConstraints,
	}
	if len(mutations) > 0 {
		muts := make([]any, len(mutations))
		for i, m := range mutations {
			muts[i] = m
		}
		spec["mutations"] = muts
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "admissionregistration.k8s.io/v1alpha1",
		"kind":       "MutatingAdmissionPolicy",
		"metadata":   map[string]any{"name": name},
		"spec":       spec,
	}}
}

func unstructuredMutatingPolicyBinding(name, policyName string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "admissionregistration.k8s.io/v1alpha1",
		"kind":       "MutatingAdmissionPolicyBinding",
		"metadata":   map[string]any{"name": name},
		"spec":       map[string]any{"policyName": policyName},
	}}
}

func allPodsMatchConstraints() map[string]any {
	return map[string]any{
		"resourceRules": []any{
			map[string]any{
				"apiGroups":   []any{""},
				"apiVersions": []any{"v1"},
				"resources":   []any{"pods"},
				"operations":  []any{"*"},
			},
		},
	}
}

func TestAnalyzeMutatingAdmissionPolicyImpact_UnboundPolicyIsNotReported(t *testing.T) {
	policy := unstructuredMutatingPolicy("add-label", allPodsMatchConstraints(),
		map[string]any{"patchType": "JSONPatch", "jsonPatch": map[string]any{"expression": `[JSONPatch{op: "add", path: "/metadata/labels/x", value: "y"}]`}},
	)
	pod := unstructuredTestPod("prod", "server", map[string]any{"app": "server"})

	ksServer := newMutatingPolicyTestServer(t, policy, pod)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", map[string]any{
		"namespace":   "prod",
		"name":        "server",
		"api_version": "v1",
		"resource":    "pods",
	}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	require.True(t, parsed["supported"].(bool))
	require.Empty(t, parsed["matches"])
}

func TestAnalyzeMutatingAdmissionPolicyImpact_BoundPolicyMatchingResourceIsReported(t *testing.T) {
	policy := unstructuredMutatingPolicy("add-label", allPodsMatchConstraints(),
		map[string]any{"patchType": "JSONPatch", "jsonPatch": map[string]any{"expression": `[JSONPatch{op: "add", path: "/metadata/labels/x", value: "y"}]`}},
	)
	binding := unstructuredMutatingPolicyBinding("add-label-binding", "add-label")
	pod := unstructuredTestPod("prod", "server", map[string]any{"app": "server"})

	ksServer := newMutatingPolicyTestServer(t, policy, binding, pod)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", map[string]any{
		"namespace":   "prod",
		"name":        "server",
		"api_version": "v1",
		"resource":    "pods",
	}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	matches, ok := parsed["matches"].([]any)
	require.True(t, ok)
	require.Len(t, matches, 1)
	m := matches[0].(map[string]any)
	require.Equal(t, "add-label", m["policy_name"])
	require.Equal(t, "add-label-binding", m["binding_name"])
	mutations := m["mutations"].([]any)
	require.Len(t, mutations, 1)
	require.Equal(t, "JSONPatch", mutations[0].(map[string]any)["patch_type"])
}

func TestAnalyzeMutatingAdmissionPolicyImpact_NonMatchingResourceExcludesPolicy(t *testing.T) {
	configmapsOnly := map[string]any{
		"resourceRules": []any{
			map[string]any{
				"apiGroups":   []any{""},
				"apiVersions": []any{"v1"},
				"resources":   []any{"configmaps"},
				"operations":  []any{"*"},
			},
		},
	}
	policy := unstructuredMutatingPolicy("configmap-only", configmapsOnly)
	binding := unstructuredMutatingPolicyBinding("b", "configmap-only")
	pod := unstructuredTestPod("prod", "server", map[string]any{"app": "server"})

	ksServer := newMutatingPolicyTestServer(t, policy, binding, pod)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", map[string]any{
		"namespace":   "prod",
		"name":        "server",
		"api_version": "v1",
		"resource":    "pods",
	}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	require.Empty(t, parsed["matches"])
}

func TestAnalyzeMutatingAdmissionPolicyImpact_MissingRequiredArgumentsReturnError(t *testing.T) {
	ksServer := newMutatingPolicyTestServer(t)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", map[string]any{
		"namespace": "prod",
		// name, api_version, resource deliberately omitted
	}))
	require.True(t, result.IsError)
}

func TestAnalyzeMutatingAdmissionPolicyImpact_InvalidOperationReturnsError(t *testing.T) {
	ksServer := newMutatingPolicyTestServer(t)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", map[string]any{
		"namespace":   "prod",
		"name":        "server",
		"api_version": "v1",
		"resource":    "pods",
		"operation":   "DELETE",
	}))
	require.True(t, result.IsError)
}

func TestAnalyzeMutatingAdmissionPolicyImpact_UnsupportedClusterReportsNotSupported(t *testing.T) {
	pod := unstructuredTestPod("prod", "server", map[string]any{"app": "server"})
	ksServer := newMutatingPolicyTestServer(t, pod)
	// Override discovery so the API is not served at all.
	ksServer.k8sClient.DiscoveryClient = &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", map[string]any{
		"namespace":   "prod",
		"name":        "server",
		"api_version": "v1",
		"resource":    "pods",
	}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	require.False(t, parsed["supported"].(bool))
}

func TestAnalyzeMutatingAdmissionPolicyImpact_ClusterScopedResourceIgnoresNamespace(t *testing.T) {
	policy := unstructuredMutatingPolicy("add-label-cr", map[string]any{
		"resourceRules": []any{
			map[string]any{
				"apiGroups":   []any{"rbac.authorization.k8s.io"},
				"apiVersions": []any{"v1"},
				"resources":   []any{"clusterroles"},
				"operations":  []any{"*"},
			},
		},
		"namespaceSelector": map[string]any{"matchLabels": map[string]any{"env": "prod"}},
	},
		map[string]any{"patchType": "JSONPatch", "jsonPatch": map[string]any{"expression": `[JSONPatch{op: "add", path: "/metadata/labels/x", value: "y"}]`}},
	)
	binding := unstructuredMutatingPolicyBinding("b", "add-label-cr")
	clusterRoleGVR := schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterroles"}
	clusterRole := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata":   map[string]any{"name": "my-role"},
	}}

	listKinds := map[schema.GroupVersionResource]string{
		mutatingAdmissionPolicyGVR:        "MutatingAdmissionPolicyList",
		mutatingAdmissionPolicyBindingGVR: "MutatingAdmissionPolicyBindingList",
		clusterRoleGVR:                    "ClusterRoleList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, policy, binding, clusterRole)
	discovery := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discovery.Resources = []*metav1.APIResourceList{{
		GroupVersion: "admissionregistration.k8s.io/v1alpha1",
		APIResources: []metav1.APIResource{
			{Name: "mutatingadmissionpolicies", Kind: "MutatingAdmissionPolicy"},
			{Name: "mutatingadmissionpolicybindings", Kind: "MutatingAdmissionPolicyBinding"},
		},
	}}
	ksServer := &KubescapeMcpserver{
		s:         server.NewMCPServer("kubescape-test", "test", server.WithToolCapabilities(false), server.WithRecovery()),
		k8sClient: &k8sinterface.KubernetesApi{DynamicClient: dyn, DiscoveryClient: discovery},
	}
	createMutatingAdmissionPolicyTools(ksServer)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", map[string]any{
		"name":           "my-role",
		"api_group":      "rbac.authorization.k8s.io",
		"api_version":    "v1",
		"resource":       "clusterroles",
		"cluster_scoped": true,
	}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	matches := parsed["matches"].([]any)
	require.Len(t, matches, 1, "namespaceSelector must not skip a cluster-scoped resource even with no namespace given")
}
