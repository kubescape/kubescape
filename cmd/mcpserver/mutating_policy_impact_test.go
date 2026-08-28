package mcpserver

import (
	"encoding/json"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/mark3labs/mcp-go/mcp"
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

func TestAnalyzeMutatingAdmissionPolicyImpact_MissingNamespaceReturnsErrorBeforeAnyClusterCall(t *testing.T) {
	// No discovery/dynamic resources are registered for the API at all, so if
	// the namespace-required check ran after Collect(), this would fail with
	// a "cluster does not serve" or list error instead of the intended
	// argument-validation error.
	ksServer := newMutatingPolicyTestServer(t)
	ksServer.k8sClient.DiscoveryClient = &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", map[string]any{
		"name":        "server",
		"api_version": "v1",
		"resource":    "pods",
		// namespace omitted, cluster_scoped omitted (false)
	}))
	require.True(t, result.IsError)
}

func TestAnalyzeMutatingAdmissionPolicyImpact_NamespaceObjectMatchesSelectorAgainstOwnLabels(t *testing.T) {
	policy := unstructuredMutatingPolicy("add-label-to-prod-namespaces", map[string]any{
		"resourceRules": []any{
			map[string]any{
				"apiGroups":   []any{""},
				"apiVersions": []any{"v1"},
				"resources":   []any{"namespaces"},
				"operations":  []any{"*"},
			},
		},
		"namespaceSelector": map[string]any{"matchLabels": map[string]any{"env": "prod"}},
	},
		map[string]any{"patchType": "JSONPatch", "jsonPatch": map[string]any{"expression": `[JSONPatch{op: "add", path: "/metadata/labels/x", value: "y"}]`}},
	)
	binding := unstructuredMutatingPolicyBinding("b", "add-label-to-prod-namespaces")

	nsGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
	prodNS := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]any{
			"name":   "prod",
			"labels": map[string]any{"env": "prod"},
		},
	}}
	devNS := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]any{
			"name":   "dev",
			"labels": map[string]any{"env": "dev"},
		},
	}}

	listKinds := map[schema.GroupVersionResource]string{
		mutatingAdmissionPolicyGVR:        "MutatingAdmissionPolicyList",
		mutatingAdmissionPolicyBindingGVR: "MutatingAdmissionPolicyBindingList",
		nsGVR:                             "NamespaceList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, policy, binding, prodNS, devNS)
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

	// The prod namespace's own labels satisfy the selector: it must match.
	prodResult := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", map[string]any{
		"name":           "prod",
		"api_version":    "v1",
		"resource":       "namespaces",
		"cluster_scoped": true,
	}))
	require.False(t, prodResult.IsError)
	var prodParsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, prodResult)), &prodParsed))
	require.Len(t, prodParsed["matches"].([]any), 1, "the prod namespace's own labels satisfy the selector and must match")

	// The dev namespace's own labels do not satisfy the selector: it must be
	// excluded, not treated as "cluster-scoped, selector doesn't apply".
	devResult := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", map[string]any{
		"name":           "dev",
		"api_version":    "v1",
		"resource":       "namespaces",
		"cluster_scoped": true,
	}))
	require.False(t, devResult.IsError)
	var devParsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, devResult)), &devParsed))
	require.Empty(t, devParsed["matches"], "the dev namespace's own labels must exclude it, not bypass the selector as a cluster-scoped object")
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

// matchConstraintsForResources is allPodsMatchConstraints for an arbitrary
// group/version/resources triple, so a test can scope a policy with the
// subresource form a resources entry may carry.
func matchConstraintsForResources(group, version string, resources ...string) map[string]any {
	named := make([]any, 0, len(resources))
	for _, resource := range resources {
		named = append(named, resource)
	}
	return map[string]any{
		"resourceRules": []any{
			map[string]any{
				"apiGroups":   []any{group},
				"apiVersions": []any{version},
				"resources":   named,
				"operations":  []any{"*"},
			},
		},
	}
}

// matchedPolicyNames pulls the matched policy names out of a tool result, so a
// test can assert on which policies matched without restating the whole
// response shape.
func matchedPolicyNames(t *testing.T, result *mcp.CallToolResult) []string {
	t.Helper()

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	require.True(t, parsed["supported"].(bool))

	matches, _ := parsed["matches"].([]any)
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m.(map[string]any)["policy_name"].(string))
	}
	return names
}

// TestAnalyzeMutatingAdmissionPolicyImpact_PolicyScopedToEveryResourceIsReported
// covers a policy scoped with "*/*", the documented way to name every resource
// and subresource. Reporting no match for it would hide a policy that mutates
// the whole cluster.
func TestAnalyzeMutatingAdmissionPolicyImpact_PolicyScopedToEveryResourceIsReported(t *testing.T) {
	policy := unstructuredMutatingPolicy("mutate-everything", matchConstraintsForResources("*", "*", "*/*"),
		map[string]any{"patchType": "JSONPatch", "jsonPatch": map[string]any{"expression": `[JSONPatch{op: "add", path: "/metadata/labels/x", value: "y"}]`}},
	)
	binding := unstructuredMutatingPolicyBinding("mutate-everything-binding", "mutate-everything")
	pod := unstructuredTestPod("prod", "server", map[string]any{"app": "server"})

	ksServer := newMutatingPolicyTestServer(t, policy, binding, pod)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", map[string]any{
		"namespace":   "prod",
		"name":        "server",
		"api_version": "v1",
		"resource":    "pods",
	}))
	require.False(t, result.IsError)
	require.Equal(t, []string{"mutate-everything"}, matchedPolicyNames(t, result))
}

// TestAnalyzeMutatingAdmissionPolicyImpact_SubresourceIsMatchedSeparately walks
// both directions of the parent/subresource split through the tool: a policy
// scoped to pods leaves pods/status alone, and one scoped to pods/status leaves
// the pod alone.
func TestAnalyzeMutatingAdmissionPolicyImpact_SubresourceIsMatchedSeparately(t *testing.T) {
	mutation := map[string]any{"patchType": "JSONPatch", "jsonPatch": map[string]any{"expression": `[JSONPatch{op: "add", path: "/metadata/labels/x", value: "y"}]`}}

	podPolicy := unstructuredMutatingPolicy("mutate-pods", allPodsMatchConstraints(), mutation)
	podBinding := unstructuredMutatingPolicyBinding("mutate-pods-binding", "mutate-pods")
	statusPolicy := unstructuredMutatingPolicy("mutate-pod-status", matchConstraintsForResources("", "v1", "pods/status"), mutation)
	statusBinding := unstructuredMutatingPolicyBinding("mutate-pod-status-binding", "mutate-pod-status")
	pod := unstructuredTestPod("prod", "server", map[string]any{"app": "server"})

	ksServer := newMutatingPolicyTestServer(t, podPolicy, podBinding, statusPolicy, statusBinding, pod)

	args := map[string]any{
		"namespace":   "prod",
		"name":        "server",
		"api_version": "v1",
		"resource":    "pods",
	}

	bare := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", args))
	require.False(t, bare.IsError)
	require.Equal(t, []string{"mutate-pods"}, matchedPolicyNames(t, bare))

	args["subresource"] = "status"
	status := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", args))
	require.False(t, status.IsError)
	require.Equal(t, []string{"mutate-pod-status"}, matchedPolicyNames(t, status))
}

// TestAnalyzeMutatingAdmissionPolicyImpact_SubresourceWithParentIsRejected keeps
// a caller from writing the parent twice, which would silently match nothing.
// The cluster is stocked so the same call without the bad subresource succeeds,
// leaving the argument check as the only thing the error can come from.
func TestAnalyzeMutatingAdmissionPolicyImpact_SubresourceWithParentIsRejected(t *testing.T) {
	policy := unstructuredMutatingPolicy("mutate-pod-status", matchConstraintsForResources("", "v1", "pods/status"),
		map[string]any{"patchType": "JSONPatch", "jsonPatch": map[string]any{"expression": `[JSONPatch{op: "add", path: "/metadata/labels/x", value: "y"}]`}},
	)
	binding := unstructuredMutatingPolicyBinding("mutate-pod-status-binding", "mutate-pod-status")
	pod := unstructuredTestPod("prod", "server", map[string]any{"app": "server"})

	ksServer := newMutatingPolicyTestServer(t, policy, binding, pod)

	args := map[string]any{
		"namespace":   "prod",
		"name":        "server",
		"api_version": "v1",
		"resource":    "pods",
		"subresource": "status",
	}

	accepted := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", args))
	require.False(t, accepted.IsError)
	require.Equal(t, []string{"mutate-pod-status"}, matchedPolicyNames(t, accepted))

	args["subresource"] = "pods/status"
	rejected := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", args))
	require.True(t, rejected.IsError)
}

// TestAnalyzeMutatingAdmissionPolicyImpact_NonStringSubresourceIsRejected goes
// through the registered tools/call path, which is where a wrongly typed
// argument actually arrives: the server runs without input schema validation,
// so a number here used to assert away to "" and answer for the bare pod.
func TestAnalyzeMutatingAdmissionPolicyImpact_NonStringSubresourceIsRejected(t *testing.T) {
	policy := unstructuredMutatingPolicy("mutate-pods", allPodsMatchConstraints(),
		map[string]any{"patchType": "JSONPatch", "jsonPatch": map[string]any{"expression": `[JSONPatch{op: "add", path: "/metadata/labels/x", value: "y"}]`}},
	)
	binding := unstructuredMutatingPolicyBinding("mutate-pods-binding", "mutate-pods")
	pod := unstructuredTestPod("prod", "server", map[string]any{"app": "server"})

	ksServer := newMutatingPolicyTestServer(t, policy, binding, pod)

	for _, subresource := range []any{float64(7), true, map[string]any{"name": "status"}, []any{"status"}} {
		result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", map[string]any{
			"namespace":   "prod",
			"name":        "server",
			"api_version": "v1",
			"resource":    "pods",
			"subresource": subresource,
		}))
		require.True(t, result.IsError, "a %T subresource must be refused, not read as the resource itself", subresource)
	}
}

// TestAnalyzeMutatingAdmissionPolicyImpact_OmittedAndNullSubresourceMeanTheResource
// keeps the type check from turning the ordinary no-subresource query into an
// error. An explicit JSON null is how a client may render an unset optional
// argument, so it has to mean the same as leaving it out.
func TestAnalyzeMutatingAdmissionPolicyImpact_OmittedAndNullSubresourceMeanTheResource(t *testing.T) {
	policy := unstructuredMutatingPolicy("mutate-pods", allPodsMatchConstraints(),
		map[string]any{"patchType": "JSONPatch", "jsonPatch": map[string]any{"expression": `[JSONPatch{op: "add", path: "/metadata/labels/x", value: "y"}]`}},
	)
	binding := unstructuredMutatingPolicyBinding("mutate-pods-binding", "mutate-pods")
	pod := unstructuredTestPod("prod", "server", map[string]any{"app": "server"})

	ksServer := newMutatingPolicyTestServer(t, policy, binding, pod)

	args := map[string]any{
		"namespace":   "prod",
		"name":        "server",
		"api_version": "v1",
		"resource":    "pods",
	}

	omitted := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", args))
	require.False(t, omitted.IsError)
	require.Equal(t, []string{"mutate-pods"}, matchedPolicyNames(t, omitted))

	args["subresource"] = nil
	null := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", args))
	require.False(t, null.IsError)
	require.Equal(t, []string{"mutate-pods"}, matchedPolicyNames(t, null))
}

// withMatchConditions puts a spec.matchConditions gate on a policy fixture.
func withMatchConditions(policy *unstructured.Unstructured, conditions ...map[string]any) *unstructured.Unstructured {
	raw := make([]any, len(conditions))
	for i, condition := range conditions {
		raw[i] = condition
	}
	policy.Object["spec"].(map[string]any)["matchConditions"] = raw
	return policy
}

func addLabelMutation() map[string]any {
	return map[string]any{
		"patchType": "JSONPatch",
		"jsonPatch": map[string]any{"expression": `[JSONPatch{op: "add", path: "/metadata/labels/x", value: "y"}]`},
	}
}

func matchesFromToolResult(t *testing.T, ksServer *KubescapeMcpserver, args map[string]any) []any {
	t.Helper()
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_mutating_admission_policy_impact", args))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	require.True(t, parsed["supported"].(bool))
	return parsed["matches"].([]any)
}

func podImpactArgs() map[string]any {
	return map[string]any{
		"namespace":   "prod",
		"name":        "server",
		"api_version": "v1",
		"resource":    "pods",
	}
}

// TestAnalyzeMutatingAdmissionPolicyImpact_MatchConditionsLeaveTheMatchIndeterminate
// covers the gate over the tools/call path: the apiserver still evaluates the
// policy's own matchConditions before mutating, so the tool must report the
// match as one that might apply and name what gates it.
func TestAnalyzeMutatingAdmissionPolicyImpact_MatchConditionsLeaveTheMatchIndeterminate(t *testing.T) {
	policy := withMatchConditions(
		unstructuredMutatingPolicy("add-label", allPodsMatchConstraints(), addLabelMutation()),
		map[string]any{"name": "only-opted-in", "expression": `object.metadata.?labels["mutate"].orValue("no") == "yes"`},
	)
	binding := unstructuredMutatingPolicyBinding("add-label-binding", "add-label")
	pod := unstructuredTestPod("prod", "server", nil)

	matches := matchesFromToolResult(t, newMutatingPolicyTestServer(t, policy, binding, pod), podImpactArgs())
	require.Len(t, matches, 1)

	match := matches[0].(map[string]any)
	require.False(t, match["determinable"].(bool))

	conditions, reported := match["match_conditions"].([]any)
	require.True(t, reported, "the gate must be reported alongside the match")
	require.Len(t, conditions, 1)
	require.Equal(t, "only-opted-in", conditions[0].(map[string]any)["name"])
	require.Contains(t, conditions[0].(map[string]any)["expression"], `labels["mutate"]`)
}

// TestAnalyzeMutatingAdmissionPolicyImpact_UngatedPolicyStaysDeterminable is the
// contrast: a policy declaring no matchConditions still reports a confirmed
// match, with an empty gate list rather than a missing field.
func TestAnalyzeMutatingAdmissionPolicyImpact_UngatedPolicyStaysDeterminable(t *testing.T) {
	policy := unstructuredMutatingPolicy("add-label", allPodsMatchConstraints(), addLabelMutation())
	binding := unstructuredMutatingPolicyBinding("add-label-binding", "add-label")
	pod := unstructuredTestPod("prod", "server", nil)

	matches := matchesFromToolResult(t, newMutatingPolicyTestServer(t, policy, binding, pod), podImpactArgs())
	require.Len(t, matches, 1)

	match := matches[0].(map[string]any)
	require.True(t, match["determinable"].(bool))
	require.Empty(t, match["match_conditions"])
}
