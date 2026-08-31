package mcpserver

import (
	"encoding/json"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func newRBACEscalationTestServer(t *testing.T, objects ...runtime.Object) *KubescapeMcpserver {
	t.Helper()
	listKinds := map[schema.GroupVersionResource]string{
		roleGVR:               "RoleList",
		clusterRoleGVR:        "ClusterRoleList",
		roleBindingGVR:        "RoleBindingList",
		clusterRoleBindingGVR: "ClusterRoleBindingList",
		serviceAccountGVR:     "ServiceAccountList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objects...)

	ksServer := &KubescapeMcpserver{
		s: server.NewMCPServer(
			"kubescape-test",
			"test",
			server.WithToolCapabilities(false),
			server.WithRecovery(),
		),
		k8sClient: &k8sinterface.KubernetesApi{DynamicClient: dyn},
	}
	createRBACEscalationTools(ksServer)
	return ksServer
}

func unstructuredServiceAccount(namespace, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "ServiceAccount",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
	}}
}

func unstructuredPolicyRule(apiGroups, resources, verbs, resourceNames []string) map[string]any {
	m := map[string]any{
		"apiGroups": toAnySlice(apiGroups),
		"resources": toAnySlice(resources),
		"verbs":     toAnySlice(verbs),
	}
	if len(resourceNames) > 0 {
		m["resourceNames"] = toAnySlice(resourceNames)
	}
	return m
}

func toAnySlice(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func unstructuredClusterRole(name string, rules ...map[string]any) *unstructured.Unstructured {
	ruleList := make([]any, len(rules))
	for i, r := range rules {
		ruleList[i] = r
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata":   map[string]any{"name": name},
		"rules":      ruleList,
	}}
}

func unstructuredClusterRoleBinding(name, clusterRoleName string, subjectNamespace, subjectName string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRoleBinding",
		"metadata":   map[string]any{"name": name},
		"roleRef": map[string]any{
			"apiGroup": "rbac.authorization.k8s.io",
			"kind":     "ClusterRole",
			"name":     clusterRoleName,
		},
		"subjects": []any{
			map[string]any{"kind": "ServiceAccount", "namespace": subjectNamespace, "name": subjectName},
		},
	}}
}

func TestAnalyzeRBACEscalationPaths_NoEscalationReportsEmptyResult(t *testing.T) {
	sa := unstructuredServiceAccount("prod", "app")
	cr := unstructuredClusterRole("pod-reader", unstructuredPolicyRule([]string{""}, []string{"pods"}, []string{"get"}, nil))
	crb := unstructuredClusterRoleBinding("crb", "pod-reader", "prod", "app")
	ksServer := newRBACEscalationTestServer(t, sa, cr, crb)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_rbac_escalation_paths", map[string]any{
		"subject_kind": "ServiceAccount",
		"namespace":    "prod",
		"name":         "app",
	}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	require.False(t, parsed["cluster_admin_equivalent"].(bool))
	require.Empty(t, parsed["reached"])
}

func TestAnalyzeRBACEscalationPaths_ImpersonateReachesNamedServiceAccount(t *testing.T) {
	attackerSA := unstructuredServiceAccount("prod", "attacker")
	targetSA := unstructuredServiceAccount("prod", "target")
	impersonator := unstructuredClusterRole("impersonator", unstructuredPolicyRule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, []string{"target"}))
	crb := unstructuredClusterRoleBinding("crb", "impersonator", "prod", "attacker")
	ksServer := newRBACEscalationTestServer(t, attackerSA, targetSA, impersonator, crb)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_rbac_escalation_paths", map[string]any{
		"subject_kind": "ServiceAccount",
		"namespace":    "prod",
		"name":         "attacker",
	}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	reached := parsed["reached"].([]any)
	require.Len(t, reached, 1)
	entry := reached[0].(map[string]any)
	require.Equal(t, "ServiceAccount prod/target", entry["subject"])
	path := entry["path"].([]any)
	require.Len(t, path, 1)
	require.Equal(t, "impersonate", path[0].(map[string]any)["primitive"])
}

func TestAnalyzeRBACEscalationPaths_BindClusterAdminClusterRoleIsFlagged(t *testing.T) {
	attackerSA := unstructuredServiceAccount("prod", "attacker")
	adminRole := unstructuredClusterRole("cluster-admin-ish", unstructuredPolicyRule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	binder := unstructuredClusterRole("binder", unstructuredPolicyRule([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"bind"}, []string{"cluster-admin-ish"}))
	crbCreator := unstructuredClusterRole("crb-creator", unstructuredPolicyRule([]string{"rbac.authorization.k8s.io"}, []string{"clusterrolebindings"}, []string{"create"}, nil))
	ksServer := newRBACEscalationTestServer(t,
		attackerSA, adminRole, binder, crbCreator,
		unstructuredClusterRoleBinding("crb1", "binder", "prod", "attacker"),
		unstructuredClusterRoleBinding("crb2", "crb-creator", "prod", "attacker"),
	)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_rbac_escalation_paths", map[string]any{
		"subject_kind": "ServiceAccount",
		"namespace":    "prod",
		"name":         "attacker",
	}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	require.True(t, parsed["cluster_admin_equivalent"].(bool), "bind+create-clusterrolebindings to a */*/* ClusterRole must be flagged cluster-admin-equivalent")
}

func TestAnalyzeRBACEscalationPaths_MissingNameReturnsError(t *testing.T) {
	ksServer := newRBACEscalationTestServer(t)
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_rbac_escalation_paths", map[string]any{
		"subject_kind": "ServiceAccount",
		"namespace":    "prod",
	}))
	require.True(t, result.IsError)
}

func TestAnalyzeRBACEscalationPaths_ServiceAccountWithoutNamespaceReturnsError(t *testing.T) {
	ksServer := newRBACEscalationTestServer(t)
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_rbac_escalation_paths", map[string]any{
		"subject_kind": "ServiceAccount",
		"name":         "app",
	}))
	require.True(t, result.IsError)
}

func TestAnalyzeRBACEscalationPaths_InvalidSubjectKindReturnsError(t *testing.T) {
	ksServer := newRBACEscalationTestServer(t)
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_rbac_escalation_paths", map[string]any{
		"subject_kind": "Robot",
		"name":         "app",
	}))
	require.True(t, result.IsError)
}

func TestAnalyzeRBACEscalationPaths_UserSubjectNeedsNoNamespace(t *testing.T) {
	target := unstructuredServiceAccount("prod", "target")
	impersonator := unstructuredClusterRole("impersonator", unstructuredPolicyRule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, []string{"target"}))
	crb := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRoleBinding",
		"metadata":   map[string]any{"name": "crb"},
		"roleRef": map[string]any{
			"apiGroup": "rbac.authorization.k8s.io",
			"kind":     "ClusterRole",
			"name":     "impersonator",
		},
		"subjects": []any{
			map[string]any{"kind": "User", "name": "alice"},
		},
	}}
	ksServer := newRBACEscalationTestServer(t, target, impersonator, crb)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_rbac_escalation_paths", map[string]any{
		"subject_kind": "User",
		"name":         "alice",
	}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	require.Equal(t, "User alice", parsed["subject"])
	require.Len(t, parsed["reached"].([]any), 1)
}
