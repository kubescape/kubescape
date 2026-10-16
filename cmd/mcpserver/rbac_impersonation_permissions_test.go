package mcpserver

import (
	"encoding/json"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/rbacgraph"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestRBACUnrestrictedImpersonationReportsRiskWithoutInventedAdmin(t *testing.T) {
	for _, resource := range []string{"users", "serviceaccounts"} {
		t.Run(resource, func(t *testing.T) {
			grant := unstructuredClusterRole("impersonator", unstructuredPolicyRule([]string{""}, []string{resource}, []string{"impersonate"}, nil))
			binding := unstructuredClusterRoleBinding("grant", "impersonator", "prod", "caller")
			target := unstructuredServiceAccount("prod", "target")
			reader := unstructuredClusterRole("reader", unstructuredPolicyRule([]string{""}, []string{"pods"}, []string{"get"}, nil))
			readerBinding := unstructuredClusterRoleBinding("read", "reader", "prod", "target")
			tool := newRBACEscalationTestServer(t, []runtime.Object{grant, binding, target, reader, readerBinding}...)
			result := registeredToolResult(t, dispatchRegisteredTool(t, tool, "analyze_rbac_escalation_paths", map[string]any{
				"subject_kind": "ServiceAccount", "namespace": "prod", "name": "caller",
			}))
			require.False(t, result.IsError)
			var parsed map[string]any
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
			require.Equal(t, false, parsed["cluster_admin_equivalent"])
			warnings, ok := parsed["unbounded_findings"].([]any)
			require.True(t, ok)
			require.NotEmpty(t, warnings, "the result must not turn an unbounded target set into an all-clear")
			warning := warnings[0].(map[string]any)
			require.Equal(t, "impersonate", warning["primitive"])
			require.Equal(t, "cluster-wide", warning["scope"])
			wantKind := "User"
			if resource == "serviceaccounts" {
				wantKind = "ServiceAccount"
			}
			require.Equal(t, wantKind, warning["impersonated_kind"])
		})
	}
}

func TestUnboundedSummariesDistinguishTargetSetsFromPermissionGrants(t *testing.T) {
	findings := []rbacgraph.UnboundedFinding{
		{Edge: rbacgraph.EscalationEdge{Primitive: rbacgraph.PrimitiveImpersonate, Unbounded: true, ImpersonatedKind: rbacgraph.KindServiceAccount, Scope: "prod"}},
		{Edge: rbacgraph.EscalationEdge{Primitive: rbacgraph.PrimitiveEscalateVerb, Unbounded: true, Scope: "prod"}},
	}
	summaries := buildUnboundedSummaries(findings)
	require.Equal(t, "ServiceAccount", summaries[0]["impersonated_kind"])
	require.NotContains(t, summaries[1], "impersonated_kind")
	require.Equal(t, "prod", summaries[0]["scope"])
	require.Equal(t, "prod", summaries[1]["scope"])
}

func TestRBACImpersonationReachesBoundServiceAccountWithoutObject(t *testing.T) {
	grant := unstructuredClusterRole("impersonator", unstructuredPolicyRule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, nil))
	binding := unstructuredClusterRoleBinding("grant", "impersonator", "prod", "caller")
	admin := unstructuredClusterRole("admin", unstructuredPolicyRule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	adminBinding := unstructuredClusterRoleBinding("dangling-admin", "admin", "prod", "deleted-admin")
	tool := newRBACEscalationTestServer(t, grant, binding, admin, adminBinding)
	result := registeredToolResult(t, dispatchRegisteredTool(t, tool, "analyze_rbac_escalation_paths", map[string]any{
		"subject_kind": "ServiceAccount", "namespace": "prod", "name": "caller",
	}))
	require.False(t, result.IsError)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	require.Equal(t, true, parsed["cluster_admin_equivalent"])
	require.NotEmpty(t, parsed["reached"])
	require.NotEmpty(t, parsed["unbounded_findings"])
}

func TestRBACImpersonationReachesImplicitServiceAccountGroups(t *testing.T) {
	for _, group := range []string{"system:serviceaccounts", "system:serviceaccounts:prod"} {
		t.Run(group, func(t *testing.T) {
			grant := unstructuredClusterRole("impersonator", unstructuredPolicyRule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, nil))
			binding := unstructuredClusterRoleBinding("grant", "impersonator", "prod", "unused")
			binding.Object["subjects"] = []any{map[string]any{"kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": "alice"}}
			admin := unstructuredClusterRole("admin", unstructuredPolicyRule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
			adminBinding := unstructuredClusterRoleBinding("group-admin", "admin", "prod", "unused")
			adminBinding.Object["subjects"] = []any{map[string]any{"kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": group}}
			tool := newRBACEscalationTestServer(t, grant, binding, admin, adminBinding)
			result := registeredToolResult(t, dispatchRegisteredTool(t, tool, "analyze_rbac_escalation_paths", map[string]any{"subject_kind": "User", "name": "alice"}))
			require.False(t, result.IsError)
			var parsed map[string]any
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
			require.Equal(t, true, parsed["cluster_admin_equivalent"])
			require.NotEmpty(t, parsed["reached"])
			require.NotEmpty(t, parsed["unbounded_findings"])
		})
	}
}

func TestRBACAnonymousImpersonationUsesUnauthenticatedGroup(t *testing.T) {
	for _, tc := range []struct {
		name, group, subject string
		wantAdmin            bool
	}{
		{name: "impersonate anonymous through group binding", group: "system:unauthenticated", subject: "alice", wantAdmin: true},
		{name: "anonymous excludes authenticated grants", group: "system:authenticated", subject: "system:anonymous"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grant := unstructuredClusterRole("impersonator", unstructuredPolicyRule([]string{""}, []string{"users"}, []string{"impersonate"}, nil))
			binding := unstructuredClusterRoleBinding("grant", "impersonator", "prod", "unused")
			binding.Object["subjects"] = []any{map[string]any{"kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": "alice"}}
			admin := unstructuredClusterRole("admin", unstructuredPolicyRule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
			adminBinding := unstructuredClusterRoleBinding("group-admin", "admin", "prod", "unused")
			adminBinding.Object["subjects"] = []any{map[string]any{"kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": tc.group}}
			tool := newRBACEscalationTestServer(t, grant, binding, admin, adminBinding)
			result := registeredToolResult(t, dispatchRegisteredTool(t, tool, "analyze_rbac_escalation_paths", map[string]any{"subject_kind": "User", "name": tc.subject}))
			require.False(t, result.IsError)
			var parsed map[string]any
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
			require.Equal(t, tc.wantAdmin, parsed["cluster_admin_equivalent"])
			if tc.wantAdmin {
				require.NotEmpty(t, parsed["reached"])
				require.NotEmpty(t, parsed["unbounded_findings"])
			}
		})
	}
}
