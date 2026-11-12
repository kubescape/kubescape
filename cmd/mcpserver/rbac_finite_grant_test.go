package mcpserver

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// The tool's description promises the bind-verb bypass. A finite grant leaves
// Reached, Unbounded and ClusterAdmin untouched by design, so it can only
// reach the caller through a field of its own.
func TestAnalyzeRBACEscalationPaths_FiniteBindGrantIsReported(t *testing.T) {
	rbacGroup := []string{"rbac.authorization.k8s.io"}
	ksServer := newRBACEscalationTestServer(t,
		unstructuredServiceAccount("prod", "attacker"),
		unstructuredClusterRole("secret-reader", unstructuredPolicyRule([]string{""}, []string{"secrets"}, []string{"get", "list"}, nil)),
		unstructuredClusterRole("binder", unstructuredPolicyRule(rbacGroup, []string{"clusterroles"}, []string{"bind"}, []string{"secret-reader"})),
		unstructuredClusterRole("crb-creator", unstructuredPolicyRule(rbacGroup, []string{"clusterrolebindings"}, []string{"create"}, nil)),
		unstructuredClusterRoleBinding("crb1", "binder", "prod", "attacker"),
		unstructuredClusterRoleBinding("crb2", "crb-creator", "prod", "attacker"),
	)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_rbac_escalation_paths", map[string]any{
		"subject_kind": "ServiceAccount",
		"namespace":    "prod",
		"name":         "attacker",
	}))
	require.False(t, result.IsError)

	text := toolResultText(t, result)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(text), &parsed))
	grants, ok := parsed["grants"].([]any)
	require.Truef(t, ok, "the bind-verb escalation must appear in the output, got: %s", text)
	require.Len(t, grants, 1)
	grant := grants[0].(map[string]any)
	require.Equal(t, "bind-verb", grant["primitive"])
	require.Equal(t, "cluster-wide", grant["scope"])
	require.Equal(t, "ServiceAccount prod/attacker", grant["subject"])
	require.Equal(t, map[string]any{"kind": "ClusterRole", "namespace": "", "name": "secret-reader"}, grant["target"])
}
