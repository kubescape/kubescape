package mcpserver

import (
	"encoding/json"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/rbacgraph"
	"github.com/stretchr/testify/require"
)

func TestBuildUnboundedSummaries_PreservesScopeUncertainty(t *testing.T) {
	for _, tt := range []struct {
		name      string
		scope     string
		unknown   bool
		wantScope string
	}{
		{name: "unresolved Role", unknown: true, wantScope: "unknown"},
		{name: "known namespace", scope: "prod", wantScope: "prod"},
		{name: "cluster-wide", wantScope: "cluster-wide"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			findings := []rbacgraph.UnboundedFinding{{
				Subject: rbacgraph.Subject{Kind: rbacgraph.KindUser, Name: "alice"},
				Edge:    rbacgraph.EscalationEdge{Scope: tt.scope, ScopeUnknown: tt.unknown, Detail: "unresolved target", Unbounded: true},
			}}
			// Check the serialized consumer-facing shape, not only the Go map.
			raw, err := json.Marshal(buildUnboundedSummaries(findings))
			require.NoError(t, err)
			var summaries []map[string]any
			require.NoError(t, json.Unmarshal(raw, &summaries))
			require.Len(t, summaries, 1)
			require.Equal(t, tt.wantScope, summaries[0]["scope"])
			require.Equal(t, tt.unknown, summaries[0]["scope_unknown"])
			require.Equal(t, "unresolved target", summaries[0]["detail"])
		})
	}
}

func TestAnalyzeRBACEscalationPaths_UnresolvedRoleScopeOutput(t *testing.T) {
	grant := unstructuredClusterRole("role-editor", unstructuredPolicyRule(
		[]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"escalate", "update"}, []string{"missing"},
	))
	ksServer := newRBACEscalationTestServer(t,
		unstructuredServiceAccount("prod", "app"), grant,
		unstructuredClusterRoleBinding("editor-binding", "role-editor", "prod", "app"),
	)
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_rbac_escalation_paths", map[string]any{
		"subject_kind": "ServiceAccount", "namespace": "prod", "name": "app",
	}))
	require.False(t, result.IsError)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	require.Equal(t, false, parsed["cluster_admin_equivalent"])
	findings, ok := parsed["unbounded_findings"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, findings)
	for _, finding := range findings {
		entry := finding.(map[string]any)
		require.Equal(t, "unknown", entry["scope"])
		require.Equal(t, true, entry["scope_unknown"])
	}
}
