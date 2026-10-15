package mcpserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/require"
)

func TestAnalyzeRBACEscalationPaths_DescriptionCoversWorkloadControllers(t *testing.T) {
	ksServer := newRBACEscalationTestServer(t)

	resp := ksServer.s.HandleMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	raw, err := json.Marshal(resp)
	require.NoError(t, err)
	var parsed struct {
		Result struct {
			Tools []mcp.Tool `json:"tools"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(raw, &parsed))

	var description string
	for _, tool := range parsed.Result.Tools {
		if tool.Name == "analyze_rbac_escalation_paths" {
			description = tool.Description
		}
	}
	require.NotEmpty(t, description, "analyze_rbac_escalation_paths must be registered")
	require.Contains(t, description, "Deployment")
	require.Contains(t, description, "CronJob")
}

func TestAnalyzeRBACEscalationPaths_DeploymentPatchReportsNamedObjectsOnly(t *testing.T) {
	attacker := unstructuredServiceAccount("prod", "attacker")
	target := unstructuredServiceAccount("prod", "target")
	patcher := unstructuredClusterRole("patcher", unstructuredPolicyRule([]string{"apps"}, []string{"deployments"}, []string{"patch"}, []string{"web"}))
	crb := unstructuredClusterRoleBinding("crb", "patcher", "prod", "attacker")
	ksServer := newRBACEscalationTestServer(t, attacker, target, patcher, crb)

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
	hop := entry["path"].([]any)[0].(map[string]any)
	require.Equal(t, "assign-serviceaccount", hop["primitive"])
	require.Contains(t, hop["detail"], "patch apps/deployments (named objects only)")
}
