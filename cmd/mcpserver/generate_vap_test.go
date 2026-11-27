package mcpserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const generateTestC0016Policy = "kubescape-c-0016-allow-privilege-escalation"

func callGenerateVAP(t *testing.T, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	result, err := (&KubescapeMcpserver{}).CallTool(context.Background(), "generate_vap", args)
	require.NoError(t, err)
	require.NotNil(t, result)
	return result
}

func generateVAPResultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	require.Len(t, result.Content, 1)
	text, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok)
	return text.Text
}

func decodeGenerateVAPResponse(t *testing.T, result *mcp.CallToolResult) map[string]any {
	t.Helper()
	require.False(t, result.IsError, "unexpected error: %v", result.Content)
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(generateVAPResultText(t, result)), &got))
	return got
}

func generateVAPToolError(t *testing.T, result *mcp.CallToolResult) ToolError {
	t.Helper()
	require.True(t, result.IsError)
	var te ToolError
	require.NoError(t, json.Unmarshal([]byte(generateVAPResultText(t, result)), &te))
	return te
}

func TestGenerateVAP_ByControlID(t *testing.T) {
	got := decodeGenerateVAPResponse(t, callGenerateVAP(t, map[string]any{
		"control_id": "c-0016",
	}))
	assert.Equal(t, generateTestC0016Policy, got["policy_name"])
	assert.Equal(t, "C-0016", got["control_id"])
	assert.Equal(t, false, got["takes_params"])

	manifest, _ := got["manifest"].(string)
	assert.Contains(t, manifest, "apiVersion: admissionregistration.k8s.io/v1")
	assert.Contains(t, manifest, "kind: ValidatingAdmissionPolicy")
	assert.Contains(t, manifest, "name: kubescape-c-0016-allow-privilege-escalation")
}

func TestGenerateVAP_ByPolicyName(t *testing.T) {
	got := decodeGenerateVAPResponse(t, callGenerateVAP(t, map[string]any{
		"policy_name": generateTestC0016Policy,
	}))
	assert.Equal(t, generateTestC0016Policy, got["policy_name"])
	assert.Equal(t, "C-0016", got["control_id"])
	assert.Equal(t, false, got["takes_params"])

	manifest, _ := got["manifest"].(string)
	assert.Contains(t, manifest, "kind: ValidatingAdmissionPolicy")
}

func TestGenerateVAP_TakesParamsPolicy(t *testing.T) {
	got := decodeGenerateVAPResponse(t, callGenerateVAP(t, map[string]any{
		"control_id": "C-0009",
	}))
	assert.Equal(t, "C-0009", got["control_id"])
	assert.Equal(t, true, got["takes_params"])

	manifest, _ := got["manifest"].(string)
	assert.Contains(t, manifest, "kind: ValidatingAdmissionPolicy")
	assert.Contains(t, manifest, "paramKind:")
}

func TestGenerateVAP_NoCELEquivalentControl(t *testing.T) {
	te := generateVAPToolError(t, callGenerateVAP(t, map[string]any{
		"control_id": "C-9999",
	}))
	assert.Equal(t, ErrCodeInvalidArgument, te.Code)
	assert.Contains(t, te.Message, `control "C-9999" has no CEL equivalent yet`)
}

func TestGenerateVAP_NoCELEquivalentPolicy(t *testing.T) {
	te := generateVAPToolError(t, callGenerateVAP(t, map[string]any{
		"policy_name": "unknown-vap-policy",
	}))
	assert.Equal(t, ErrCodeInvalidArgument, te.Code)
	assert.Contains(t, te.Message, `policy "unknown-vap-policy" has no CEL equivalent yet`)
}

func TestGenerateVAP_ArgumentMutualExclusion(t *testing.T) {
	t.Run("neither specified", func(t *testing.T) {
		te := generateVAPToolError(t, callGenerateVAP(t, map[string]any{}))
		assert.Equal(t, ErrCodeInvalidArgument, te.Code)
		assert.Contains(t, te.Message, "exactly one of policy_name or control_id must be specified")
	})

	t.Run("both specified", func(t *testing.T) {
		te := generateVAPToolError(t, callGenerateVAP(t, map[string]any{
			"control_id":  "C-0016",
			"policy_name": generateTestC0016Policy,
		}))
		assert.Equal(t, ErrCodeInvalidArgument, te.Code)
		assert.Contains(t, te.Message, "only one of policy_name or control_id can be specified")
	})
}

func TestGenerateVAP_ToolRegistration(t *testing.T) {
	s := server.NewMCPServer("test", "0.0.0")
	srv := &KubescapeMcpserver{s: s}
	createPolicyListingTools(srv)

	req := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	resp := s.HandleMessage(context.Background(), req)
	raw, err := json.Marshal(resp)
	require.NoError(t, err)

	var parsed struct {
		Result struct {
			Tools []mcp.Tool `json:"tools"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(raw, &parsed))

	var found *mcp.Tool
	for i := range parsed.Result.Tools {
		if parsed.Result.Tools[i].Name == "generate_vap" {
			found = &parsed.Result.Tools[i]
			break
		}
	}
	require.NotNil(t, found, "generate_vap must be registered")
	assert.Contains(t, found.Description, "experimental")
	require.NotNil(t, found.Annotations.ReadOnlyHint)
	assert.True(t, *found.Annotations.ReadOnlyHint)
	assert.Contains(t, found.InputSchema.Properties, "control_id")
	assert.Contains(t, found.InputSchema.Properties, "policy_name")
}
