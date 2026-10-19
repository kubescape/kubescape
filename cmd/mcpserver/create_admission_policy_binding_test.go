package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const bindingTestC0016Policy = "kubescape-c-0016-allow-privilege-escalation"

func callCreateBinding(t *testing.T, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	result, err := (&KubescapeMcpserver{}).CallTool(context.Background(), "create_admission_policy_binding", args)
	require.NoError(t, err)
	require.NotNil(t, result)
	return result
}

func bindingResultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	require.Len(t, result.Content, 1)
	text, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok)
	return text.Text
}

func decodeBindingResponse(t *testing.T, result *mcp.CallToolResult) map[string]any {
	t.Helper()
	require.False(t, result.IsError, "unexpected error: %v", result.Content)
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(bindingResultText(t, result)), &got))
	return got
}

func bindingToolError(t *testing.T, result *mcp.CallToolResult) ToolError {
	t.Helper()
	require.True(t, result.IsError)
	var te ToolError
	require.NoError(t, json.Unmarshal([]byte(bindingResultText(t, result)), &te))
	return te
}

func TestCreateAdmissionPolicyBinding_ByControlID(t *testing.T) {
	got := decodeBindingResponse(t, callCreateBinding(t, map[string]any{
		"binding_name": "my-binding",
		"control_id":   "c-0016",
	}))
	assert.Equal(t, bindingTestC0016Policy, got["policy"])
	assert.Equal(t, "C-0016", got["controlID"])
	assert.Equal(t, []any{}, got["warnings"], "warnings must be an empty array, not null")

	manifest, _ := got["manifest"].(string)
	assert.Contains(t, manifest, "apiVersion: admissionregistration.k8s.io/v1")
	assert.Contains(t, manifest, "kind: ValidatingAdmissionPolicyBinding")
	assert.Contains(t, manifest, "policyName: "+bindingTestC0016Policy)
	assert.Contains(t, manifest, "- Deny")
	assert.Contains(t, manifest, "matchResources: {}")
}

func TestCreateAdmissionPolicyBinding_ByPolicyNameWithSelectors(t *testing.T) {
	got := decodeBindingResponse(t, callCreateBinding(t, map[string]any{
		"binding_name":       "my-binding",
		"policy_name":        bindingTestC0016Policy,
		"validation_actions": []any{"Audit", "Warn"},
		"namespaces":         []any{"prod"},
		"labels":             []any{"app==nginx"},
		"resource_rules":     []any{"apps/v1/deployments"},
	}))
	assert.Equal(t, bindingTestC0016Policy, got["policy"])
	assert.NotContains(t, got, "controlID")
	manifest, _ := got["manifest"].(string)
	assert.Contains(t, manifest, "- Audit")
	assert.Contains(t, manifest, "- Warn")
	assert.Contains(t, manifest, "kubernetes.io/metadata.name")
	assert.Contains(t, manifest, "app: nginx")
	assert.Contains(t, manifest, "- deployments")
}

func TestCreateAdmissionPolicyBinding_ParamRef(t *testing.T) {
	got := decodeBindingResponse(t, callCreateBinding(t, map[string]any{
		"binding_name":        "my-binding",
		"control_id":          "C-0009",
		"parameter_reference": "basic-control-configuration",
	}))
	manifest, _ := got["manifest"].(string)
	assert.Contains(t, manifest, "name: basic-control-configuration")
	assert.Contains(t, manifest, "parameterNotFoundAction: Deny")
}

func TestCreateAdmissionPolicyBinding_Deterministic(t *testing.T) {
	args := map[string]any{
		"binding_name": "my-binding",
		"control_id":   "C-0016",
		"namespaces":   []any{"b", "a"},
		"labels":       []any{"z=1", "a=2"},
	}
	first := bindingResultText(t, callCreateBinding(t, args))
	second := bindingResultText(t, callCreateBinding(t, args))
	assert.Equal(t, first, second)
}

func TestCreateAdmissionPolicyBinding_WarningsAreStructuredData(t *testing.T) {
	t.Run("convertible resource rule", func(t *testing.T) {
		got := decodeBindingResponse(t, callCreateBinding(t, map[string]any{
			"binding_name":   "my-binding",
			"control_id":     "C-0016",
			"resource_rules": []any{"apps/v1beta1/deployments"},
		}))
		warnings, _ := got["warnings"].([]any)
		require.Len(t, warnings, 1)
		assert.Contains(t, warnings[0], "another API group or version")
	})
	t.Run("partially narrowing namespace selector", func(t *testing.T) {
		got := decodeBindingResponse(t, callCreateBinding(t, map[string]any{
			"binding_name": "my-binding",
			"control_id":   "C-0280",
			"namespaces":   []any{"prod"},
		}))
		warnings, _ := got["warnings"].([]any)
		require.Len(t, warnings, 1)
		assert.Contains(t, warnings[0], "--namespace does not narrow")
	})
}

func TestCreateAdmissionPolicyBinding_CustomPolicyIsLenient(t *testing.T) {
	got := decodeBindingResponse(t, callCreateBinding(t, map[string]any{
		"binding_name":        "my-binding",
		"policy_name":         "my-own-policy",
		"parameter_reference": "params",
		"namespaces":          []any{"prod"},
		"resource_rules":      []any{"/v1/pods"},
	}))
	assert.Equal(t, "my-own-policy", got["policy"])
	assert.Equal(t, []any{}, got["warnings"])
}

func TestCreateAdmissionPolicyBinding_InvalidArguments(t *testing.T) {
	valid := func() map[string]any {
		return map[string]any{"binding_name": "my-binding", "control_id": "C-0016"}
	}
	cases := []struct {
		name     string
		mutate   func(map[string]any)
		contains string
	}{
		{"missing binding name", func(a map[string]any) { delete(a, "binding_name") }, "binding_name"},
		{"invalid binding name", func(a map[string]any) { a["binding_name"] = "Not_Valid" }, "invalid policy binding name"},
		{"neither policy nor control", func(a map[string]any) { delete(a, "control_id") }, "exactly one of policy_name or control_id"},
		{"both policy and control", func(a map[string]any) { a["policy_name"] = bindingTestC0016Policy }, "only one of policy_name or control_id"},
		{"unknown control", func(a map[string]any) { a["control_id"] = "C-9999" }, "unsupported control ID"},
		{"invalid namespace", func(a map[string]any) { a["namespaces"] = []any{"Bad_NS"} }, "invalid namespace"},
		{"deny with warn", func(a map[string]any) { a["validation_actions"] = []any{"Deny", "Warn"} }, "cannot be combined"},
		{"duplicate action", func(a map[string]any) { a["validation_actions"] = []any{"Audit", "Audit"} }, "duplicate action"},
		{"empty actions", func(a map[string]any) { a["validation_actions"] = []any{} }, "at least one"},
		{"malformed label", func(a map[string]any) { a["labels"] = []any{"nolabel"} }, "label"},
		{"malformed resource rule", func(a map[string]any) { a["resource_rules"] = []any{"deployments"} }, "resource"},
		{"rule outside the policy", func(a map[string]any) { a["resource_rules"] = []any{"agents.x-k8s.io/v1beta1/sandboxes"} }, "outside the matchConstraints"},
		{"reference on a policy without params", func(a map[string]any) { a["parameter_reference"] = "params" }, "takes no --parameter-reference"},
		{"missing reference names the paramKind", func(a map[string]any) { a["control_id"] = "C-0009" }, "kubescape.io/v1 ControlConfiguration"},
		{"namespace on cluster-scoped resources", func(a map[string]any) {
			a["control_id"] = "C-0280"
			a["namespaces"] = []any{"prod"}
			a["resource_rules"] = []any{"rbac.authorization.k8s.io/v1/clusterroles"}
		}, "narrows nothing"},
		{"non-string policy name", func(a map[string]any) { delete(a, "control_id"); a["policy_name"] = 7 }, "policy_name"},
		{"actions not an array", func(a map[string]any) { a["validation_actions"] = "Deny" }, "array of strings"},
		{"non-string array element", func(a map[string]any) { a["namespaces"] = []any{"prod", 1} }, "must be strings"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := valid()
			tc.mutate(args)
			te := bindingToolError(t, callCreateBinding(t, args))
			assert.Equal(t, ErrCodeInvalidArgument, te.Code)
			assert.Contains(t, te.Message, tc.contains)
		})
	}
}

func TestCreateAdmissionPolicyBinding_ResponseMarshalFailure(t *testing.T) {
	orig := jsonMarshal
	t.Cleanup(func() { jsonMarshal = orig })
	jsonMarshal = func(any) ([]byte, error) { return nil, errors.New("boom") }

	te := bindingToolError(t, callCreateBinding(t, map[string]any{"binding_name": "my-binding", "control_id": "C-0016"}))
	assert.Equal(t, ErrCodeMarshalError, te.Code)
}

func TestCreateAdmissionPolicyBinding_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&KubescapeMcpserver{}).CallTool(ctx, "create_admission_policy_binding", map[string]any{})
	require.ErrorIs(t, err, context.Canceled)
}

func TestCreateAdmissionPolicyBinding_ToolRegistration(t *testing.T) {
	s := server.NewMCPServer("test", "0.0.1", server.WithToolCapabilities(false))
	createPolicyListingTools(&KubescapeMcpserver{s: s})

	resp := s.HandleMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	raw, err := json.Marshal(resp)
	require.NoError(t, err)
	var parsed struct {
		Result struct {
			Tools []mcp.Tool `json:"tools"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(raw, &parsed))

	byName := map[string]mcp.Tool{}
	for _, tool := range parsed.Result.Tools {
		byName[tool.Name] = tool
	}
	tool, ok := byName["create_admission_policy_binding"]
	require.True(t, ok, "create_admission_policy_binding must be registered")
	assert.Equal(t, []string{"binding_name"}, tool.InputSchema.Required)
	for _, arg := range []string{"binding_name", "policy_name", "control_id", "validation_actions", "parameter_reference", "namespaces", "labels", "resource_rules"} {
		assert.Contains(t, tool.InputSchema.Properties, arg)
	}
	for _, arg := range []string{"validation_actions", "namespaces", "labels", "resource_rules"} {
		prop, _ := tool.InputSchema.Properties[arg].(map[string]any)
		assert.Equal(t, "array", prop["type"], arg)
	}
	require.NotNil(t, tool.Annotations.ReadOnlyHint)
	assert.True(t, *tool.Annotations.ReadOnlyHint)

	// The sibling tool is untouched.
	list, ok := byName["list_admission_policies"]
	require.True(t, ok)
	assert.Empty(t, list.InputSchema.Properties)
	assert.Empty(t, list.InputSchema.Required)
}
