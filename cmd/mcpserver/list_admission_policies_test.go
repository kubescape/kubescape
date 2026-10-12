package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/opaprocessor/cel"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListAdmissionPolicies_MapsPolicyInfo(t *testing.T) {
	data, err := listAdmissionPolicies(func() ([]cel.PolicyInfo, error) {
		return []cel.PolicyInfo{
			{
				PolicyName:    "kubescape-c-0009-resource-policies",
				ControlID:     "C-0009",
				TakesParams:   true,
				FailurePolicy: "Fail",
				Resources:     []string{"pods"},
			},
			{PolicyName: "helper-policy"},
			{PolicyName: "dup", ControlID: "C-0016", DuplicateName: true, DuplicateControl: true},
		}, nil
	})
	require.NoError(t, err)

	var got []admissionPolicyEntry
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, []admissionPolicyEntry{
		{Policy: "kubescape-c-0009-resource-policies", ControlID: "C-0009", TakesParams: true, FailurePolicy: "Fail", Resources: []string{"pods"}},
		{Policy: "helper-policy"},
		{Policy: "dup", ControlID: "C-0016", DuplicateName: true, DuplicateControl: true},
	}, got)
}

func TestListAdmissionPolicies_JSONFieldNames(t *testing.T) {
	data, err := listAdmissionPolicies(func() ([]cel.PolicyInfo, error) {
		return []cel.PolicyInfo{{PolicyName: "p", ControlID: "C-0001", FailurePolicy: "Ignore", Resources: []string{"pods"}}}, nil
	})
	require.NoError(t, err)

	var raw []map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))
	require.Len(t, raw, 1)
	assert.Equal(t, map[string]any{
		"policy":        "p",
		"controlID":     "C-0001",
		"takesParams":   false,
		"failurePolicy": "Ignore",
		"resources":     []any{"pods"},
	}, raw[0])
}

func TestListAdmissionPolicies_EmptyIsEmptyArray(t *testing.T) {
	data, err := listAdmissionPolicies(func() ([]cel.PolicyInfo, error) { return nil, nil })
	require.NoError(t, err)
	assert.JSONEq(t, `[]`, string(data))
}

func TestListAdmissionPolicies_PropagatesError(t *testing.T) {
	data, err := listAdmissionPolicies(func() ([]cel.PolicyInfo, error) {
		return nil, errors.New("boom")
	})
	require.Error(t, err)
	assert.Nil(t, data)
	assert.Contains(t, err.Error(), "boom")
}

func TestListAdmissionPolicies_EmbeddedLibraryMatchesCatalog(t *testing.T) {
	srv := &KubescapeMcpserver{}
	data, err := srv.ListAdmissionPolicies(context.Background())
	require.NoError(t, err)

	var got []admissionPolicyEntry
	require.NoError(t, json.Unmarshal(data, &got))
	want, err := cel.ListPolicies()
	require.NoError(t, err)
	require.NotEmpty(t, want)
	require.Len(t, got, len(want))
	for i, p := range want {
		assert.Equal(t, p.PolicyName, got[i].Policy)
		assert.Equal(t, p.ControlID, got[i].ControlID)
		assert.Equal(t, p.TakesParams, got[i].TakesParams)
	}
}

func TestListAdmissionPolicies_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&KubescapeMcpserver{}).ListAdmissionPolicies(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestCallTool_ListAdmissionPolicies(t *testing.T) {
	srv := &KubescapeMcpserver{}
	result, err := srv.CallTool(context.Background(), "list_admission_policies", map[string]any{})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.IsError)
	require.Len(t, result.Content, 1)
	text, ok := result.Content[0].(mcp.TextContent)
	require.True(t, ok)

	var entries []admissionPolicyEntry
	require.NoError(t, json.Unmarshal([]byte(text.Text), &entries))
	assert.NotEmpty(t, entries)
}

func TestListAdmissionPolicies_ToolRegistration(t *testing.T) {
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

	var found *mcp.Tool
	for i := range parsed.Result.Tools {
		if parsed.Result.Tools[i].Name == "list_admission_policies" {
			found = &parsed.Result.Tools[i]
		}
	}
	require.NotNil(t, found, "list_admission_policies must be registered")
	assert.Contains(t, found.Description, "experimental")
	assert.Empty(t, found.InputSchema.Required, "tool takes no required arguments")
	assert.Empty(t, found.InputSchema.Properties, "tool takes no arguments")
	require.NotNil(t, found.Annotations.ReadOnlyHint)
	assert.True(t, *found.Annotations.ReadOnlyHint)
}
