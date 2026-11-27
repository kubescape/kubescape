package mcpserver

import (
	"context"
	"fmt"

	"github.com/kubescape/kubescape/v4/cmd/vap"
	"github.com/mark3labs/mcp-go/mcp"
)

// generateVAPResponse is the tool's JSON result.
type generateVAPResponse struct {
	PolicyName  string `json:"policy_name"`
	ControlID   string `json:"control_id,omitempty"`
	Manifest    string `json:"manifest"`
	TakesParams bool   `json:"takes_params"`
}

// GenerateVAP renders a ValidatingAdmissionPolicy manifest from the embedded CEL
// admission policy library. It limits generation strictly to controls/policies that
// already have an implementation in the embedded library, returning a clear error
// if no CEL equivalent exists yet.
func (ksServer *KubescapeMcpserver) GenerateVAP(ctx context.Context, arguments map[string]any) (*mcp.CallToolResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return generateVAP(arguments), nil
}

func generateVAP(arguments map[string]any) *mcp.CallToolResult {
	policyName, toolErr := mcpStringArg(arguments, "policy_name")
	if toolErr != nil {
		return toolErr
	}
	controlID, toolErr := mcpStringArg(arguments, "control_id")
	if toolErr != nil {
		return toolErr
	}
	switch {
	case policyName == "" && controlID == "":
		return mcpToolError(ErrCodeInvalidArgument, "exactly one of policy_name or control_id must be specified", map[string]any{"argument": "policy_name"})
	case policyName != "" && controlID != "":
		return mcpToolError(ErrCodeInvalidArgument, "only one of policy_name or control_id can be specified", map[string]any{"argument": "control_id"})
	}

	result, err := vap.GeneratePolicy(vap.GeneratePolicyOptions{
		PolicyName: policyName,
		ControlID:  controlID,
	})
	if err != nil {
		return mcpToolError(ErrCodeInvalidArgument, err.Error(), nil)
	}

	payload, err := jsonMarshal(generateVAPResponse{
		PolicyName:  result.PolicyName,
		ControlID:   result.ControlID,
		Manifest:    result.Manifest,
		TakesParams: result.TakesParams,
	})
	if err != nil {
		return mcpToolError(ErrCodeMarshalError, fmt.Sprintf("failed to marshal policy manifest result: %v", err), nil)
	}
	return mcp.NewToolResultText(string(payload))
}
