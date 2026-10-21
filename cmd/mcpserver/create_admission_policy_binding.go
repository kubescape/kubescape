package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kubescape/kubescape/v4/cmd/vap"
	"github.com/mark3labs/mcp-go/mcp"
)

// createAdmissionPolicyBindingResponse is the tool's JSON result.
type createAdmissionPolicyBindingResponse struct {
	Policy    string   `json:"policy"`
	ControlID string   `json:"controlID,omitempty"`
	Manifest  string   `json:"manifest"`
	Warnings  []string `json:"warnings"`
}

// CreateAdmissionPolicyBinding renders a ValidatingAdmissionPolicyBinding
// manifest through the same validation as `kubescape vap create-policy-binding`.
// It reads only the embedded policy library: it never touches a cluster, a file
// or the network, and the manifest is returned for the caller to review, not
// applied.
func (ksServer *KubescapeMcpserver) CreateAdmissionPolicyBinding(ctx context.Context, arguments map[string]any) (*mcp.CallToolResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return createAdmissionPolicyBinding(arguments), nil
}

func createAdmissionPolicyBinding(arguments map[string]any) *mcp.CallToolResult {
	bindingName, toolErr := mcpRequiredStringArg(arguments, "binding_name")
	if toolErr != nil {
		return toolErr
	}
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
	parameterReference, toolErr := mcpStringArg(arguments, "parameter_reference")
	if toolErr != nil {
		return toolErr
	}
	actions, toolErr := mcpStringListArg(arguments, "validation_actions")
	if toolErr != nil {
		return toolErr
	}
	if actions == nil {
		actions = []string{"Deny"}
	}
	namespaces, toolErr := mcpSelectorListArg(arguments, "namespaces")
	if toolErr != nil {
		return toolErr
	}
	labels, toolErr := mcpSelectorListArg(arguments, "labels")
	if toolErr != nil {
		return toolErr
	}
	// Passed through untouched: BuildPolicyBinding validates every entry, so a
	// blank one must reach it rather than be dropped here and widen the binding.
	resourceRules, toolErr := mcpRawStringListArg(arguments, "resource_rules")
	if toolErr != nil {
		return toolErr
	}

	result, err := vap.BuildPolicyBinding(vap.BindingOptions{
		Name:               bindingName,
		PolicyName:         policyName,
		ControlID:          controlID,
		Namespaces:         namespaces,
		Labels:             labels,
		Actions:            actions,
		ResourceRules:      resourceRules,
		ParameterReference: parameterReference,
	})
	if err != nil {
		if errors.Is(err, vap.ErrMarshalManifest) {
			return mcpToolError(ErrCodeMarshalError, "failed to serialize the policy binding manifest", nil)
		}
		return mcpToolError(ErrCodeInvalidArgument, err.Error(), nil)
	}

	warnings := make([]string, 0, len(result.Warnings))
	for _, w := range result.Warnings {
		warnings = append(warnings, w.String())
	}
	payload, err := jsonMarshal(createAdmissionPolicyBindingResponse{
		Policy:    result.PolicyName,
		ControlID: result.ControlID,
		Manifest:  result.Manifest,
		Warnings:  warnings,
	})
	if err != nil {
		return mcpToolError(ErrCodeMarshalError, fmt.Sprintf("failed to marshal policy binding result: %v", err), nil)
	}
	return mcp.NewToolResultText(string(payload))
}

// mcpStringListArg reads an optional array-of-strings argument. A missing or
// null argument returns nil. Elements are trimmed; empty ones are dropped.
func mcpStringListArg(arguments map[string]any, name string) ([]string, *mcp.CallToolResult) {
	items, toolErr := mcpRawStringListArg(arguments, name)
	if toolErr != nil || items == nil {
		return nil, toolErr
	}
	list := make([]string, 0, len(items))
	for _, item := range items {
		if item = strings.TrimSpace(item); item != "" {
			list = append(list, item)
		}
	}
	return list, nil
}

// mcpRawStringListArg reads an optional array-of-strings argument without
// altering its elements. A missing or null argument returns nil; a supplied
// empty array returns an empty, non-nil slice.
func mcpRawStringListArg(arguments map[string]any, name string) ([]string, *mcp.CallToolResult) {
	raw, ok := arguments[name]
	if !ok || raw == nil {
		return nil, nil
	}
	var items []string
	switch v := raw.(type) {
	case []string:
		items = v
	case []any:
		items = make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("%s array elements must be strings", name), map[string]any{"argument": name})
			}
			items = append(items, s)
		}
	default:
		return nil, mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("%s argument must be an array of strings", name), map[string]any{"argument": name})
	}
	return items, nil
}

// mcpSelectorListArg reads a list that narrows the binding. A supplied
// non-empty list whose entries are all blank is refused: dropping them would
// silently leave the binding without the selector and so wider than asked.
func mcpSelectorListArg(arguments map[string]any, name string) ([]string, *mcp.CallToolResult) {
	list, toolErr := mcpStringListArg(arguments, name)
	if toolErr != nil {
		return nil, toolErr
	}
	supplied := 0
	switch v := arguments[name].(type) {
	case []string:
		supplied = len(v)
	case []any:
		supplied = len(v)
	}
	if supplied > 0 && len(list) == 0 {
		return nil, mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("%s must not contain only blank entries", name), map[string]any{"argument": name})
	}
	return list, nil
}
