package mcpserver

import (
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
)

// ErrorCode is a machine-readable string identifying the failure class.
type ErrorCode string

const (
	ErrCodeMalformedIdentifier ErrorCode = "MALFORMED_IDENTIFIER"
	// ErrCodeResourceNotFound indicates the requested target resource could not be found
	// in the cluster. This applies both during single-resource scan resolution
	// (via classifyScanError) and admission policy impact lookup (when the target object
	// does not exist in the cluster). From an LLM agent's perspective, the recovery
	// action for both cases is identical: verify and correct the resource kind, name,
	// or namespace.
	ErrCodeResourceNotFound    ErrorCode = "RESOURCE_NOT_FOUND"
	ErrCodeAmbiguousResource   ErrorCode = "AMBIGUOUS_RESOURCE"
	ErrCodeRBACDenied          ErrorCode = "RBAC_DENIED"
	ErrCodeInvalidArgument     ErrorCode = "INVALID_ARGUMENT"
	ErrCodeScanFailed          ErrorCode = "SCAN_EXECUTION_FAILED"
	ErrCodeK8sClientError      ErrorCode = "K8S_CLIENT_ERROR"
	ErrCodeMarshalError        ErrorCode = "MARSHAL_ERROR"
	ErrCodeTimeout             ErrorCode = "TIMEOUT"
	ErrCodeResourceHasParent   ErrorCode = "RESOURCE_HAS_PARENT"
	ErrCodeNotWorkload         ErrorCode = "NOT_A_WORKLOAD"
	ErrCodeSecretScanDenied    ErrorCode = "SECRET_SCAN_DENIED"
	ErrCodeUnsupportedResource ErrorCode = "UNSUPPORTED_RESOURCE_KIND"
)

// ToolError is the structured JSON payload returned inside
// mcp.NewToolResultError's text content.
type ToolError struct {
	Code    ErrorCode      `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// mcpToolError builds a *mcp.CallToolResult with IsError=true whose text
// content is the JSON-encoded ToolError.
func mcpToolError(code ErrorCode, message string, details map[string]any) *mcp.CallToolResult {
	te := ToolError{Code: code, Message: message, Details: sanitizeDetails(details)}
	b, err := json.Marshal(te)
	if err != nil {
		return mcp.NewToolResultError(message)
	}
	return mcp.NewToolResultError(string(b))
}

// sanitizeDetails returns a copy of details with only scalar values
// (string, int, int32, int64, float32, float64, bool) and string slices. This prevents
// leaking raw k8s objects, internal file paths, tokens, or deeply
// nested structures into the tool result. Nil input returns nil.
//
// Rule of thumb for contributors: details should contain only identifiers
// (argument, kind, name, namespace, resource_type, framework) and
// enumerations (supported_kinds, supported_values). Never: raw error
// stacks, file paths, auth tokens, k8s object dumps.
func sanitizeDetails(details map[string]any) map[string]any {
	if details == nil {
		return nil
	}
	clean := make(map[string]any, len(details))
	for k, v := range details {
		switch val := v.(type) {
		case string, int, int32, int64, float32, float64, bool:
			clean[k] = val
		case []string:
			clean[k] = val
		}
	}
	return clean
}
