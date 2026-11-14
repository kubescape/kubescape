package mcpserver

import (
	"fmt"

	"github.com/kubescape/kubescape/v4/core/pkg/vulnexposure"
	"github.com/mark3labs/mcp-go/mcp"
)

// parseControlMinSeverity reads the optional min_severity argument of the
// configuration scan tools. It returns SeverityUnknown when it is not set.
func parseControlMinSeverity(arguments map[string]any) (vulnexposure.Severity, *mcp.CallToolResult) {
	minSeverity, toolErr := mcpStringArg(arguments, "min_severity")
	if toolErr != nil || minSeverity == "" {
		return vulnexposure.SeverityUnknown, toolErr
	}
	severity := vulnexposure.ParseSeverity(minSeverity)
	// Controls are rated Low to Critical; grype's Negligible does not apply.
	if severity == vulnexposure.SeverityUnknown || severity == vulnexposure.SeverityNegligible {
		return vulnexposure.SeverityUnknown, mcpToolError(ErrCodeInvalidArgument,
			fmt.Sprintf("min_severity must be one of Critical, High, Medium, Low (got %q)", minSeverity),
			map[string]any{"argument": "min_severity", "supported_values": []string{"Critical", "High", "Medium", "Low"}})
	}
	return severity, nil
}
