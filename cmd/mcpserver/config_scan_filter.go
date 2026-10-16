package mcpserver

import (
	"fmt"
	"strings"

	"github.com/kubescape/kubescape/v4/core/pkg/vulnexposure"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/mark3labs/mcp-go/mcp"
)

// controlStatusFilterValues are the control statuses get_configuration_security_scan_manifest
// can filter on.
var controlStatusFilterValues = []string{string(apis.StatusFailed), string(apis.StatusPassed), string(apis.StatusSkipped)}

// scannedControlFilter selects the controls of a WorkloadConfigurationScan.
// The zero value keeps every control.
type scannedControlFilter struct {
	statuses    map[string]bool       // nil means every status
	minSeverity vulnexposure.Severity // SeverityUnknown means every severity
}

func (f scannedControlFilter) active() bool {
	return f.statuses != nil || f.minSeverity != vulnexposure.SeverityUnknown
}

// parseScannedControlFilter reads the optional status and min_severity
// arguments of get_configuration_security_scan_manifest.
func parseScannedControlFilter(arguments map[string]any) (scannedControlFilter, *mcp.CallToolResult) {
	var f scannedControlFilter

	status, toolErr := mcpStringArg(arguments, "status")
	if toolErr != nil {
		return f, toolErr
	}
	if status != "" {
		f.statuses = map[string]bool{}
		for _, s := range strings.Split(status, ",") {
			s = strings.ToLower(strings.TrimSpace(s))
			if !isControlStatusFilterValue(s) {
				return f, mcpToolError(ErrCodeInvalidArgument,
					fmt.Sprintf("status must be a comma-separated list of %s (got %q)", strings.Join(controlStatusFilterValues, ", "), status),
					map[string]any{"argument": "status", "supported_values": controlStatusFilterValues})
			}
			f.statuses[s] = true
		}
	}

	minSeverity, toolErr := mcpStringArg(arguments, "min_severity")
	if toolErr != nil {
		return f, toolErr
	}
	if minSeverity != "" {
		f.minSeverity = vulnexposure.ParseSeverity(minSeverity)
		// Controls are rated Low to Critical; grype's Negligible does not apply.
		if f.minSeverity == vulnexposure.SeverityUnknown || f.minSeverity == vulnexposure.SeverityNegligible {
			return f, mcpToolError(ErrCodeInvalidArgument,
				fmt.Sprintf("min_severity must be one of Critical, High, Medium, Low (got %q)", minSeverity),
				map[string]any{"argument": "min_severity", "supported_values": []string{"Critical", "High", "Medium", "Low"}})
		}
	}
	return f, nil
}

func isControlStatusFilterValue(s string) bool {
	for _, v := range controlStatusFilterValues {
		if s == v {
			return true
		}
	}
	return false
}

// filterScannedControls returns the controls the filter selects. It never
// modifies the given map.
func filterScannedControls(controls map[string]v1beta1.ScannedControl, f scannedControlFilter) map[string]v1beta1.ScannedControl {
	if !f.active() {
		return controls
	}
	out := make(map[string]v1beta1.ScannedControl, len(controls))
	for id, c := range controls {
		if f.statuses != nil && !f.statuses[strings.ToLower(c.Status.Status)] {
			continue
		}
		if vulnexposure.ParseSeverity(c.Severity.Severity) < f.minSeverity {
			continue
		}
		out[id] = c
	}
	return out
}
