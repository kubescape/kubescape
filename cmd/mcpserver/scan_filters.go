package mcpserver

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/kubescape/kubescape/v4/core/pkg/vulnexposure"
	"github.com/mark3labs/mcp-go/mcp"
	"k8s.io/apimachinery/pkg/labels"
)

type scanFilterArgs struct {
	includeKinds       string
	excludeKinds       string
	labelSelector      string
	excludeControls    []string
	minSeverity        string
	maxSeverity        string
	excludedNamespaces string
}

func (f scanFilterArgs) keySuffix() string {
	parts := make([]string, 0, 7)
	if f.minSeverity != "" {
		parts = append(parts, "minSev="+url.QueryEscape(f.minSeverity))
	}
	if f.maxSeverity != "" {
		parts = append(parts, "maxSev="+url.QueryEscape(f.maxSeverity))
	}
	if f.includeKinds != "" {
		parts = append(parts, "includeKinds="+url.QueryEscape(f.includeKinds))
	}
	if f.excludeKinds != "" {
		parts = append(parts, "excludeKinds="+url.QueryEscape(f.excludeKinds))
	}
	if f.labelSelector != "" {
		parts = append(parts, "labelSelector="+url.QueryEscape(f.labelSelector))
	}
	if f.excludedNamespaces != "" {
		parts = append(parts, "excludeNS="+url.QueryEscape(f.excludedNamespaces))
	}
	if len(f.excludeControls) > 0 {
		sortedControls := append([]string(nil), f.excludeControls...)
		sort.Strings(sortedControls)
		parts = append(parts, "excludeControls="+url.QueryEscape(strings.Join(sortedControls, ",")))
	}
	if len(parts) == 0 {
		return ""
	}
	return ":" + strings.Join(parts, ":")
}

func (f scanFilterArgs) applyToRequest(req *scanRequest) {
	req.includeKinds = f.includeKinds
	req.excludeKinds = f.excludeKinds
	req.labelSelector = f.labelSelector
	req.excludeControls = f.excludeControls
	req.minSeverity = f.minSeverity
	req.maxSeverity = f.maxSeverity
	req.excludedNamespaces = f.excludedNamespaces
}

func withOptionalExcludeControlsProperty(desc string) mcp.ToolOption {
	return func(t *mcp.Tool) {
		t.InputSchema.Properties["exclude_controls"] = map[string]any{
			"anyOf": []any{
				map[string]any{"type": "string"},
				map[string]any{
					"type":  "array",
					"items": map[string]any{"type": "string"},
				},
			},
			"description": desc,
		}
	}
}

func scanFilterOptions() []mcp.ToolOption {
	return []mcp.ToolOption{
		mcp.WithString("min_severity",
			mcp.Description("Minimum control severity to include in the scan results: Critical, High, Medium, Low (optional, case-insensitive)"),
		),
		mcp.WithString("max_severity",
			mcp.Description("Maximum control severity to include in the scan results: Critical, High, Medium, Low (optional, case-insensitive)"),
		),
		mcp.WithString("include_kinds",
			mcp.Description("Comma-separated Kubernetes resource kinds to include (optional, case-insensitive; e.g. \"Deployment,DaemonSet\")"),
		),
		mcp.WithString("exclude_kinds",
			mcp.Description("Comma-separated Kubernetes resource kinds to exclude (optional, case-insensitive; e.g. \"Job,CronJob\")"),
		),
		mcp.WithString("label_selector",
			mcp.Description("Kubernetes label selector to filter collected resources (optional, e.g. \"app=web,env!=dev\")"),
		),
		mcp.WithString("exclude_namespaces",
			mcp.Description("Comma-separated namespaces to exclude from the scan (optional, e.g. \"kube-system,kube-public\")"),
		),
		withOptionalExcludeControlsProperty("Control IDs to exclude from the scan: a comma-separated string (e.g. \"C-0012,C-0017\") or an array of strings (optional)"),
	}
}

func iacScanFilterOptions() []mcp.ToolOption {
	return []mcp.ToolOption{
		mcp.WithString("min_severity",
			mcp.Description("Minimum control severity to include in the scan results: Critical, High, Medium, Low (optional, case-insensitive)"),
		),
		mcp.WithString("max_severity",
			mcp.Description("Maximum control severity to include in the scan results: Critical, High, Medium, Low (optional, case-insensitive)"),
		),
		mcp.WithString("include_kinds",
			mcp.Description("Comma-separated Kubernetes resource kinds to include (optional, case-insensitive; e.g. \"Deployment,DaemonSet\")"),
		),
		mcp.WithString("exclude_kinds",
			mcp.Description("Comma-separated Kubernetes resource kinds to exclude (optional, case-insensitive; e.g. \"Job,CronJob\")"),
		),
		withOptionalExcludeControlsProperty("Control IDs to exclude from the scan: a comma-separated string (e.g. \"C-0012,C-0017\") or an array of strings (optional)"),
	}
}

func workloadScanFilterOptions() []mcp.ToolOption {
	return []mcp.ToolOption{
		mcp.WithString("min_severity",
			mcp.Description("Minimum control severity to include in the scan results: Critical, High, Medium, Low (optional, case-insensitive)"),
		),
		mcp.WithString("max_severity",
			mcp.Description("Maximum control severity to include in the scan results: Critical, High, Medium, Low (optional, case-insensitive)"),
		),
		withOptionalExcludeControlsProperty("Control IDs to exclude from the scan: a comma-separated string (e.g. \"C-0012,C-0017\") or an array of strings (optional)"),
	}
}

func parseSeverityValue(arguments map[string]any, argName string) (string, *mcp.CallToolResult) {
	val, toolErr := mcpStringArg(arguments, argName)
	if toolErr != nil || val == "" {
		return "", toolErr
	}
	sev := vulnexposure.ParseSeverity(val)
	if sev == vulnexposure.SeverityUnknown || sev == vulnexposure.SeverityNegligible {
		return "", mcpToolError(ErrCodeInvalidArgument,
			fmt.Sprintf("%s must be one of Critical, High, Medium, Low (got %q)", argName, val),
			map[string]any{"argument": argName, "supported_values": []string{"Critical", "High", "Medium", "Low"}})
	}
	return sev.String(), nil
}

func parseScanFilterArgs(arguments map[string]any, activeNamespace string) (scanFilterArgs, *mcp.CallToolResult) {
	var filters scanFilterArgs

	minSev, toolErr := parseSeverityValue(arguments, "min_severity")
	if toolErr != nil {
		return filters, toolErr
	}
	filters.minSeverity = minSev

	maxSev, toolErr := parseSeverityValue(arguments, "max_severity")
	if toolErr != nil {
		return filters, toolErr
	}
	filters.maxSeverity = maxSev

	if filters.minSeverity != "" && filters.maxSeverity != "" {
		minRank := vulnexposure.ParseSeverity(filters.minSeverity)
		maxRank := vulnexposure.ParseSeverity(filters.maxSeverity)
		if minRank > maxRank {
			return filters, mcpToolError(ErrCodeInvalidArgument,
				fmt.Sprintf("min_severity (%s) cannot be higher than max_severity (%s)", filters.minSeverity, filters.maxSeverity),
				map[string]any{"min_severity": filters.minSeverity, "max_severity": filters.maxSeverity})
		}
	}

	includeKinds, toolErr := mcpStringArg(arguments, "include_kinds")
	if toolErr != nil {
		return filters, toolErr
	}
	if strings.TrimSpace(includeKinds) != "" {
		hasValid := false
		for _, k := range strings.Split(includeKinds, ",") {
			if strings.TrimSpace(k) != "" {
				hasValid = true
				break
			}
		}
		if !hasValid {
			return filters, mcpToolError(ErrCodeInvalidArgument,
				fmt.Sprintf("include_kinds value %q contains no valid kind names", includeKinds),
				map[string]any{"argument": "include_kinds"})
		}
		filters.includeKinds = strings.TrimSpace(includeKinds)
	}

	excludeKinds, toolErr := mcpStringArg(arguments, "exclude_kinds")
	if toolErr != nil {
		return filters, toolErr
	}
	if strings.TrimSpace(excludeKinds) != "" {
		hasValid := false
		for _, k := range strings.Split(excludeKinds, ",") {
			if strings.TrimSpace(k) != "" {
				hasValid = true
				break
			}
		}
		if !hasValid {
			return filters, mcpToolError(ErrCodeInvalidArgument,
				fmt.Sprintf("exclude_kinds value %q contains no valid kind names", excludeKinds),
				map[string]any{"argument": "exclude_kinds"})
		}
		filters.excludeKinds = strings.TrimSpace(excludeKinds)
	}

	labelSelector, toolErr := mcpStringArg(arguments, "label_selector")
	if toolErr != nil {
		return filters, toolErr
	}
	if strings.TrimSpace(labelSelector) != "" {
		if _, err := labels.Parse(labelSelector); err != nil {
			return filters, mcpToolError(ErrCodeInvalidArgument,
				fmt.Sprintf("invalid label_selector %q: %v", labelSelector, err),
				map[string]any{"argument": "label_selector", "error": err.Error()})
		}
		filters.labelSelector = strings.TrimSpace(labelSelector)
	}

	excludeNS, toolErr := mcpStringArg(arguments, "exclude_namespaces")
	if toolErr != nil {
		return filters, toolErr
	}
	if strings.TrimSpace(excludeNS) != "" {
		trimmedNS := strings.TrimSpace(activeNamespace)
		if trimmedNS != "" && trimmedNS != "*" {
			return filters, mcpToolError(ErrCodeInvalidArgument,
				"namespace and exclude_namespaces cannot be used together",
				map[string]any{"argument": "exclude_namespaces"})
		}
		filters.excludedNamespaces = strings.TrimSpace(excludeNS)
	}

	if rawExcludeControls, hasExcludeControls := arguments["exclude_controls"]; hasExcludeControls && !unsetControlList(rawExcludeControls) {
		excludeControls, toolErr := parseControlIDsNamed("exclude_controls", rawExcludeControls, hasExcludeControls)
		if toolErr != nil {
			return filters, toolErr
		}
		filters.excludeControls = excludeControls
	}

	return filters, nil
}

// unsetControlList reports whether an optional control-ID list argument was sent
// without a value: JSON null, a blank string or an empty array. Like the other
// optional filters, that leaves the filter off instead of failing the call (see
// mcpStringArg). A value that holds only separators is still rejected.
func unsetControlList(raw any) bool {
	switch v := raw.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(v) == ""
	case []any:
		return len(v) == 0
	}
	return false
}

func parseLocalIaCFilterArgs(arguments map[string]any) (scanFilterArgs, *mcp.CallToolResult) {
	if _, ok := arguments["label_selector"]; ok {
		return scanFilterArgs{}, mcpToolError(ErrCodeInvalidArgument,
			"label_selector is not supported for local IaC scans: a local IaC scan evaluates files, not cluster resources",
			map[string]any{"argument": "label_selector"})
	}
	if _, ok := arguments["exclude_namespaces"]; ok {
		return scanFilterArgs{}, mcpToolError(ErrCodeInvalidArgument,
			"exclude_namespaces is not supported for local IaC scans: a local IaC scan evaluates files, not Kubernetes namespaces",
			map[string]any{"argument": "exclude_namespaces"})
	}
	return parseScanFilterArgs(arguments, "")
}
