package mcpserver

import (
	"github.com/kubescape/kubescape/v4/core/pkg/fixhandler"
	"github.com/mark3labs/mcp-go/mcp"
)

type suggestFixFileResult struct {
	FilePath           string   `json:"file_path"`
	Diff               string   `json:"diff"`
	AppliedExpressions []string `json:"applied_expressions"`
}

type suggestFixResponse struct {
	Diff                  string                      `json:"diff"`
	FilesChanged          int                         `json:"files_changed"`
	ResourcesChanged      int                         `json:"resources_changed"`
	FixedControlInstances int                         `json:"fixed_control_instances"`
	Files                 []suggestFixFileResult      `json:"files,omitempty"`
	RenderedManifests     []renderedManifest          `json:"rendered_manifests,omitempty"`
	Items                 []remediationItem           `json:"items"`
	UnfixedControls       []fixhandler.UnfixedControl `json:"unfixed_controls,omitempty"`
	Report                *remediationReportSummary   `json:"report,omitempty"`
	Degraded              bool                        `json:"degraded"`
	Warnings              []string                    `json:"warnings,omitempty"`
}

func createSuggestFixTools(ksServer *KubescapeMcpserver) {
	suggestFixTool := mcp.NewTool(
		"suggest_fix",
		mcp.WithDescription("Preview fixes for security findings as a unified git-compatible diff and structured plan without modifying files. Operates in dry-run mode from either local IaC (path) or an existing posture report JSON (report_path). Returns a unified diff, file-by-file changes, items classification, and unfixed controls. Control IDs are optional; if omitted, fixes are suggested for all failing controls."),
		mcp.WithString("path",
			mcp.Description("Absolute or relative path to the local YAML file or directory to scan and suggest fixes for (e.g., /path/to/manifest.yaml). Exactly one of path or report_path is required."),
		),
		mcp.WithString("report_path",
			mcp.Description("Path to an existing Kubescape posture report JSON file (kubescape scan --format json) to suggest fixes from. Exactly one of path or report_path is required."),
		),
		mcp.WithString("base_path",
			mcp.Description("Directory a file-backed report's files must stay inside. Required with report_path for a report of a file, directory or git scan, because the report itself names where those files are; ignored for a cluster report, which has none. Not allowed with path."),
		),
		withOptionalControlIDsProperty("Optional control IDs to remediate: a comma-separated string (e.g. \"C-0013,C-0017\") or an array of strings (e.g. [\"C-0013\"]). If omitted, fixes are suggested for all failing controls."),
	)
	ksServer.s.AddTool(suggestFixTool, ksServer.toolHandler(suggestFixTool.Name))
}
