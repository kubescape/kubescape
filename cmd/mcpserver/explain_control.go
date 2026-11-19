package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/pkg/fixhandler"
	"github.com/kubescape/kubescape/v4/core/pkg/pathcontainment"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/diff"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/mark3labs/mcp-go/mcp"
)

// explainFailingResource represents one failing resource and its specific failed paths.
type explainFailingResource struct {
	ResourceID  string   `json:"resource_id,omitempty"`
	Kind        string   `json:"kind,omitempty"`
	Name        string   `json:"name,omitempty"`
	Namespace   string   `json:"namespace,omitempty"`
	FilePath    string   `json:"file_path,omitempty"`
	FailedPaths []string `json:"failed_paths"`
}

// explainControlResponse is the output structure for the explain_control tool.
type explainControlResponse struct {
	ControlID          string                    `json:"control_id"`
	Name               string                    `json:"name"`
	Severity           string                    `json:"severity"`
	Description        string                    `json:"description"`
	Remediation        string                    `json:"remediation"`
	AutoFixAvailable   bool                      `json:"auto_fix_available"`
	FailingResources   *[]explainFailingResource `json:"failing_resources,omitempty"`
	Degraded           bool                      `json:"degraded,omitempty"`
	NotEvaluated       bool                      `json:"not_evaluated,omitempty"`
	NotEvaluatedReason string                    `json:"not_evaluated_reason,omitempty"`
}

func createExplainControlTools(ksServer *KubescapeMcpserver) {
	explainControlTool := mcp.NewTool(
		"explain_control",
		mcp.WithDescription("Explain a Kubescape security control by ID, returning its metadata (name, description, severity, remediation guidance, and whether it has an auto-fix available through kubescape fix) and optionally including failing resources and specific failed paths from a local manifest (path) or an existing posture report JSON (report_path)."),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithString("control_id",
			mcp.Required(),
			mcp.Description("The control ID to explain (e.g. \"C-0017\")."),
		),
		mcp.WithString("path",
			mcp.Description("Optional path to a local YAML manifest file or directory to scan for control failures."),
		),
		mcp.WithString("report_path",
			mcp.Description("Optional path to an existing Kubescape posture report JSON file to extract control failures from."),
		),
		mcp.WithString("base_path",
			mcp.Description("Optional base directory that files referenced in report_path must stay inside."),
		),
	)
	ksServer.s.AddTool(explainControlTool, ksServer.toolHandler(explainControlTool.Name))
}

// ExplainControl handles the explain_control MCP tool invocation.
func (ksServer *KubescapeMcpserver) ExplainControl(ctx context.Context, arguments map[string]any) (*mcp.CallToolResult, error) {
	if arguments == nil {
		arguments = map[string]any{}
	}

	controlID, toolErr := mcpRequiredStringArg(arguments, "control_id")
	if toolErr != nil {
		return toolErr, nil
	}

	path, toolErr := mcpStringArg(arguments, "path")
	if toolErr != nil {
		return toolErr, nil
	}

	reportPath, toolErr := mcpStringArg(arguments, "report_path")
	if toolErr != nil {
		return toolErr, nil
	}

	basePath, toolErr := mcpStringArg(arguments, "base_path")
	if toolErr != nil {
		return toolErr, nil
	}

	if path != "" && reportPath != "" {
		return mcpToolError(ErrCodeInvalidArgument, "path and report_path are mutually exclusive; supply at most one", map[string]any{"argument": "report_path"}), nil
	}
	if path != "" && basePath != "" {
		return mcpToolError(ErrCodeInvalidArgument, "base_path applies only with report_path", map[string]any{"argument": "base_path"}), nil
	}
	if reportPath == "" && basePath != "" {
		return mcpToolError(ErrCodeInvalidArgument, "base_path applies only with report_path", map[string]any{"argument": "base_path"}), nil
	}

	if reportPath != "" {
		if reportPath, toolErr = ksServer.containToWorkspace("report_path", reportPath); toolErr != nil {
			return toolErr, nil
		}
	}
	if basePath != "" {
		if basePath, toolErr = ksServer.containToWorkspace("base_path", basePath); toolErr != nil {
			return toolErr, nil
		}
		resolvedBase, err := resolveRemediationBasePath(basePath)
		if err != nil {
			return mcpToolError(ErrCodeInvalidArgument, err.Error(), map[string]any{"argument": "base_path"}), nil
		}
		basePath = resolvedBase
	}
	if path != "" {
		if path, toolErr = ksServer.containToWorkspace("path", path); toolErr != nil {
			return toolErr, nil
		}
	}

	workspaceRoot, closeWorkspaceRoot, err := ksServer.openWorkspaceRoot()
	if err != nil {
		return mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("cannot open workspace root: %v", err), nil), nil
	}
	defer closeWorkspaceRoot()

	pg, err := ksServer.readyPolicyGetter(ctx)
	if err != nil {
		return mcpToolError(classifyScanError(err), fmt.Sprintf("failed to get policy getter: %v", err), nil), nil
	}

	control, err := getter.ResolveControl(pg, controlID)
	var ambiguous *getter.AmbiguousControlError
	switch {
	case errors.Is(err, getter.ErrControlNotFound):
		return mcpToolError(classifyScanError(err), fmt.Sprintf("control '%s' not found", strings.TrimSpace(controlID)), map[string]any{"control_id": controlID}), nil
	case errors.As(err, &ambiguous):
		return mcpToolError(ErrCodeInvalidArgument, ambiguous.Error(), map[string]any{"argument": "control_id", "matches": ambiguous.Matches}), nil
	case err != nil:
		return mcpToolError(classifyScanError(err), fmt.Sprintf("failed to resolve control %q: %v", controlID, err), nil), nil
	}

	canonicalID := control.ControlID
	if canonicalID == "" {
		canonicalID = strings.TrimSpace(controlID)
	}

	name := control.GetName()
	if name == "" {
		name = control.Name
	}

	severity := apis.ControlSeverityToString(control.BaseScore)
	if severity == apis.SeverityUnknownString && control.Attributes != nil {
		if s, ok := control.Attributes["severity"].(string); ok && s != "" {
			severity = s
		}
	}

	description := control.Description
	if description == "" && len(control.Rules) > 0 {
		description = control.Rules[0].Description
	}

	remediation := control.Remediation
	if remediation == "" && len(control.Rules) > 0 {
		remediation = control.Rules[0].Remediation
	}

	var failingResources *[]explainFailingResource
	scanFixable := false
	degraded := false
	notEvaluated := false
	notEvaluatedReason := ""

	if reportPath != "" {
		raw, err := readRemediationReportWithRoot(reportPath, workspaceRoot)
		if err != nil {
			return mcpToolError(ErrCodeInvalidArgument, err.Error(), map[string]any{"argument": "report_path"}), nil
		}
		var report reporthandlingv2.PostureReport
		if err := json.Unmarshal(raw, &report); err != nil {
			return mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("report_path %q is not a Kubescape posture report JSON: %v", reportPath, err), map[string]any{"argument": "report_path"}), nil
		}
		if !isPostureReport(raw, &report) {
			return mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("report_path %q is not a Kubescape posture report JSON", reportPath), map[string]any{"argument": "report_path"}), nil
		}
		_, cov, err := parseRemediationReport(raw, &report)
		if err != nil {
			return mcpToolError(ErrCodeInvalidArgument, fmt.Sprintf("report_path %q has invalid scan coverage: %v", reportPath, err), map[string]any{"argument": "report_path"}), nil
		}
		if cov != nil {
			if cov.Degraded || len(cov.FailedGVRPulls) > 0 || len(cov.PartialGVRPulls) > 0 ||
				len(cov.PolicyDegradations) > 0 || len(cov.SkippedManifests) > 0 {
				degraded = true
			}
			for _, ne := range cov.NotEvaluatedControls {
				if strings.EqualFold(ne.ControlID, canonicalID) {
					notEvaluated = true
					notEvaluatedReason = ne.ReasonString()
					degraded = true
					break
				}
			}
		}
		if !controlInReportScope(&report, canonicalID) {
			notEvaluated = true
			if notEvaluatedReason == "" {
				notEvaluatedReason = fmt.Sprintf("control '%s' is outside report scope", canonicalID)
			}
		}
		rsrcs, fixable := extractFailingResources(&report, canonicalID, basePath)
		failingResources = &rsrcs
		scanFixable = fixable
	} else if path != "" {
		var scanKey string
		if rev := pathRevision(path); rev != "" {
			scanKey = explainScanKey(path, canonicalID, rev)
		} else {
			scanKey = explainScanKey(path, canonicalID, fmt.Sprintf("fresh_%d", atomic.AddUint64(&explainFreshScanSeq, 1)))
		}
		v, err := ksServer.doScanChan(ctx, scanKey, func(scanCtx context.Context) (interface{}, error) {
			return iacScanReportFn(ksServer, scanCtx, path, []string{canonicalID})
		})
		if err != nil {
			return mcpToolError(classifyScanError(err), fmt.Sprintf("failed to scan path %q: %v", path, err), nil), nil
		}
		outcome := v.(*iacScanOutcome)
		var report reporthandlingv2.PostureReport
		if err := json.Unmarshal(outcome.ReportJSON, &report); err != nil {
			return mcpToolError(ErrCodeScanFailed, fmt.Sprintf("failed to parse scan report: %v", err), nil), nil
		}
		if outcome.Degraded {
			degraded = true
		}
		for _, ne := range outcome.NotEvaluatedControls {
			if strings.EqualFold(ne.ControlID, canonicalID) {
				notEvaluated = true
				notEvaluatedReason = ne.ReasonString()
				degraded = true
				break
			}
		}
		rsrcs, fixable := extractFailingResources(&report, canonicalID, basePath)
		failingResources = &rsrcs
		scanFixable = fixable
	}

	autoFixAvailable := controlHasAutoFix(control, scanFixable)

	response := explainControlResponse{
		ControlID:          canonicalID,
		Name:               name,
		Severity:           severity,
		Description:        description,
		Remediation:        remediation,
		AutoFixAvailable:   autoFixAvailable,
		FailingResources:   failingResources,
		Degraded:           degraded,
		NotEvaluated:       notEvaluated,
		NotEvaluatedReason: notEvaluatedReason,
	}

	responseJSON, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return mcpToolError(ErrCodeMarshalError, fmt.Sprintf("failed to marshal explain_control response: %v", err), nil), nil
	}
	return mcp.NewToolResultText(string(responseJSON)), nil
}

var explainFreshScanSeq uint64

// explainScanKey is the in-flight coalescing key of the scan behind one explain_control call.
func explainScanKey(path, controlID string, revision ...string) string {
	if len(revision) > 0 && revision[0] != "" {
		return fmt.Sprintf("explain_control:%s:%s:%s", url.QueryEscape(path), url.QueryEscape(controlID), url.QueryEscape(revision[0]))
	}
	return fmt.Sprintf("explain_control:%s:%s", url.QueryEscape(path), url.QueryEscape(controlID))
}

// pathRevision computes a reliable revision identifier for regular files based on file
// modification times and sizes. For directories (where scanner inputs may include Terraform,
// Helm, and various manifests whose traversal would be unbounded and uncancellable) or when
// stat fails, it returns an empty revision so a fresh scan key is used under doScanChan.
func pathRevision(target string) string {
	fi, err := os.Stat(target)
	if err != nil || fi.IsDir() {
		return ""
	}
	return fmt.Sprintf("%d_%d", fi.ModTime().UnixNano(), fi.Size())
}

// controlInReportScope reports whether targetControlID was evaluated in report,
// checking both SummaryDetails and Results.
func controlInReportScope(report *reporthandlingv2.PostureReport, targetControlID string) bool {
	norm := normalizeControlID(targetControlID)
	for id := range report.SummaryDetails.Controls {
		if normalizeControlID(id) == norm {
			return true
		}
	}
	for i := range report.SummaryDetails.Frameworks {
		for id := range report.SummaryDetails.Frameworks[i].Controls {
			if normalizeControlID(id) == norm {
				return true
			}
		}
	}
	for i := range report.Results {
		for _, ctrl := range report.Results[i].AssociatedControls {
			if normalizeControlID(ctrl.ControlID) == norm || normalizeControlID(ctrl.GetID()) == norm {
				return true
			}
		}
	}
	return false
}

// isPostureReport checks whether raw JSON bytes or the decoded report match the structure of a Kubescape posture report.
func isPostureReport(raw []byte, report *reporthandlingv2.PostureReport) bool {
	if diff.ReportKindOfJSON(raw) == diff.PostureReport {
		return true
	}
	if report != nil {
		if len(report.Results) > 0 || len(report.Resources) > 0 || report.ReportID != "" || report.ClusterName != "" || !report.ReportGenerationTime.IsZero() {
			return true
		}
	}
	return false
}

// extractFailingResources searches a PostureReport for resources that failed the given control,
// collecting the unique failed paths for each resource and checking if any rule provides a FixPath.
// If basePath is non-empty, file references that escape basePath are rejected.
func extractFailingResources(report *reporthandlingv2.PostureReport, targetControlID, basePath string) ([]explainFailingResource, bool) {
	resourcesMap := make(map[string]*reporthandling.Resource)
	for i := range report.Resources {
		resourcesMap[report.Resources[i].GetID()] = &report.Resources[i]
	}
	for i := range report.Results {
		if report.Results[i].RawResource != nil {
			resourcesMap[report.Results[i].RawResource.GetID()] = report.Results[i].RawResource
		}
	}

	byResourceID := make(map[string]*explainFailingResource)
	rejectedResourceIDs := make(map[string]bool)
	hasFixPath := false

	for i := range report.Results {
		resResult := &report.Results[i]
		if rejectedResourceIDs[resResult.ResourceID] {
			continue
		}

		rawRes := resResult.RawResource
		if rawRes == nil {
			rawRes = resourcesMap[resResult.ResourceID]
		}

		for j := range resResult.AssociatedControls {
			ctrl := &resResult.AssociatedControls[j]
			if !strings.EqualFold(ctrl.ControlID, targetControlID) && !strings.EqualFold(ctrl.GetID(), targetControlID) {
				continue
			}

			if !cautils.ControlStatus(&report.SummaryDetails, ctrl).IsFailed() {
				continue
			}

			failedCtrl := cautils.FailedRules(&report.SummaryDetails, *ctrl)

			entry, exists := byResourceID[resResult.ResourceID]
			if !exists {
				entry = &explainFailingResource{
					ResourceID:  resResult.ResourceID,
					FailedPaths: make([]string, 0),
				}
				if rawRes != nil {
					entry.Kind = rawRes.GetKind()
					entry.Name = rawRes.GetName()
					entry.Namespace = rawRes.GetNamespace()
					var sourcePathFile string
					if obj := rawRes.GetObject(); obj != nil {
						if sp, ok := obj["sourcePath"].(string); ok && sp != "" {
							if idx := strings.LastIndex(sp, ":"); idx != -1 {
								if _, err := strconv.Atoi(sp[idx+1:]); err == nil {
									sp = sp[:idx]
								}
							}
							sourcePathFile = sp
						}
					}

					src := rawRes.GetSource()
					if src != nil && src.RelativePath != "" {
						entry.FilePath = src.RelativePath
					} else if sourcePathFile != "" {
						entry.FilePath = sourcePathFile
					} else if src != nil && src.Path != "" {
						entry.FilePath = src.Path
					}
				}

				// If basePath is specified, resolve the file against the recorded source root
				// or scan root before checking containment. Use basePath as fallback when no root is recorded.
				if basePath != "" {
					var checkPath string
					var src *reporthandling.Source
					if rawRes != nil {
						src = rawRes.GetSource()
					}

					if entry.FilePath != "" {
						if filepath.IsAbs(entry.FilePath) {
							checkPath = entry.FilePath
						} else {
							var root string
							if src != nil && src.Path != "" && src.Path != entry.FilePath {
								root = src.Path
							} else if scanRoot := reportScanRoot(report); scanRoot != "" {
								root = scanRoot
							}
							if root != "" {
								checkPath = joinPathNoClean(root, entry.FilePath)
							} else {
								checkPath = entry.FilePath
							}
						}
					}

					if checkPath != "" {
						resolved, err := pathcontainment.ResolveContainedPath(basePath, checkPath)
						if err != nil {
							rejectedResourceIDs[resResult.ResourceID] = true
							break
						}
						if rel, err := filepath.Rel(basePath, resolved); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
							entry.FilePath = rel
						}
					}
				}

				byResourceID[resResult.ResourceID] = entry
			}

			seenPaths := make(map[string]bool)
			for _, p := range entry.FailedPaths {
				seenPaths[p] = true
			}

			for _, rule := range failedCtrl.ResourceAssociatedRules {
				for _, p := range rule.Paths {
					// PosturePaths.ResourceID names the resource the remediation applies to;
					// skip paths that remediate another resource.
					if p.ResourceID != "" && p.ResourceID != resResult.ResourceID {
						continue
					}
					if isFixableResource(report, rawRes) && p.FixPath.Path != "" && fixhandler.FixPathToValidYamlExpression(p.FixPath.Path, p.FixPath.Value, 0) != "" {
						hasFixPath = true
					}
					for _, candidate := range []string{p.FailedPath, p.FixPath.Path, p.DeletePath, p.ReviewPath} {
						if candidate != "" && !seenPaths[candidate] {
							seenPaths[candidate] = true
							entry.FailedPaths = append(entry.FailedPaths, candidate)
						}
					}
				}
			}
		}
	}

	result := make([]explainFailingResource, 0, len(byResourceID))
	for _, entry := range byResourceID {
		sort.Strings(entry.FailedPaths)
		result = append(result, *entry)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].ResourceID != result[j].ResourceID {
			return result[i].ResourceID < result[j].ResourceID
		}
		return result[i].Name < result[j].Name
	})

	return result, hasFixPath
}

// controlHasAutoFix checks if the control has auto-fix available through kubescape fix.
func controlHasAutoFix(ctrl *reporthandling.Control, scanFixable bool) bool {
	if scanFixable {
		return true
	}
	if ctrl == nil {
		return false
	}
	if ctrl.Attributes != nil {
		for k, v := range ctrl.Attributes {
			if strings.EqualFold(k, "controlTypeTags") && isSmartRemediationTag(v) {
				return true
			}
			if strings.EqualFold(k, "smartRemediation") {
				if b, ok := v.(bool); ok && b {
					return true
				}
				if s, ok := v.(string); ok && strings.EqualFold(s, "true") {
					return true
				}
			}
		}
	}
	for _, rule := range ctrl.Rules {
		if rule.Attributes != nil {
			for k, v := range rule.Attributes {
				if strings.EqualFold(k, "controlTypeTags") && isSmartRemediationTag(v) {
					return true
				}
				if strings.EqualFold(k, "smartRemediation") {
					if b, ok := v.(bool); ok && b {
						return true
					}
					if s, ok := v.(string); ok && strings.EqualFold(s, "true") {
						return true
					}
				}
			}
		}
	}
	return false
}

func isSmartRemediationTag(val any) bool {
	switch v := val.(type) {
	case string:
		return strings.EqualFold(v, "smartRemediation")
	case []string:
		for _, s := range v {
			if strings.EqualFold(s, "smartRemediation") {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && strings.EqualFold(s, "smartRemediation") {
				return true
			}
		}
	}
	return false
}

// reportScanRoot extracts the root directory of a posture report, where available.
func reportScanRoot(report *reporthandlingv2.PostureReport) string {
	if report == nil {
		return ""
	}
	switch report.Metadata.ScanMetadata.ScanningTarget {
	case reporthandlingv2.GitLocal:
		if repo := report.Metadata.ContextMetadata.RepoContextMetadata; repo != nil {
			return repo.LocalRootPath
		}
	case reporthandlingv2.Directory:
		if dir := report.Metadata.ContextMetadata.DirectoryContextMetadata; dir != nil {
			return dir.BasePath
		}
	case reporthandlingv2.File:
		if file := report.Metadata.ContextMetadata.FileContextMetadata; file != nil {
			return cautils.FileScanRootPath(file.FilePath)
		}
	}
	return ""
}

// joinPathNoClean joins a base directory and a relative path without lexical cleaning,
// preserving component-by-component symlink traversal for ResolveContainedPath.
func joinPathNoClean(base, rel string) string {
	if base == "" {
		return rel
	}
	if rel == "" {
		return base
	}
	return strings.TrimSuffix(base, string(filepath.Separator)) + string(filepath.Separator) + strings.TrimPrefix(rel, string(filepath.Separator))
}

// isFixableResource reports whether kubescape fix can remediate this resource.
// For cluster scans, kubescape fix plans and renders manifest changes directly from
// the scanned cluster object without requiring a local file source. For local scans,
// it requires an eligible YAML or JSON manifest file that the fix engine can mutate.
func isFixableResource(report *reporthandlingv2.PostureReport, rawRes *reporthandling.Resource) bool {
	if rawRes == nil {
		return false
	}
	if fixhandler.IsClusterPostureReport(report) {
		return true
	}
	src := rawRes.GetSource()
	if src == nil {
		return false
	}
	ft := strings.ToUpper(strings.TrimSpace(src.FileType))
	if ft == reporthandling.SourceTypeYaml || ft == reporthandling.SourceTypeJson || ft == "YML" {
		return true
	}
	if ft == "" {
		ext := strings.ToLower(filepath.Ext(src.RelativePath))
		if ext == "" {
			ext = strings.ToLower(filepath.Ext(src.Path))
		}
		return ext == ".yaml" || ext == ".yml" || ext == ".json"
	}
	return false
}
