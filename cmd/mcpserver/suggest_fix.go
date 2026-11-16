package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	ksmetav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/pkg/fixhandler"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
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

func suggestFixKey(path, reportPath, basePath string, controlIDs []string) string {
	sortedIDs := make([]string, len(controlIDs))
	copy(sortedIDs, controlIDs)
	sort.Strings(sortedIDs)
	return fmt.Sprintf("suggest_fix:%s:%s:%s:%s",
		url.QueryEscape(path),
		url.QueryEscape(reportPath),
		url.QueryEscape(basePath),
		url.QueryEscape(strings.Join(sortedIDs, ",")),
	)
}

func (ksServer *KubescapeMcpserver) runSuggestFix(ctx context.Context, path string, controlIDs []string, workspaceRoots ...*os.Root) ([]byte, error) {
	outcome, err := iacScanReportFn(ksServer, ctx, path, controlIDs)
	if err != nil {
		return nil, err
	}
	var workspaceRoot *os.Root
	if len(workspaceRoots) > 0 {
		workspaceRoot = workspaceRoots[0]
	}
	return runSuggestFixCore(ctx, outcome.ReportJSON, remediationRequest{
		controlIDs:     controlIDs,
		selectControls: len(controlIDs) > 0,
		workspaceRoot:  workspaceRoot,
		degraded:       outcome.Degraded,
		notEvaluated:   outcome.NotEvaluatedControls,
		useScanOutcome: true,
	})
}

func runSuggestFixFromReport(ctx context.Context, reportPath, basePath string, controlIDs []string, workspaceRoots ...*os.Root) ([]byte, error) {
	var workspaceRoot *os.Root
	if len(workspaceRoots) > 0 {
		workspaceRoot = workspaceRoots[0]
	}
	raw, err := readRemediationReportWithRoot(reportPath, workspaceRoot)
	if err != nil {
		return nil, err
	}

	var report reporthandlingv2.PostureReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, newRemediationInputError("report_path %q is not a Kubescape posture report JSON: %v", reportPath, err)
	}

	req := remediationRequest{
		controlIDs:     controlIDs,
		selectControls: len(controlIDs) > 0,
		inputErrors:    true,
		report:         &report,
	}
	if !fixhandler.IsClusterPostureReport(&report) {
		if basePath == "" {
			return nil, newRemediationInputError("base_path is required with report_path for a report of a file, directory or git scan: the report names where its files are, and base_path is the directory they must stay inside")
		}
		resolved, err := resolveRemediationBasePath(basePath)
		if err != nil {
			return nil, err
		}
		req.basePath = resolved
	}
	req.workspaceRoot = workspaceRoot
	return runSuggestFixCore(ctx, raw, req)
}

func runSuggestFixCore(ctx context.Context, reportBytes []byte, req remediationRequest) ([]byte, error) {
	tempName, cleanup, err := stageRemediationReport(reportBytes)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	fixInfo := &ksmetav1.FixInfo{
		ReportFile: tempName,
		DryRun:     true,
		NoConfirm:  true,
		BasePath:   req.basePath,
	}
	if req.selectControls {
		fixInfo.IncludeControls = req.controlIDs
	}
	handler, err := fixhandler.NewFixHandlerWithRoot(fixInfo, req.workspaceRoot)
	if err != nil {
		if req.inputErrors {
			return nil, newRemediationInputError("report_path is not usable as a remediation report: %v", err)
		}
		return nil, fmt.Errorf("failed to initialize fix handler: %w", err)
	}

	report, coverage, err := parseRemediationReport(reportBytes, req.report)
	if err != nil {
		return nil, err
	}

	resourcesToFix := handler.PrepareResourcesToFix(ctx)

	files := make([]suggestFixFileResult, 0)
	rendered := make([]renderedManifest, 0)
	var warnings []string
	renderFailed := make(map[string]string)

	var diff string
	var filesChanged int
	var resourcesChanged int

	if handler.IsClusterReport() {
		for i := range resourcesToFix {
			rfi := resourcesToFix[i]
			if rfi.Resource == nil {
				continue
			}
			id := rfi.Resource.GetID()
			fixes, errs := handler.RenderFixes(ctx, []fixhandler.ResourceFixInfo{rfi})
			if len(errs) > 0 {
				renderFailed[id] = errs[0].Error()
				warnings = append(warnings, fmt.Sprintf("could not render the fix for resource %s: %v", id, errs[0]))
				continue
			}
			for _, fix := range fixes {
				rendered = append(rendered, renderedManifest{ResourceID: id, Manifest: fix.Manifest})
			}
		}
		sort.Slice(rendered, func(i, j int) bool { return rendered[i].ResourceID < rendered[j].ResourceID })
		resourcesChanged = len(rendered)
	} else {
		patchResult, err := handler.BuildPatch(ctx, resourcesToFix)
		if err != nil {
			return nil, fmt.Errorf("failed to build patch: %w", err)
		}
		if patchResult != nil {
			diff = patchResult.Patch
			filesChanged = patchResult.Files
			resourcesChanged = patchResult.Resources
		}

		patchNames, _ := handler.PatchNames(resourcesToFix)

		fileFixes := make(map[string][]fixhandler.ResourceFixInfo)
		for _, rfi := range resourcesToFix {
			fileFixes[rfi.FilePath] = append(fileFixes[rfi.FilePath], rfi)
		}

		filePaths := make([]string, 0, len(fileFixes))
		for fp := range fileFixes {
			filePaths = append(filePaths, fp)
		}
		sort.Strings(filePaths)

		for _, fp := range filePaths {
			fileAsString, err := handler.GetFileString(fp)
			if err != nil {
				return nil, err
			}
			patched, expressions, err := fixhandler.ApplyFixesInPlace(ctx, fp, fileAsString, fileFixes[fp])
			if err != nil {
				return nil, fmt.Errorf("failed to compute fix for %s: %w", fp, err)
			}
			diffName := fp
			if patchNames != nil && patchNames[fp] != "" {
				diffName = patchNames[fp]
			}
			fileDiff := fixhandler.UnifiedDiff(diffName, fileAsString, patched)
			files = append(files, suggestFixFileResult{
				FilePath:           fp,
				Diff:               fileDiff,
				AppliedExpressions: expressions,
			})
		}
	}

	unfixed := handler.UnfixedControls()
	sort.SliceStable(unfixed, func(i, j int) bool {
		a, b := unfixed[i], unfixed[j]
		if a.ResourceID != b.ResourceID {
			return a.ResourceID < b.ResourceID
		}
		if a.ControlID != b.ControlID {
			return a.ControlID < b.ControlID
		}
		if a.DocumentIndex != b.DocumentIndex {
			return a.DocumentIndex < b.DocumentIndex
		}
		return a.FilePath < b.FilePath
	})
	reported := reportedControlIDs(report)
	notEvaluated := req.notEvaluated
	degraded := req.degraded
	if !req.useScanOutcome && coverage != nil {
		notEvaluated = coverage.NotEvaluatedControls
		degraded = coverage.Degraded
	}
	unaddressed := unaddressedControls(req.controlIDs, reported, unfixed, notEvaluated)
	unfixed = append(unfixed, unaddressed...)

	if coverage == nil {
		warnings = append(warnings, "the report carries no scanCoverage, so whether the scan was complete cannot be determined; an empty items list is not confirmation that nothing failed")
	}

	resp := suggestFixResponse{
		Diff:                  diff,
		FilesChanged:          filesChanged,
		ResourcesChanged:      resourcesChanged,
		FixedControlInstances: handler.FixedControlsCount(),
		Files:                 files,
		RenderedManifests:     rendered,
		Items:                 buildRemediationItems(handler.ControlOutcomes(), unaddressed, report, renderFailed),
		UnfixedControls:       unfixed,
		Report:                summarizeRemediationReport(report, coverage),
		Degraded:              degraded,
		Warnings:              boundWarnings(warnings),
	}
	return json.MarshalIndent(resp, "", "  ")
}
