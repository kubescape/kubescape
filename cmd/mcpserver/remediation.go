package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/kubescape/kubescape/v4/core/cautils"
	ksmetav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/pkg/fixhandler"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

// iacScanReportFn produces the PostureReport the remediation flow feeds to the
// fixhandler. Package-level so tests can supply a canned report instead of
// running a real scan.
var iacScanReportFn = func(s *KubescapeMcpserver, ctx context.Context, path string, controlIDs []string) (*iacScanOutcome, error) {
	return s.runIaCScanControlsReport(ctx, path, controlIDs)
}

// remediationFileResult is the patched content for one file. Multiple entries
// appear when path is a directory whose resources span several files.
type remediationFileResult struct {
	FilePath           string   `json:"file_path"`
	PatchedYAML        string   `json:"patched_yaml"`
	AppliedExpressions []string `json:"applied_expressions"`
}

type remediationResponse struct {
	Files []remediationFileResult `json:"files"`
	// FixedControlInstances counts (resource, control) tuples that produced at
	// least one edit.
	FixedControlInstances int `json:"fixed_control_instances"`
	// Degraded reports that the scan behind this remediation did not fully
	// complete, mirroring scanResponse.Degraded. An agent must not read an
	// empty files list on a degraded run as "everything is compliant".
	Degraded bool `json:"degraded"`
	// UnfixedControls tells the caller which controls have no deterministic
	// fix — the signal that stops an agent inventing one. It also carries any
	// requested control the scan never evaluated, so a control can never
	// silently vanish from the response.
	UnfixedControls []fixhandler.UnfixedControl `json:"unfixed_controls,omitempty"`
}

// normalizeControlID makes control IDs comparable regardless of how the caller
// spelled them: parseControlIDs only trims, so "c-0013" must still match the
// report's "C-0013".
func normalizeControlID(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}

// reportedControlIDs collects every control the scan actually accounted for,
// from both the summary and the per-resource results.
func reportedControlIDs(reportJSON []byte) (map[string]bool, error) {
	var report reporthandlingv2.PostureReport
	if err := json.Unmarshal(reportJSON, &report); err != nil {
		return nil, fmt.Errorf("failed to parse posture report: %w", err)
	}
	seen := make(map[string]bool)
	for id := range report.SummaryDetails.Controls {
		seen[normalizeControlID(id)] = true
	}
	for _, result := range report.Results {
		for _, control := range result.AssociatedControls {
			seen[normalizeControlID(control.ControlID)] = true
		}
	}
	return seen, nil
}

// unaddressedControls returns an UnfixedControl for every requested control the
// scan never accounted for.
//
// A degraded run can drop a control before it is ever evaluated. Such a control
// appears in neither files (nothing was fixed for it) nor the fixhandler's own
// unfixed list (which only covers controls the report marked failed), so
// omitting it would leave the caller unable to tell "this control passed" from
// "this control was skipped" — exactly the ambiguity apply_remediation exists to
// remove. A control that is present in the report and simply produced no fix
// genuinely passed, and is not reported here.
func unaddressedControls(requested []string, reported map[string]bool, unfixed []fixhandler.UnfixedControl, notEvaluated []cautils.NotEvaluatedControl) []fixhandler.UnfixedControl {
	covered := make(map[string]bool, len(unfixed))
	for _, uc := range unfixed {
		covered[normalizeControlID(uc.ControlID)] = true
	}

	reasons := make(map[string]string, len(notEvaluated))
	for _, ne := range notEvaluated {
		reason := ne.Reason
		if reason == "" {
			reason = "not evaluated: the scan could not evaluate this control"
		}
		if len(ne.MissingGVRs) > 0 {
			reason = fmt.Sprintf("%s (missing resource types: %s)", reason, strings.Join(ne.MissingGVRs, ", "))
		}
		reasons[normalizeControlID(ne.ControlID)] = reason
	}

	out := make([]fixhandler.UnfixedControl, 0)
	emitted := make(map[string]bool)
	for _, id := range requested {
		key := normalizeControlID(id)
		if key == "" || covered[key] || emitted[key] {
			continue
		}
		// ScanCoverage is authoritative about what was not evaluated and must be
		// consulted before the report. ConvertFrameworksToSummaryDetails seeds
		// SummaryDetails.Controls with every in-scope control *before* evaluation,
		// so a control can appear there — possibly with a skipped status — and
		// still never have been evaluated. Testing the report first would drop the
		// control-specific reason, and for a seeded summary would drop the entry
		// entirely, reintroducing the vanishing-control bug this function exists
		// to prevent.
		reason, notEvaluated := reasons[key]
		if !notEvaluated {
			if reported[key] {
				continue // evaluated; the absence of a fix means it passed
			}
			reason = "not evaluated: control did not appear in the scan report"
		}
		emitted[key] = true
		out = append(out, fixhandler.UnfixedControl{ControlID: id, Reason: reason})
	}
	return out
}

func createRemediationTools(ksServer *KubescapeMcpserver) {
	applyRemediationTool := mcp.NewTool(
		"apply_remediation",
		mcp.WithDescription("Compute the exact, deterministic YAML patch for failed controls in local IaC. Scans the given path for the given controls, derives Kubescape's official yq-based fixes, and returns the fully patched YAML as a string. DOES NOT modify any file on disk — the caller decides whether to write the returned content. Controls with no automatic fix are listed in unfixed_controls and must not be fixed by guesswork. Use list_controls to discover valid IDs."),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Absolute or relative path to the local YAML file or directory to remediate (e.g., /path/to/manifest.yaml)"),
		),
		withControlIDsProperty("Control IDs to remediate: a comma-separated string (e.g. \"C-0013,C-0017\") or an array of strings (e.g. [\"C-0013\"]). At least one ID is required."),
	)
	ksServer.s.AddTool(applyRemediationTool, ksServer.toolHandler(applyRemediationTool.Name))
}

func (ksServer *KubescapeMcpserver) runApplyRemediation(ctx context.Context, path string, controlIDs []string) ([]byte, error) {
	// 1. Scan in memory.
	outcome, err := iacScanReportFn(ksServer, ctx, path, controlIDs)
	if err != nil {
		return nil, err
	}
	reportBytes := outcome.ReportJSON

	// 2. NewFixHandler only accepts a report on disk, so stage one. Write and
	//    close before handing it over — NewFixHandler opens and reads it
	//    synchronously in the constructor (fixhandler.go:42-47), so removal is
	//    safe on every path after that.
	tempFile, err := os.CreateTemp("", "kubescape-mcp-remediation-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp report file: %w", err)
	}
	tempName := tempFile.Name()
	defer os.Remove(tempName)
	if _, err := tempFile.Write(reportBytes); err != nil {
		tempFile.Close()
		return nil, fmt.Errorf("failed to write temp report file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close temp report file: %w", err)
	}

	// 3. Instantiate the fixer in a dry-run configuration.
	handler, err := fixhandler.NewFixHandler(&ksmetav1.FixInfo{
		ReportFile: tempName,
		DryRun:     true, // documents intent; ApplyChanges is never called
		NoConfirm:  true,
		// SkipUserValues stays false: fixes whose value is a YOUR_* placeholder
		// are still returned, because the calling agent is exactly the party
		// that can substitute a real value.
		// BasePath stays empty: the report was generated in-process from the
		// caller's own path, so this is not the untrusted-report case BasePath
		// guards against.
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize fix handler: %w", err)
	}

	// 4. Plan the fixes. This writes nothing.
	resourcesToFix := handler.PrepareResourcesToFix(ctx)

	// 5. Group expressions per file and apply them in memory. Mirrors
	//    getFileYamlExpressions/reduceYamlExpressions (fixhandler.go:818, :989)
	//    without their disk write. Each key is already scoped with
	//    select(di==N), so multi-document files compose under one " | " pipeline.
	fileExprs := make(map[string][]string)
	fileFixes := make(map[string][]fixhandler.DocumentFix)
	for _, rfi := range resourcesToFix {
		exprs := make([]string, 0, len(rfi.YamlExpressions))
		for expr, fixPath := range rfi.YamlExpressions {
			exprs = append(exprs, expr)
			fileFixes[rfi.FilePath] = append(fileFixes[rfi.FilePath], fixhandler.DocumentFix{
				DocumentIndex: rfi.DocumentIndex,
				Fix:           fixPath,
			})
		}
		sort.Strings(exprs) // map iteration order is random; output must be stable
		fileExprs[rfi.FilePath] = append(fileExprs[rfi.FilePath], exprs...)
	}

	filePaths := make([]string, 0, len(fileExprs))
	for fp := range fileExprs {
		filePaths = append(filePaths, fp)
	}
	sort.Strings(filePaths)

	editor := fixhandler.NewYAMLTreeEditor()
	files := make([]remediationFileResult, 0, len(filePaths))
	for _, fp := range filePaths {
		fileAsString, err := fixhandler.GetFileString(fp)
		if err != nil {
			return nil, err
		}
		patched, err := editor.ApplyFixes(fileAsString, fileFixes[fp])
		if err != nil {
			return nil, fmt.Errorf("failed to compute fix for %s: %w", fp, err)
		}
		files = append(files, remediationFileResult{
			FilePath:           fp,
			PatchedYAML:        patched,
			AppliedExpressions: fileExprs[fp],
		})
	}

	// 6. Reconcile what was asked for against what the scan actually covered, so
	//    a control dropped by a degraded run surfaces instead of vanishing.
	unfixed := handler.UnfixedControls()
	reported, err := reportedControlIDs(reportBytes)
	if err != nil {
		return nil, err
	}
	unfixed = append(unfixed, unaddressedControls(controlIDs, reported, unfixed, outcome.NotEvaluatedControls)...)

	// 7. Always return the envelope, even with zero files: unfixed_controls
	//    then explains why nothing was fixable, which is more useful to an
	//    agent than an error.
	resp := remediationResponse{
		Files:                 files,
		FixedControlInstances: handler.FixedControlsCount(),
		Degraded:              outcome.Degraded,
		UnfixedControls:       unfixed,
	}
	return json.MarshalIndent(resp, "", "  ")
}
