package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/kubescape/kubescape/v4/core/cautils"
	ksmetav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/pkg/fixhandler"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
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

// renderedManifest is the patched manifest of one live-cluster resource. A
// cluster resource has no file, so its fix is rendered from the scanned object
// and returned here instead of in files. Nothing is written to the cluster:
// applying the manifest is left to the caller.
type renderedManifest struct {
	ResourceID string `json:"resource_id"`
	Manifest   string `json:"manifest"`
}

// Classification values for remediationItem.Classification.
const (
	// classPatchAvailable: the fixer counted this control as remediated by the
	// patch it planned for the resource. The patch is planned per resource, so
	// this is a statement about the resource's patch as a whole, not about an
	// expression specific to this control.
	classPatchAvailable = "patch_available"
	// classPartialPatch: some of the control's failed paths are covered by the
	// resource's patch and others are not. The control still needs manual work.
	classPartialPatch = "partial_patch"
	// classManual: the fixer produced no remediation for this control; reason
	// carries the fixer's own explanation.
	classManual = "manual"
	// classNotEvaluated: the control was requested but the scan never
	// evaluated it, so nothing is known about the resources it would flag.
	classNotEvaluated = "not_evaluated"
)

// Bounds on the evidence an item carries and the coverage lists the report
// summary carries, so one noisy control or report cannot dominate a response.
const (
	maxItemEvidenceRules    = 20
	maxItemEvidencePaths    = 20
	maxNotEvaluatedIDs      = 50
	maxRemediationWarnings  = 20
	maxRemediationReportLen = 64 << 20 // 64 MiB
)

type remediationResourceRef struct {
	Kind      string `json:"kind,omitempty"`
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace"`
}

type remediationControlRef struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// remediationEvidencePath copies one PosturePaths entry of the report verbatim.
type remediationEvidencePath struct {
	FailedPath string `json:"failed_path,omitempty"`
	ReviewPath string `json:"review_path,omitempty"`
	DeletePath string `json:"delete_path,omitempty"`
	FixPath    string `json:"fix_path,omitempty"`
	FixValue   string `json:"fix_value,omitempty"`
}

type remediationEvidenceRule struct {
	Rule      string                    `json:"rule"`
	Status    string                    `json:"status"`
	SubStatus string                    `json:"sub_status,omitempty"`
	Paths     []remediationEvidencePath `json:"paths"`
	// PathsTruncated is true when the rule had more paths than are listed.
	PathsTruncated bool `json:"paths_truncated,omitempty"`
}

// remediationItem is the outcome for one (resource, control) pair.
type remediationItem struct {
	// ResourceID is the report's opaque identifier of the resource. It is the
	// identity of the item; kind, name and namespace are display fields and two
	// distinct resources may share them. Empty for a not_evaluated item, which
	// concerns a control rather than a resource.
	ResourceID string                    `json:"resource_id"`
	Resource   *remediationResourceRef   `json:"resource,omitempty"`
	Control    remediationControlRef     `json:"control"`
	Evidence   []remediationEvidenceRule `json:"evidence"`
	// EvidenceTruncated is true when the control had more rules than are listed.
	EvidenceTruncated bool   `json:"evidence_truncated,omitempty"`
	Classification    string `json:"classification"`
	// Reason is the fixer's own reason for a control it did not remediate,
	// verbatim.
	Reason string `json:"reason,omitempty"`
	// FilePath is the manifest the resource was read from; empty for a cluster
	// resource.
	FilePath string `json:"file_path,omitempty"`
}

// remediationReportSummary is a bounded view of the report's scan coverage.
type remediationReportSummary struct {
	// Kind is cluster, directory, file, git or unknown.
	Kind string `json:"kind"`
	// CoverageAvailable is false when the report carries no scanCoverage, in
	// which case the counters below are zero and say nothing about completeness.
	CoverageAvailable bool `json:"coverage_available"`
	Degraded          bool `json:"degraded"`
	EvaluatedControls int  `json:"evaluated_controls"`
	TotalControls     int  `json:"total_controls"`
	// NotEvaluatedControlIDs lists at most maxNotEvaluatedIDs IDs, sorted;
	// NotEvaluatedControlCount is the full count.
	NotEvaluatedControlIDs   []string `json:"not_evaluated_control_ids"`
	NotEvaluatedControlCount int      `json:"not_evaluated_control_count"`
	FailedGVRPulls           int      `json:"failed_gvr_pulls"`
	SilentFailedGVRCount     int      `json:"silent_failed_gvr_count"`
	UnexaminedKinds          int      `json:"unexamined_kinds"`
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
	// Items is the structured, per-(resource, control) view of the same
	// accounting, sorted by (resource_id, control_id). It is always present.
	Items []remediationItem `json:"items"`
	// RenderedManifests holds the patched manifests of live-cluster resources,
	// sorted by resource_id. It is always present and empty for a file-backed
	// report, whose patches are in Files.
	RenderedManifests []renderedManifest        `json:"rendered_manifests"`
	Report            *remediationReportSummary `json:"report,omitempty"`
	// Warnings are bounded, human-readable notes about the run.
	Warnings []string `json:"warnings,omitempty"`
}

// remediationInputError marks a failure caused by the caller's input rather than
// by the scan, so the tool reports it as an invalid argument.
type remediationInputError struct{ msg string }

func (e *remediationInputError) Error() string { return e.msg }

func newRemediationInputError(format string, args ...any) error {
	return &remediationInputError{msg: fmt.Sprintf(format, args...)}
}

// normalizeControlID makes control IDs comparable regardless of how the caller
// spelled them: parseControlIDs only trims, so "c-0013" must still match the
// report's "C-0013".
func normalizeControlID(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}

// reportedControlIDs collects every control the scan actually accounted for,
// from both the summary and the per-resource results.
func reportedControlIDs(report *reporthandlingv2.PostureReport) map[string]bool {
	seen := make(map[string]bool)
	for id := range report.SummaryDetails.Controls {
		seen[normalizeControlID(id)] = true
	}
	for _, result := range report.Results {
		for _, control := range result.AssociatedControls {
			seen[normalizeControlID(control.ControlID)] = true
		}
	}
	return seen
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
		mcp.WithDescription("Compute the exact, deterministic YAML patch for failed controls, from either local IaC (path) or an existing posture report JSON (report_path), which may be a live-cluster report. Derives Kubescape's official yq-based fixes and returns the patched YAML as a string; a cluster resource's patched manifest is returned in rendered_manifests, a file's in files. DOES NOT modify any file on disk and DOES NOT change the cluster — the caller decides whether to write or apply the returned content. items lists every failed (resource, control) pair with a classification and the fixer's own reason; controls with no automatic fix are also listed in unfixed_controls and must not be fixed by guesswork. Use list_controls to discover valid IDs."),
		mcp.WithString("path",
			mcp.Description("Absolute or relative path to the local YAML file or directory to scan and remediate (e.g., /path/to/manifest.yaml). Exactly one of path or report_path is required."),
		),
		mcp.WithString("report_path",
			mcp.Description("Path to an existing Kubescape posture report JSON file (kubescape scan --format json) to plan remediation from instead of scanning. Exactly one of path or report_path is required."),
		),
		mcp.WithString("base_path",
			mcp.Description("Directory a file-backed report's files must stay inside. Required with report_path for a report of a file, directory or git scan, because the report itself names where those files are; ignored for a cluster report, which has none. Not allowed with path."),
		),
		withControlIDsProperty("Control IDs to remediate: a comma-separated string (e.g. \"C-0013,C-0017\") or an array of strings (e.g. [\"C-0013\"]). At least one ID is required."),
	)
	ksServer.s.AddTool(applyRemediationTool, ksServer.toolHandler(applyRemediationTool.Name))
}

// remediationKey is the in-flight coalescing key of one apply_remediation call.
// report_path and base_path both change the result, so both are in it: two calls
// that differ only in either must not share one execution.
func remediationKey(path, reportPath, basePath string, controlIDs []string) string {
	return fmt.Sprintf("apply_remediation:%s:%s:%s:%s",
		url.QueryEscape(path), url.QueryEscape(reportPath), url.QueryEscape(basePath),
		url.QueryEscape(strings.Join(controlIDs, ",")))
}

// remediationRequest carries what runRemediation needs beyond the report.
type remediationRequest struct {
	controlIDs []string
	// basePath, when set, is handed to the fixer as FixInfo.BasePath.
	basePath string
	// selectControls narrows the fixer to controlIDs. A scan already limited to
	// them has nothing left to narrow; an existing report has not.
	selectControls bool
	// inputErrors makes every error from loading the report an input error:
	// the report came from the caller, not from this process.
	inputErrors bool
	// degraded and notEvaluated come from the scan this process ran. Zero for
	// an existing report, whose coverage is read from the report itself.
	degraded     bool
	notEvaluated []cautils.NotEvaluatedControl
	// useScanOutcome distinguishes a scan this process ran from a report file.
	useScanOutcome bool
	// report is the decoded report when the caller already has it, so a large
	// report is not decoded again.
	report *reporthandlingv2.PostureReport
}

func (ksServer *KubescapeMcpserver) runApplyRemediation(ctx context.Context, path string, controlIDs []string) ([]byte, error) {
	// 1. Scan in memory.
	outcome, err := iacScanReportFn(ksServer, ctx, path, controlIDs)
	if err != nil {
		return nil, err
	}
	return runRemediation(ctx, outcome.ReportJSON, remediationRequest{
		controlIDs:     controlIDs,
		degraded:       outcome.Degraded,
		notEvaluated:   outcome.NotEvaluatedControls,
		useScanOutcome: true,
	})
}

// runApplyRemediationFromReport plans remediation from a report file that was
// produced elsewhere. It reads at most maxRemediationReportLen bytes, once, and
// works from that copy, so the file cannot change between the checks and the
// use.
func runApplyRemediationFromReport(ctx context.Context, reportPath, basePath string, controlIDs []string) ([]byte, error) {
	raw, err := readRemediationReport(reportPath)
	if err != nil {
		return nil, err
	}

	var report reporthandlingv2.PostureReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, newRemediationInputError("report_path %q is not a Kubescape posture report JSON: %v", reportPath, err)
	}

	req := remediationRequest{controlIDs: controlIDs, selectControls: true, inputErrors: true, report: &report}
	if !fixhandler.IsClusterPostureReport(&report) {
		// A file-backed report names, itself, where the files to patch are. A
		// report from another party must not be allowed to name a place the
		// caller did not vouch for, so the caller has to say where they are.
		// The report's own directory is not a safe default: a scan is
		// routinely written somewhere other than the tree it scanned.
		if basePath == "" {
			return nil, newRemediationInputError("base_path is required with report_path for a report of a file, directory or git scan: the report names where its files are, and base_path is the directory they must stay inside")
		}
		resolved, err := resolveRemediationBasePath(basePath)
		if err != nil {
			return nil, err
		}
		req.basePath = resolved
	}
	return runRemediation(ctx, raw, req)
}

// readRemediationReport reads a report file, refusing anything that is not a
// regular file or is larger than maxRemediationReportLen.
func readRemediationReport(reportPath string) ([]byte, error) {
	abs, err := filepath.Abs(reportPath)
	if err != nil {
		return nil, newRemediationInputError("report_path %q is not a usable path: %v", reportPath, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, newRemediationInputError("report_path %q cannot be read: %v", reportPath, err)
	}
	f, err := os.Open(resolved)
	if err != nil {
		return nil, newRemediationInputError("report_path %q cannot be read: %v", reportPath, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, newRemediationInputError("report_path %q cannot be read: %v", reportPath, err)
	}
	if !info.Mode().IsRegular() {
		return nil, newRemediationInputError("report_path %q is not a regular file", reportPath)
	}
	if info.Size() > maxRemediationReportLen {
		return nil, newRemediationInputError("report_path %q is %d bytes, larger than the %d byte limit", reportPath, info.Size(), int64(maxRemediationReportLen))
	}

	// The size above can be stale for a file that grows; bound the read itself.
	raw, err := io.ReadAll(io.LimitReader(f, maxRemediationReportLen+1))
	if err != nil {
		return nil, newRemediationInputError("report_path %q cannot be read: %v", reportPath, err)
	}
	if len(raw) > maxRemediationReportLen {
		return nil, newRemediationInputError("report_path %q is larger than the %d byte limit", reportPath, int64(maxRemediationReportLen))
	}
	return raw, nil
}

// resolveRemediationBasePath returns base_path as an absolute, symlink-free
// directory path.
func resolveRemediationBasePath(basePath string) (string, error) {
	abs, err := filepath.Abs(basePath)
	if err != nil {
		return "", newRemediationInputError("base_path %q is not a usable path: %v", basePath, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", newRemediationInputError("base_path %q cannot be resolved: %v", basePath, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", newRemediationInputError("base_path %q cannot be read: %v", basePath, err)
	}
	if !info.IsDir() {
		return "", newRemediationInputError("base_path %q is not a directory", basePath)
	}
	return resolved, nil
}

// stageRemediationReport writes the report to a private temporary file,
// because NewFixHandler only accepts a report on disk, and returns its name
// with a function that removes it. The handler opens and reads the file
// synchronously in its constructor (fixhandler.go:42-47), so removal is safe on
// every path after that.
func stageRemediationReport(reportBytes []byte) (string, func(), error) {
	tempFile, err := os.CreateTemp("", "kubescape-mcp-remediation-*.json")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp report file: %w", err)
	}
	tempName := tempFile.Name()
	cleanup := func() { os.Remove(tempName) }
	if _, err := tempFile.Write(reportBytes); err != nil {
		tempFile.Close()
		cleanup()
		return "", nil, fmt.Errorf("failed to write temp report file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to close temp report file: %w", err)
	}
	return tempName, cleanup, nil
}

// runRemediation is the shared core of both modes: it plans fixes from a report
// with the fixhandler and shapes the result. It writes nothing but the staged
// copy of the report.
func runRemediation(ctx context.Context, reportBytes []byte, req remediationRequest) ([]byte, error) {
	tempName, cleanup, err := stageRemediationReport(reportBytes)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Instantiate the fixer in a dry-run configuration.
	fixInfo := &ksmetav1.FixInfo{
		ReportFile: tempName,
		DryRun:     true, // documents intent; ApplyChanges is never called
		NoConfirm:  true,
		// SkipUserValues stays false: fixes whose value is a YOUR_* placeholder
		// are still returned, because the calling agent is exactly the party
		// that can substitute a real value.
		// BasePath is set only for a report that came from the caller; a report
		// generated in-process from the caller's own path is not the untrusted
		// case BasePath guards against.
		BasePath: req.basePath,
	}
	if req.selectControls {
		fixInfo.IncludeControls = req.controlIDs
	}
	handler, err := fixhandler.NewFixHandler(fixInfo)
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

	// Plan the fixes. This writes nothing.
	resourcesToFix := handler.PrepareResourcesToFix(ctx)

	files := make([]remediationFileResult, 0)
	rendered := make([]renderedManifest, 0)
	var warnings []string
	renderFailed := make(map[string]string)

	if handler.IsClusterReport() {
		// A cluster resource has no file; render each fix from the scanned
		// object. One at a time, so a failure is attributed to its resource and
		// does not cost the others.
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
	} else {
		// Group expressions per file and apply them in memory. Mirrors
		// getFileYamlExpressions/reduceYamlExpressions (fixhandler.go:818, :989)
		// without their disk write. Each key is already scoped with
		// select(di==N), so multi-document files compose under one " | " pipeline.
		fileExprs := make(map[string][]string)
		for _, rfi := range resourcesToFix {
			exprs := make([]string, 0, len(rfi.YamlExpressions))
			for expr := range rfi.YamlExpressions {
				exprs = append(exprs, expr)
			}
			sort.Strings(exprs) // map iteration order is random; output must be stable
			fileExprs[rfi.FilePath] = append(fileExprs[rfi.FilePath], exprs...)
		}

		filePaths := make([]string, 0, len(fileExprs))
		for fp := range fileExprs {
			filePaths = append(filePaths, fp)
		}
		sort.Strings(filePaths)

		for _, fp := range filePaths {
			joined := strings.Join(fileExprs[fp], " | ")
			fileAsString, err := fixhandler.GetFileString(fp)
			if err != nil {
				return nil, err
			}
			patched, err := fixhandler.ApplyFixToContent(ctx, fileAsString, joined)
			if err != nil {
				return nil, fmt.Errorf("failed to compute fix for %s: %w", fp, err)
			}
			files = append(files, remediationFileResult{
				FilePath:           fp,
				PatchedYAML:        patched,
				AppliedExpressions: fileExprs[fp],
			})
		}
	}

	// Reconcile what was asked for against what the scan actually covered, so
	// a control dropped by a degraded run surfaces instead of vanishing.
	unfixed := handler.UnfixedControls()
	// The fixer lists unfixed controls in the report's result order, which a
	// scan does not keep stable. Sorting makes the response a function of the
	// report's content alone; unaddressed controls follow in requested order.
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

	resp := remediationResponse{
		Files:                 files,
		FixedControlInstances: handler.FixedControlsCount(),
		Degraded:              degraded,
		UnfixedControls:       unfixed,
		Items:                 buildRemediationItems(handler.ControlOutcomes(), unaddressed, report, renderFailed),
		RenderedManifests:     rendered,
		Report:                summarizeRemediationReport(report, coverage),
		Warnings:              boundWarnings(warnings),
	}
	// Always return the envelope, even with zero files: unfixed_controls
	// then explains why nothing was fixable, which is more useful to an
	// agent than an error.
	return json.MarshalIndent(resp, "", "  ")
}

// parseRemediationReport decodes the report and, separately, its top-level
// scanCoverage, which PostureReport does not model. coverage is nil when the
// report has none.
func parseRemediationReport(reportJSON []byte, decoded *reporthandlingv2.PostureReport) (*reporthandlingv2.PostureReport, *cautils.ScanCoverage, error) {
	report := decoded
	if report == nil {
		report = &reporthandlingv2.PostureReport{}
		if err := json.Unmarshal(reportJSON, report); err != nil {
			return nil, nil, fmt.Errorf("failed to parse posture report: %w", err)
		}
	}
	var envelope struct {
		ScanCoverage *cautils.ScanCoverage `json:"scanCoverage"`
	}
	if err := json.Unmarshal(reportJSON, &envelope); err != nil {
		return nil, nil, fmt.Errorf("failed to parse posture report coverage: %w", err)
	}
	return report, envelope.ScanCoverage, nil
}

func boundWarnings(warnings []string) []string {
	if len(warnings) <= maxRemediationWarnings {
		return warnings
	}
	omitted := len(warnings) - maxRemediationWarnings
	out := append([]string(nil), warnings[:maxRemediationWarnings]...)
	return append(out, fmt.Sprintf("%d further warnings omitted", omitted))
}

func summarizeRemediationReport(report *reporthandlingv2.PostureReport, coverage *cautils.ScanCoverage) *remediationReportSummary {
	summary := &remediationReportSummary{
		Kind:                   remediationReportKind(report),
		NotEvaluatedControlIDs: []string{},
	}
	if coverage == nil {
		return summary
	}
	summary.CoverageAvailable = true
	summary.Degraded = coverage.Degraded
	summary.EvaluatedControls = coverage.EvaluatedControls
	summary.TotalControls = coverage.TotalControls
	summary.FailedGVRPulls = len(coverage.FailedGVRPulls)
	summary.SilentFailedGVRCount = coverage.SilentFailedGVRCount
	summary.UnexaminedKinds = len(coverage.UnexaminedKinds)

	ids := make([]string, 0, len(coverage.NotEvaluatedControls))
	for _, ne := range coverage.NotEvaluatedControls {
		ids = append(ids, ne.ControlID)
	}
	sort.Strings(ids)
	summary.NotEvaluatedControlCount = len(ids)
	if len(ids) > maxNotEvaluatedIDs {
		ids = ids[:maxNotEvaluatedIDs]
	}
	summary.NotEvaluatedControlIDs = ids
	return summary
}

func remediationReportKind(report *reporthandlingv2.PostureReport) string {
	if fixhandler.IsClusterPostureReport(report) {
		return "cluster"
	}
	switch report.Metadata.ScanMetadata.ScanningTarget {
	case reporthandlingv2.Directory:
		return "directory"
	case reporthandlingv2.File:
		return "file"
	case reporthandlingv2.GitLocal, reporthandlingv2.Repo:
		return "git"
	default:
		return "unknown"
	}
}

// classificationRank orders classifications from least to most conservative so
// that a (resource, control) pair recorded twice never reads as better than its
// worst record.
func classificationRank(class string) int {
	switch class {
	case classPatchAvailable:
		return 0
	case classPartialPatch:
		return 1
	case classManual:
		return 2
	default:
		return 3
	}
}

// buildRemediationItems turns the fixer's per-control outcomes, and the
// requested controls the scan never evaluated, into sorted items with the
// report's own evidence attached. The classification comes only from the
// fixer's outcome: the presence of a fixPath in the evidence never decides it.
func buildRemediationItems(outcomes []fixhandler.ControlOutcome, unaddressed []fixhandler.UnfixedControl, report *reporthandlingv2.PostureReport, renderFailed map[string]string) []remediationItem {
	resources := make(map[string]*reporthandling.Resource, len(report.Resources))
	for i := range report.Resources {
		resources[report.Resources[i].GetID()] = &report.Resources[i]
	}
	controls := make(map[string]*resourcesresults.ResourceAssociatedControl)
	for i := range report.Results {
		r := &report.Results[i]
		if r.RawResource != nil {
			resources[r.RawResource.GetID()] = r.RawResource
		}
		for j := range r.AssociatedControls {
			controls[r.ResourceID+"\x00"+normalizeControlID(r.AssociatedControls[j].ControlID)] = &r.AssociatedControls[j]
		}
	}

	byKey := make(map[string]remediationItem, len(outcomes)+len(unaddressed))
	add := func(item remediationItem) {
		key := item.ResourceID + "\x00" + normalizeControlID(item.Control.ID)
		if prev, seen := byKey[key]; seen && classificationRank(prev.Classification) >= classificationRank(item.Classification) {
			return
		}
		byKey[key] = item
	}

	for _, o := range outcomes {
		item := remediationItem{
			ResourceID: o.ResourceID,
			Control:    remediationControlRef{ID: o.ControlID, Name: o.ControlName},
			FilePath:   o.FilePath,
			Reason:     o.Reason,
		}
		if res, ok := resources[o.ResourceID]; ok {
			item.Resource = &remediationResourceRef{Kind: res.GetKind(), Name: res.GetName(), Namespace: res.GetNamespace()}
		}
		switch {
		case o.Fixed:
			item.Classification = classPatchAvailable
			if msg, failed := renderFailed[o.ResourceID]; failed {
				item.Classification = classManual
				item.Reason = "the planned fix could not be rendered: " + msg
			}
		case o.Partial:
			item.Classification = classPartialPatch
		default:
			item.Classification = classManual
		}
		if ac, ok := controls[o.ResourceID+"\x00"+normalizeControlID(o.ControlID)]; ok {
			item.Evidence, item.EvidenceTruncated = remediationEvidence(ac)
		}
		if item.Evidence == nil {
			item.Evidence = []remediationEvidenceRule{}
		}
		add(item)
	}

	for _, u := range unaddressed {
		add(remediationItem{
			Control:        remediationControlRef{ID: u.ControlID, Name: u.ControlName},
			Evidence:       []remediationEvidenceRule{},
			Classification: classNotEvaluated,
			Reason:         u.Reason,
		})
	}

	items := make([]remediationItem, 0, len(byKey))
	for _, item := range byKey {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].ResourceID != items[j].ResourceID {
			return items[i].ResourceID < items[j].ResourceID
		}
		return normalizeControlID(items[i].Control.ID) < normalizeControlID(items[j].Control.ID)
	})
	return items
}

// remediationEvidence copies the report's own rule results for one control:
// names, statuses and the paths exactly as recorded. It adds and infers
// nothing, and is bounded.
func remediationEvidence(ac *resourcesresults.ResourceAssociatedControl) ([]remediationEvidenceRule, bool) {
	rules := make([]remediationEvidenceRule, 0, len(ac.ResourceAssociatedRules))
	truncated := false
	for _, rule := range ac.ResourceAssociatedRules {
		if len(rules) >= maxItemEvidenceRules {
			truncated = true
			break
		}
		ev := remediationEvidenceRule{
			Rule:      rule.Name,
			Status:    string(rule.Status),
			SubStatus: string(rule.SubStatus),
			Paths:     []remediationEvidencePath{},
		}
		for _, p := range rule.Paths {
			if len(ev.Paths) >= maxItemEvidencePaths {
				ev.PathsTruncated = true
				break
			}
			ev.Paths = append(ev.Paths, remediationEvidencePath{
				FailedPath: p.FailedPath,
				ReviewPath: p.ReviewPath,
				DeletePath: p.DeletePath,
				FixPath:    p.FixPath.Path,
				FixValue:   p.FixPath.Value,
			})
		}
		rules = append(rules, ev)
	}
	return rules, truncated
}
