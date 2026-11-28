package printer

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/csvsafe"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	reporthandling "github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

const (
	csvOutputFile = "report"
)

var csvImageHeader = []string{
	"Image",
	"Platform",
	"Severity",
	"Vulnerability",
	"Package",
	"Version",
	"Fix State",
	"Fixed In",
	"KEV",
	"EPSS Score",
	"EPSS Percentile",
	"VEX Status",
	"VEX Justification",
}

var _ printer.IPrinter = &CsvPrinter{}

type controlStatusReason struct {
	controlID string
	status    string
	reason    string
}

type CsvPrinter struct {
	writer *os.File
	// showSecrets controls whether sensitive field values (Secret.data,
	// container env[].value, and other secret-shaped fields -- see
	// isSensitivePath) are redacted in the fix-path column below, matching
	// the terminal pretty-printer's default.
	showSecrets bool
}

func NewCsvPrinter(showSecrets bool) *CsvPrinter {
	return &CsvPrinter{showSecrets: showSecrets}
}

// csvSafeCell neutralizes a cell against spreadsheet formula injection (CWE-1236)
// by delegating to csvsafe.SafeCell.
func csvSafeCell(cell string) string {
	return csvsafe.SafeCell(cell)
}

// csvSafeRow applies csvSafeCell to every cell of a data row.
func csvSafeRow(row []string) []string {
	return csvsafe.SafeRow(row)
}

func (cp *CsvPrinter) SetWriter(ctx context.Context, outputFile string) error {
	if cp == nil {
		return fmt.Errorf("failed to set writer: printer is nil")
	}
	outputFile, explicitOutput := printer.ResolveOutputFile(printer.CsvFormat, outputFile, csvOutputFile)
	if explicitOutput {
		var err error
		cp.writer, err = printer.GetPrinterWriterNoFallback(outputFile)
		return err
	}
	cp.writer = printer.GetWriter(ctx, outputFile)
	return nil
}

func (cp *CsvPrinter) Score(score float32) {
	if cp == nil {
		return
	}
	if score > 100 {
		score = 100
	} else if score < 0 {
		score = 0
	}

	fmt.Fprintf(os.Stderr, "\nOverall compliance-score (100- Excellent, 0- All failed): %d\n", cautils.ComplianceScoreToInt(score))
}

// ActionPrint outputs scan results in CSV format, including resource-level
// control evaluations, skipped resource findings with diagnostic reasons, and
// cluster-wide skipped or unevaluated controls. A missing session or posture
// report returns an error instead of reading a nil report.
func (cp *CsvPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) (err error) {
	if cp == nil {
		return fmt.Errorf("failed to write csv results: printer is nil")
	}
	if err := printer.PrepareOutput(cp.writer); err != nil {
		return err
	}
	hasReport := opaSessionObj != nil && opaSessionObj.Report != nil
	if !hasReport && len(imageScanData) == 0 {
		return fmt.Errorf("no data provided for CSV output")
	}
	if cp.writer == nil {
		return fmt.Errorf("failed to write CSV results: output writer is nil")
	}
	if !hasReport && len(imageScanData) > 0 {
		if err := writeImageScanCSV(cp.writer, imageScanData); err != nil {
			return err
		}
		printer.LogOutputFile(cp.writer.Name())
		return nil
	}

	finalizedReport := FinalizeResults(opaSessionObj)
	if finalizedReport == nil {
		return fmt.Errorf("no data provided for CSV output")
	}
	reportWithSeverity := ConvertToPostureReportWithSeverityLabelsAndCoverageFromCatalog(finalizedReport, opaSessionObj.LabelsToCopy, opaSessionObj.GetCatalog(), &opaSessionObj.ScanCoverage)

	summaryControls := finalizedReport.SummaryDetails.Controls

	csvWriter := csv.NewWriter(cp.writer)
	defer func() {
		csvWriter.Flush()
		if flushErr := csvWriter.Error(); flushErr != nil {
			logger.L().Ctx(ctx).Error("failed to flush CSV writer", helpers.Error(flushErr))
			if err == nil {
				err = fmt.Errorf("failed to flush CSV writer: %w", flushErr)
			}
		}
		if err == nil {
			printer.LogOutputFile(cp.writer.Name())
		}
	}()

	header := []string{
		"Control Name",
		"Control ID",
		"Severity",
		"Status",
		"Resource Name",
		"Resource Kind",
		"Resource Namespace",
		"API Version",
		"Failed Paths",
		"Fix Paths",
		"Remediation",
		"Control URL",
		"Source Path",
	}
	if err := csvWriter.Write(header); err != nil {
		logger.L().Ctx(ctx).Error("failed to write CSV header", helpers.Error(err))
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	skippedControls := collectSkippedControls(opaSessionObj)
	skippedReasonByControl := make(map[string]string, len(skippedControls))
	for _, sc := range skippedControls {
		if sc.reason != "" {
			skippedReasonByControl[sc.controlID] = sc.reason
		}
	}

	emittedSkipReasons := make(map[controlStatusReason]struct{})
	for _, result := range reportWithSeverity.Results {
		resID := result.ResourceID
		var resName, resKind, resNamespace, resApiVersion string

		if resourceData, ok := opaSessionObj.GetResource(resID); ok && resourceData != nil {
			resName = resourceData.GetName()
			resKind = resourceData.GetKind()
			resNamespace = resourceData.GetNamespace()
			resApiVersion = resourceData.GetApiVersion()
		}

		sourcePath := ""
		if opaSessionObj != nil && opaSessionObj.ResourceSource != nil {
			src := reportedSource(opaSessionObj, resID)
			sourcePath = csvSourcePath(src)
		}

		resourceResult, hasResult := opaSessionObj.ResourcesResult[resID]

		for _, assocCtrl := range result.AssociatedControls {
			ctrlID := assocCtrl.GetID()
			ctrlName := assocCtrl.GetName()

			severity := assocCtrl.Severity
			if severity == "" {
				severity = "Unknown"
			}

			ctrlStatus := cautils.ControlStatus(&opaSessionObj.Report.SummaryDetails, &assocCtrl.ResourceAssociatedControl)
			status := string(ctrlStatus.Status())
			if status == "" {
				status = "unknown"
			}

			failedPaths := ""
			fixPaths := ""
			if hasResult {
				failedPaths, fixPaths = csvControlPaths(&opaSessionObj.Report.SummaryDetails, resourceResult, ctrlID, resKind, cp.showSecrets)
			}

			remediation := ""
			if ctrlStatus.IsSkipped() {
				if msg := buildSkipMessage(ctrlStatus); msg != "" {
					remediation = msg
				} else if reason, ok := skippedReasonByControl[ctrlID]; ok && reason != "" {
					remediation = reason
				} else {
					remediation = "reason unavailable"
				}
				emittedSkipReasons[controlStatusReason{
					controlID: ctrlID,
					status:    status,
					reason:    remediation,
				}] = struct{}{}
			} else {
				if summaryControls != nil {
					if ctrl := summaryControls.GetControl(reportsummary.EControlCriteriaID, ctrlID); ctrl != nil {
						remediation = ctrl.GetRemediation()
					}
				}
			}

			row := []string{
				ctrlName,
				ctrlID,
				severity,
				status,
				resName,
				resKind,
				resNamespace,
				resApiVersion,
				failedPaths,
				fixPaths,
				remediation,
				cautils.GetControlLink(ctrlID),
				sourcePath,
			}
			if err := csvWriter.Write(csvSafeRow(row)); err != nil {
				logger.L().Ctx(ctx).Error("failed to write CSV row", helpers.Error(err))
				return fmt.Errorf("failed to write CSV row: %w", err)
			}
		}
	}

	for _, sc := range skippedControls {
		name := sc.name
		if name == "" || name == sc.controlID {
			if summaryControls != nil {
				if ctrl := summaryControls.GetControl(reportsummary.EControlCriteriaID, sc.controlID); ctrl != nil && ctrl.GetName() != "" {
					name = ctrl.GetName()
				}
			}
		}
		if name == "" {
			name = sc.controlID
		}
		severity := apis.ControlSeverityToString(sc.scoreFactor)
		if severity == "" || severity == "Unknown" {
			if summaryControls != nil {
				if ctrl := summaryControls.GetControl(reportsummary.EControlCriteriaID, sc.controlID); ctrl != nil && ctrl.GetScoreFactor() > 0 {
					severity = apis.ControlSeverityToString(ctrl.GetScoreFactor())
				}
			}
		}
		if severity == "" {
			severity = "Unknown"
		}
		reason := sc.reason
		if reason == "" {
			reason = "reason unavailable"
		}
		status := sc.status
		if status == "" {
			status = string(apis.StatusSkipped)
		}
		key := controlStatusReason{
			controlID: sc.controlID,
			status:    status,
			reason:    reason,
		}
		if _, alreadyEmitted := emittedSkipReasons[key]; alreadyEmitted {
			continue
		}
		emittedSkipReasons[key] = struct{}{}
		row := []string{
			name,
			sc.controlID,
			severity,
			status,
			"N/A",
			"N/A",
			"N/A",
			"N/A",
			"",
			"",
			reason,
			cautils.GetControlLink(sc.controlID),
			"",
		}
		if err := csvWriter.Write(csvSafeRow(row)); err != nil {
			logger.L().Ctx(ctx).Error("failed to write CSV row for skipped control", helpers.Error(err))
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	return cp.writeImageScanCompanion(ctx, imageScanData)
}

func (cp *CsvPrinter) writeImageScanCompanion(ctx context.Context, imageScanData []cautils.ImageScanData) error {
	if len(imageScanData) == 0 {
		return nil
	}
	if cp.writer == nil || cp.writer.Name() == os.DevNull {
		return nil
	}
	postureInfo, err := cp.writer.Stat()
	if cp.writer == os.Stdout || err != nil || !postureInfo.Mode().IsRegular() {
		logger.L().Ctx(ctx).Warning("CSV image vulnerabilities are written next to the posture report, set --output to a file to save them")
		return nil
	}
	companionPath := printer.CsvImageCompanionPath(cp.writer.Name())
	if companionInfo, err := os.Stat(companionPath); err == nil && os.SameFile(postureInfo, companionInfo) {
		return fmt.Errorf("CSV vulnerabilities file %q is the same file as the posture report %q (hard link or symlink); remove it or choose a different --output", companionPath, cp.writer.Name())
	}
	f, err := printer.GetWriterNoFallback(companionPath)
	if err != nil {
		return err
	}
	if err := writeImageScanCSV(f, imageScanData); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close CSV vulnerabilities file: %w", err)
	}
	printer.LogOutputFile(f.Name())
	return nil
}

func writeImageScanCSV(w io.Writer, imageScanData []cautils.ImageScanData) error {
	csvWriter := csv.NewWriter(w)
	if err := csvWriter.Write(csvImageHeader); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}
	for i := range imageScanData {
		cves := extractCVEs(imageScanData[i].Matches, imageScanData[i].Image, imageScanData[i].VexStatuses)
		imageprinter.SortCVEs(cves)
		for _, cve := range cves {
			if err := csvWriter.Write(csvSafeRow(csvImageRow(cve, imageScanData[i].Platform))); err != nil {
				return fmt.Errorf("failed to write CSV row: %w", err)
			}
		}
	}
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return fmt.Errorf("failed to flush CSV writer: %w", err)
	}
	return nil
}

func csvImageRow(cve imageprinter.CVE, platform string) []string {
	severity := cve.Severity
	if severity == "" {
		severity = "Unknown"
	}
	var kev, epssScore, epssPercentile string
	if cve.KEVKnown {
		kev = strconv.FormatBool(cve.KEV)
	}
	if cve.EPSS != nil {
		epssScore = strconv.FormatFloat(cve.EPSS.Score, 'f', -1, 64)
		epssPercentile = strconv.FormatFloat(cve.EPSS.Percentile, 'f', -1, 64)
	}
	return []string{
		cve.Image,
		platform,
		severity,
		cve.ID,
		cve.Package,
		cve.Version,
		cve.FixedState,
		strings.Join(cve.FixVersions, "; "),
		kev,
		epssScore,
		epssPercentile,
		cve.VexStatus,
		cve.VexJustification,
	}
}

func (cp *CsvPrinter) PrintNextSteps() {
}

// CloseWriter closes the CSV output writer, returning any error from flushing or closing.
func (cp *CsvPrinter) CloseWriter() error {
	if cp != nil && cp.writer != nil && cp.writer != os.Stdout {
		return printer.CloseOutput(cp.writer)
	}
	return nil
}

// csvControlPaths returns the semicolon-separated failed paths and fix paths
// for the given controlID in result. Both strings are empty when the control
// is not found or has no paths. Failed paths come from DeletePath and
// ReviewPath, which is how appendPaths records a rule's locations, and from
// FailedPath on older results. The same location can be stored under more
// than one of those fields, so each path is emitted once. FixPath.Value is
// redacted to [redacted] for sensitive paths (Secret.data, container
// env[].value, and other secret-shaped fields -- see isSensitivePath) unless
// showSecrets is true, matching the terminal pretty-printer's default.
// kind == "" (the caller's AllResources lookup missed, so the resource's real
// kind is unknown) is treated as sensitive too: isSensitivePath's
// Secret.data/stringData check requires kind == "Secret" to fire, so an
// unresolved kind would otherwise silently skip that check and only catch a
// value that also happens to match a known credential-shaped field name --
// failing closed here instead means an unresolvable resource never leaks its
// fix value by accident.
func csvControlPaths(summary *reportsummary.SummaryDetails, result resourcesresults.Result, controlID, kind string, showSecrets bool) (failedPaths, fixPaths string) {
	for i := range result.AssociatedControls {
		if result.AssociatedControls[i].GetID() != controlID {
			continue
		}
		var failed, fix []string
		seenFailed := make(map[string]struct{})
		// Only the rules that still fail are actionable; an excepted rule's
		// paths stay in the report's own rules for audit.
		displayed := cautils.EvidenceControl(summary, result.AssociatedControls[i])
		for j := range displayed.ResourceAssociatedRules {
			for k := range displayed.ResourceAssociatedRules[j].Paths {
				p := displayed.ResourceAssociatedRules[j].Paths[k]
				failed = appendCSVFailedPath(failed, seenFailed, p.DeletePath)
				failed = appendCSVFailedPath(failed, seenFailed, p.ReviewPath)
				failed = appendCSVFailedPath(failed, seenFailed, p.FailedPath)
				if p.FixPath.Path != "" {
					v := p.FixPath.Value
					if !showSecrets && (kind == "" || isSensitivePath(kind, p.FixPath.Path)) {
						v = redactedValue
					}
					if v != "" {
						fix = append(fix, p.FixPath.Path+"="+v)
					} else {
						fix = append(fix, p.FixPath.Path)
					}
				}
			}
		}
		return strings.Join(failed, "; "), strings.Join(fix, "; ")
	}
	return "", ""
}

// appendCSVFailedPath appends path to failed when path is non-empty and not
// already recorded in seen. seen is updated so a later DeletePath, ReviewPath,
// or FailedPath with the same text is emitted once. The returned slice is the
// failed paths collected so far.
func appendCSVFailedPath(failed []string, seen map[string]struct{}, path string) []string {
	if path == "" {
		return failed
	}
	if _, ok := seen[path]; ok {
		return failed
	}
	seen[path] = struct{}{}
	return append(failed, path)
}

// csvSourcePath returns the best available source path from a Source entry.
// RelativePath is preferred because it is repo-relative and more portable.
func csvSourcePath(src reporthandling.Source) string {
	return BestSourcePath(src)
}
