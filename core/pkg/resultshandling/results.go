package resultshandling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	printerv1 "github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v1"
	printerv2 "github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/reporter"
	"github.com/kubescape/kubescape/v3/core/pkg/vapreconcile"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

type ResultsHandler struct {
	ReporterObj   reporter.IReport
	UiPrinter     printer.IPrinter
	ScanData      *cautils.OPASessionObj
	PrinterObjs   []printer.IPrinter
	ImageScanData []cautils.ImageScanData
	scanError     error
}

func NewResultsHandler(reporterObj reporter.IReport, printerObjs []printer.IPrinter, uiPrinter printer.IPrinter) *ResultsHandler {
	return &ResultsHandler{
		ReporterObj:   reporterObj,
		PrinterObjs:   printerObjs,
		UiPrinter:     uiPrinter,
		ImageScanData: make([]cautils.ImageScanData, 0),
	}
}

// GetRiskScore returns the result’s risk score
func (rh *ResultsHandler) GetRiskScore() float32 {
	return rh.ScanData.Report.SummaryDetails.Score
}

// GetComplianceScore returns the result’s compliance score
func (rh *ResultsHandler) GetComplianceScore() float32 {
	return rh.ScanData.Report.SummaryDetails.ComplianceScore
}

// GetData returns scan/action related data (policies, resources, results, etc.)
//
// Call the ToJson() method if you want the JSON representation of the data
func (rh *ResultsHandler) GetData() *cautils.OPASessionObj {
	return rh.ScanData
}

// SetData sets the scan/action related data
func (rh *ResultsHandler) SetData(data *cautils.OPASessionObj) {
	rh.ScanData = data
}

// SetScanError records a scan error that must be returned after any partial
// results have been printed. This lets callers preserve useful scan output
// without reporting a successful exit status for incomplete results.
func (rh *ResultsHandler) SetScanError(err error) {
	rh.scanError = err
}

// GetPrinters returns all printers
func (rh *ResultsHandler) GetPrinters() []printer.IPrinter {
	return rh.PrinterObjs
}

// GetReporter returns the reporter object
func (rh *ResultsHandler) GetReporter() reporter.IReport {
	return rh.ReporterObj
}

// ToJson returns the results in the JSON format
func (rh *ResultsHandler) ToJson() ([]byte, error) {
	finalizedReport := printerv2.FinalizeResults(rh.ScanData)
	enrichedReport := printerv2.ConvertToPostureReportWithSeverityLabelsAndCoverage(
		finalizedReport,
		rh.ScanData.LabelsToCopy,
		rh.ScanData.AllResources,
		&rh.ScanData.ScanCoverage,
	)

	// Keep the established programmatic JSON contract and override only the two
	// control collections for which the output printers derive severity.
	// Marshaling PostureReportWithSeverity directly would omit legacy top-level
	// fields, rawResource, and nanoseconds from generationTime.
	type summaryWithEnrichment struct {
		reportsummary.SummaryDetails
		Controls map[string]printerv2.ControlSummaryWithSeverity `json:"controls,omitempty"`
	}
	type resultWithEnrichment struct {
		resourcesresults.Result
		AssociatedControls []printerv2.ResourceAssociatedControlWithSeverity `json:"controls,omitempty"`
	}

	results := make([]resultWithEnrichment, len(finalizedReport.Results))
	for i := range finalizedReport.Results {
		results[i] = resultWithEnrichment{
			Result:             finalizedReport.Results[i],
			AssociatedControls: enrichedReport.Results[i].AssociatedControls,
		}
	}

	output := struct {
		*reporthandlingv2.PostureReport
		SummaryDetails summaryWithEnrichment        `json:"summaryDetails,omitempty"`
		Results        []resultWithEnrichment       `json:"results,omitempty"`
		ResourceLabels map[string]map[string]string `json:"resourceLabels,omitempty"`
		ScanCoverage   *cautils.ScanCoverage        `json:"scanCoverage,omitempty"`
	}{
		PostureReport: finalizedReport,
		SummaryDetails: summaryWithEnrichment{
			SummaryDetails: finalizedReport.SummaryDetails,
			Controls:       enrichedReport.SummaryDetails.Controls,
		},
		Results:        results,
		ResourceLabels: enrichedReport.ResourceLabels,
		ScanCoverage:   enrichedReport.ScanCoverage,
	}

	return json.Marshal(&output)
}

// GetResults returns the results
func (rh *ResultsHandler) GetResults() *reporthandlingv2.PostureReport {
	return printerv2.FinalizeResults(rh.ScanData)
}

// HandleResults handles all necessary actions for the scan results
func (rh *ResultsHandler) HandleResults(ctx context.Context, scanInfo *cautils.ScanInfo) error {
	if rh.ScanData != nil && len(rh.ScanData.VAPPolicies) > 0 {
		index := vapreconcile.BuildIndex(rh.ScanData.VAPPolicies, rh.ScanData.VAPBindings)
		vapreconcile.EnrichSummary(rh.ScanData.Report.SummaryDetails.Controls, index)
	}

	// Display scan results in the UI first to give immediate value.

	var printErr error

	if err := rh.UiPrinter.ActionPrint(ctx, rh.ScanData, rh.ImageScanData); err != nil {
		printErr = errors.Join(printErr, fmt.Errorf("ui printer: %w", err))
	}

	rh.UiPrinter.PrintNextSteps()
	if err := closePrinter(rh.UiPrinter); err != nil {
		printErr = errors.Join(printErr, fmt.Errorf("ui printer close: %w", err))
	}

	// Then print to output files
	for _, p := range rh.PrinterObjs {
		if err := p.ActionPrint(ctx, rh.ScanData, rh.ImageScanData); err != nil {
			printErr = errors.Join(printErr, fmt.Errorf("output printer %T: %w", p, err))
		}
		if rh.ScanData != nil {
			p.Score(rh.GetComplianceScore())
		}
		if err := closePrinter(p); err != nil {
			printErr = errors.Join(printErr, fmt.Errorf("output printer %T close: %w", p, err))
		}
	}

	if err := errors.Join(printErr, rh.scanError); err != nil {
		return err
	}

	// We should submit only after printing results, so a user can see
	// results at all times, even if submission fails
	if rh.ReporterObj != nil && scanInfo.Submit.GetBool() {
		if err := rh.ReporterObj.Submit(ctx, rh.ScanData); err != nil {
			return err
		}
		rh.ReporterObj.DisplayMessage()
	}

	return nil
}

// NewPrinter returns a new printer for a given format and configuration options
func NewPrinter(ctx context.Context, printFormat string, scanInfo *cautils.ScanInfo, clusterName string) printer.IPrinter {

	switch printFormat {
	case printer.JsonFormat:
		switch scanInfo.FormatVersion {
		case "v1":
			logger.L().Ctx(ctx).Warning("Deprecated format version", helpers.String("run", "--format-version=v2"))
			return printerv1.NewJsonPrinter()
		default:
			return printerv2.NewJsonPrinter(scanInfo.MinSeverity)
		}
	case printer.YamlFormat:
		if scanInfo.FormatVersion == "v1" {
			logger.L().Ctx(ctx).Warning("Deprecated format version", helpers.String("run", "--format-version=v2"))
		}
		return printerv2.NewYamlPrinter()
	case printer.CsvFormat:
		return printerv2.NewCsvPrinter()
	case printer.MarkdownFormat:
		return printerv2.NewMarkdownPrinter()
	case printer.JunitResultFormat:
		return printerv2.NewJunitPrinter(scanInfo.VerboseMode)
	case printer.PrometheusFormat:
		return printerv2.NewPrometheusPrinter(scanInfo.VerboseMode)
	case printer.PdfFormat:
		return printerv2.NewPdfPrinter()
	case printer.HtmlFormat:
		return printerv2.NewHtmlPrinter()
	case printer.SARIFFormat:
		return printerv2.NewSARIFPrinter()
	case printer.GitLabSASTFormat:
		return printerv2.NewGitLabSASTPrinter()
	case printer.CycloneDXFormat:
		return printerv2.NewCycloneDXPrinter()
	case printer.SPDXFormat:
		return printerv2.NewSPDXPrinter()
	case printer.PolicyReportFormat:
		return printerv2.NewPolicyReportPrinter()
	default:
		if printFormat != printer.PrettyFormat {
			logger.L().Ctx(ctx).Warning(fmt.Sprintf("Invalid format \"%s\", default format \"pretty-printer\" is applied", printFormat))
		}
		return printerv2.NewPrettyPrinter(scanInfo.VerboseMode, scanInfo.FormatVersion, scanInfo.PrintAttackTree, cautils.ViewTypes(scanInfo.View), scanInfo.ScanType, scanInfo.InputPatterns, clusterName)
	}
}

func ValidatePrinter(scanType cautils.ScanTypes, scanContext cautils.ScanningContext, printFormat string) (bool, error) {
	if scanType == cautils.ScanTypeImage {
		if printFormat == printer.PrettyFormat {
			return true, nil
		}
		if slices.Contains(printer.ImageFormats, printFormat) {
			return false, nil
		}
		return false, fmt.Errorf("format \"%s\" is not supported for image scanning", printFormat)
	}
	if printFormat == printer.SARIFFormat || printFormat == printer.GitLabSASTFormat {
		// SARIF and GitLab SAST resolve file locations, so they only apply to local files
		switch scanContext {
		case cautils.ContextDir, cautils.ContextFile, cautils.ContextGitLocal, cautils.ContextGitRemote:
			return false, nil
		default:
			return false, fmt.Errorf("format \"%s\" is only supported when scanning local files", printFormat)
		}
	}
	if printFormat == printer.CycloneDXFormat || printFormat == printer.SPDXFormat {
		return false, fmt.Errorf("format \"%s\" is only supported for image scanning", printFormat)
	}

	switch printFormat {
	case printer.JsonFormat, printer.HtmlFormat, printer.JunitResultFormat, printer.PrometheusFormat, printer.PdfFormat, printer.YamlFormat, printer.CsvFormat, printer.MarkdownFormat, printer.PolicyReportFormat:
		return false, nil
	default:
		return true, nil
	}
}

// closePrinter closes p's output writer if p implements an optional close
// contract, returning any error so callers can surface incomplete writes.
// Printers migrated to return an error from CloseWriter are preferred; the
// legacy void contract is still supported for backwards compatibility.
func closePrinter(p printer.IPrinter) error {
	type errorCloser interface {
		CloseWriter() error
	}
	if c, ok := p.(errorCloser); ok {
		return c.CloseWriter()
	}
	type voidCloser interface {
		CloseWriter()
	}
	if c, ok := p.(voidCloser); ok {
		c.CloseWriter()
	}
	return nil
}
