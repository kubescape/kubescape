package resultshandling

import (
	"context"
	"encoding/json"
	"fmt"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	printerv1 "github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v1"
	printerv2 "github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/reporter"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

type ResultsHandler struct {
	ReporterObj   reporter.IReport
	UiPrinter     printer.IPrinter
	ScanData      *cautils.OPASessionObj
	PrinterObjs   []printer.IPrinter
	ImageScanData []cautils.ImageScanData
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

// GetPrinter returns all printers
func (rh *ResultsHandler) GetPrinters() []printer.IPrinter {
	return rh.PrinterObjs
}

// GetReporter returns the reporter object
func (rh *ResultsHandler) GetReporter() reporter.IReport {
	return rh.ReporterObj
}

// ToJson returns the results in the JSON format
func (rh *ResultsHandler) ToJson() ([]byte, error) {
	return json.Marshal(printerv2.FinalizeResults(rh.ScanData))
}

// GetResults returns the results
func (rh *ResultsHandler) GetResults() *reporthandlingv2.PostureReport {
	return printerv2.FinalizeResults(rh.ScanData)
}

// HandleResults handles all necessary actions for the scan results
func (rh *ResultsHandler) HandleResults(ctx context.Context) error {
	// Display scan results in the UI first to give immediate value.

	rh.UiPrinter.ActionPrint(ctx, rh.ScanData, rh.ImageScanData)

	rh.UiPrinter.PrintNextSteps()

	// Then print to output files
	for _, printer := range rh.PrinterObjs {
		printer.ActionPrint(ctx, rh.ScanData, rh.ImageScanData)
		if rh.ScanData != nil {
			printer.Score(rh.GetComplianceScore())
		}
	}

	// We should submit only after printing results, so a user can see
	// results at all times, even if submission fails
	if rh.ReporterObj != nil {
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
			return printerv2.NewJsonPrinter()
		}
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
	default:
		if printFormat != printer.PrettyFormat {
			logger.L().Ctx(ctx).Warning(fmt.Sprintf("Invalid format \"%s\", default format \"pretty-printer\" is applied", printFormat))
		}
		return printerv2.NewPrettyPrinter(scanInfo.VerboseMode, scanInfo.FormatVersion, scanInfo.PrintAttackTree, cautils.ViewTypes(scanInfo.View), scanInfo.ScanType, scanInfo.InputPatterns, clusterName)
	}
}

func ValidatePrinter(scanType cautils.ScanTypes, scanContext cautils.ScanningContext, printFormat string) error {
	if scanType == cautils.ScanTypeImage {
		// supported types for image scanning
		switch printFormat {
		case printer.JsonFormat, printer.PrettyFormat, printer.SARIFFormat:
			return nil
		default:
			return fmt.Errorf("format \"%s\"is not supported for image scanning", printFormat)
		}
	}

	if printFormat == printer.SARIFFormat {
		// supported types for SARIF
		switch scanContext {
		case cautils.ContextDir, cautils.ContextFile, cautils.ContextGitLocal:
			return nil
		default:
			return fmt.Errorf("format \"%s\" is only supported when scanning local files", printFormat)
		}
	}

	return nil
}
