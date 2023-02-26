package resultshandling

import (
	"context"
	"encoding/json"
	"fmt"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
	printerv1 "github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v1"
	printerv2 "github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/reporter"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

type ResultsHandler struct {
	reporterObj reporter.IReport
	uiPrinter   printer.IPrinter
	scanData    *cautils.OPASessionObj
	printerObjs []printer.IPrinter
}

func NewResultsHandler(reporterObj reporter.IReport, printerObjs []printer.IPrinter, uiPrinter printer.IPrinter) *ResultsHandler {
	return &ResultsHandler{
		reporterObj: reporterObj,
		printerObjs: printerObjs,
		uiPrinter:   uiPrinter,
	}
}

// GetScore returns the result’s risk score
func (rh *ResultsHandler) GetRiskScore() float32 {
	return rh.scanData.Report.SummaryDetails.Score
}

// GetData returns scan/action related data (policies, resources, results, etc.)
//
// Call the ToJson() method if you want the JSON representation of the data
func (rh *ResultsHandler) GetData() *cautils.OPASessionObj {
	return rh.scanData
}

// SetData sets the scan/action related data
func (rh *ResultsHandler) SetData(data *cautils.OPASessionObj) {
	rh.scanData = data
}

// GetPrinter returns all printers
func (rh *ResultsHandler) GetPrinters() []printer.IPrinter {
	return rh.printerObjs
}

// GetReporter returns the reporter object
func (rh *ResultsHandler) GetReporter() reporter.IReport {
	return rh.reporterObj
}

// ToJson returns the results in the JSON format
func (rh *ResultsHandler) ToJson() ([]byte, error) {
	return json.Marshal(printerv2.FinalizeResults(rh.scanData))
}

// GetResults returns the results
func (rh *ResultsHandler) GetResults() *reporthandlingv2.PostureReport {
	return printerv2.FinalizeResults(rh.scanData)
}

// HandleResults handles all necessary actions for the scan results
func (rh *ResultsHandler) HandleResults(ctx context.Context) error {
	// Display scan results in the UI first to give immediate value.
	// First we output the results and then the score, so the
	// score - a summary of the results—can always be seen at the end
	// of output
	rh.uiPrinter.ActionPrint(ctx, rh.scanData)
	rh.uiPrinter.Score(rh.GetRiskScore())

	// Then print to output files
	for _, printer := range rh.printerObjs {
		printer.ActionPrint(ctx, rh.scanData)
		printer.Score(rh.GetRiskScore())
	}

	// We should submit only after printing results, so a user can see
	// results at all times, even if submission fails
	if err := rh.reporterObj.Submit(ctx, rh.scanData); err != nil {
		return err
	}
	rh.reporterObj.DisplayReportURL()

	return nil
}

// NewPrinter returns a new printer for a given format and configuration options
func NewPrinter(ctx context.Context, printFormat, formatVersion string, verboseMode, attackTree bool, viewType cautils.ViewTypes) printer.IPrinter {

	switch printFormat {
	case printer.JsonFormat:
		switch formatVersion {
		case "v1":
			logger.L().Ctx(ctx).Warning("Deprecated format version", helpers.String("run", "--format-version=v2"))
			return printerv1.NewJsonPrinter()
		default:
			return printerv2.NewJsonPrinter()
		}
	case printer.JunitResultFormat:
		return printerv2.NewJunitPrinter(verboseMode)
	case printer.PrometheusFormat:
		return printerv2.NewPrometheusPrinter(verboseMode)
	case printer.PdfFormat:
		return printerv2.NewPdfPrinter()
	case printer.HtmlFormat:
		return printerv2.NewHtmlPrinter()
	case printer.SARIFFormat:
		return printerv2.NewSARIFPrinter()
	default:
		if printFormat != printer.PrettyFormat {
			logger.L().Ctx(ctx).Error(fmt.Sprintf("Invalid format \"%s\", default format \"pretty-printer\" is applied", printFormat))
		}
		return printerv2.NewPrettyPrinter(verboseMode, formatVersion, attackTree, viewType)
	}
}
