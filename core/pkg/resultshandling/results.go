package resultshandling

import (
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
	printerObjs []printer.IPrinter
	scanData    *cautils.OPASessionObj
}

func NewResultsHandler(reporterObj reporter.IReport, printerObjs []printer.IPrinter) *ResultsHandler {
	return &ResultsHandler{
		reporterObj: reporterObj,
		printerObjs: printerObjs,
	}
}

// GetScore return scan risk-score
func (rh *ResultsHandler) GetRiskScore() float32 {
	return rh.scanData.Report.SummaryDetails.Score
}

// GetData get scan/action related data (policies, resources, results, etc.). Call ToJson function if you wish the json representation of the data
func (rh *ResultsHandler) GetData() *cautils.OPASessionObj {
	return rh.scanData
}

// SetData set scan/action related data
func (rh *ResultsHandler) SetData(data *cautils.OPASessionObj) {
	rh.scanData = data
}

// GetPrinter get printer object
func (rh *ResultsHandler) GetPrinters() []printer.IPrinter {
	return rh.printerObjs
}

// GetReporter get reporter object
func (rh *ResultsHandler) GetReporter() reporter.IReport {
	return rh.reporterObj
}

// ToJson return results in json format
func (rh *ResultsHandler) ToJson() ([]byte, error) {
	return json.Marshal(printerv2.FinalizeResults(rh.scanData))
}

// GetResults return results
func (rh *ResultsHandler) GetResults() *reporthandlingv2.PostureReport {
	return printerv2.FinalizeResults(rh.scanData)
}

// HandleResults handles all necessary actions for the scan results
func (rh *ResultsHandler) HandleResults() error {
	for _, printer := range rh.printerObjs {
		// First we output the results and then the score, so the
		// score—a summary of the results—can always be seen at the end
		// of output
		printer.ActionPrint(rh.scanData)
		printer.Score(rh.GetRiskScore())
	}

	// We should submit only after printing results, so a user can see
	// results at all times, even if submission fails
	if err := rh.reporterObj.Submit(rh.scanData); err != nil {
		return err
	}
	rh.reporterObj.DisplayReportURL()

	return nil
}

// NewPrinter defined output format
func NewPrinter(printFormat, formatVersion string, verboseMode bool, viewType cautils.ViewTypes) printer.IPrinter {

	switch printFormat {
	case printer.JsonFormat:
		switch formatVersion {
		case "v2":
			return printerv2.NewJsonPrinter()
		default:
			logger.L().Warning("Deprecated format version", helpers.String("run", "--format-version=v2"), helpers.String("This will not be supported after", "1/Jan/2023"))
			return printerv1.NewJsonPrinter()
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
			logger.L().Error(fmt.Sprintf("Invalid format \"%s\", default format \"pretty-printer\" is applied", printFormat))
		}
		return printerv2.NewPrettyPrinter(verboseMode, formatVersion, viewType)
	}
}
