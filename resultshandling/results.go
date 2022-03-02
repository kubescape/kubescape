package resultshandling

import (
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/resultshandling/printer"
	printerv1 "github.com/armosec/kubescape/resultshandling/printer/v1"
	printerv2 "github.com/armosec/kubescape/resultshandling/printer/v2"

	"github.com/armosec/kubescape/resultshandling/reporter"
	"github.com/armosec/opa-utils/reporthandling"
)

type ResultsHandler struct {
	opaSessionObj *chan *cautils.OPASessionObj
	reporterObj   reporter.IReport
	printerObj    printer.IPrinter
}

func NewResultsHandler(opaSessionObj *chan *cautils.OPASessionObj, reporterObj reporter.IReport, printerObj printer.IPrinter) *ResultsHandler {
	return &ResultsHandler{
		opaSessionObj: opaSessionObj,
		reporterObj:   reporterObj,
		printerObj:    printerObj,
	}
}

func (resultsHandler *ResultsHandler) HandleResults(scanInfo *cautils.ScanInfo) float32 {

	opaSessionObj := <-*resultsHandler.opaSessionObj

	resultsHandler.printerObj.ActionPrint(opaSessionObj)

	if err := resultsHandler.reporterObj.ActionSendReport(opaSessionObj); err != nil {
		logger.L().Error(err.Error())
	}

	score := opaSessionObj.Report.SummaryDetails.Score
	resultsHandler.printerObj.Score(score)

	return score
}

// CalculatePostureScore calculate final score
func CalculatePostureScore(postureReport *reporthandling.PostureReport) float32 {
	failedResources := []string{}
	allResources := []string{}
	for _, frameworkReport := range postureReport.FrameworkReports {
		failedResources = reporthandling.GetUniqueResourcesIDs(append(failedResources, frameworkReport.ListResourcesIDs().GetFailedResources()...))
		allResources = reporthandling.GetUniqueResourcesIDs(append(allResources, frameworkReport.ListResourcesIDs().GetAllResources()...))
	}

	return (float32(len(allResources)) - float32(len(failedResources))) / float32(len(allResources))
}

func NewPrinter(printFormat, outputVersion string, verboseMode bool) printer.IPrinter {

	switch printFormat {
	case printer.JsonFormat:
		return printerv1.NewJsonPrinter()
	case printer.JunitResultFormat:
		return printerv2.NewJunitPrinter(verboseMode)
	case printer.PrometheusFormat:
		return printerv1.NewPrometheusPrinter(verboseMode)
	case printer.PdfFormat:
		return printerv2.NewPdfPrinter()
	default:
		return printerv2.NewPrettyPrinter(verboseMode, outputVersion)
	}
}
