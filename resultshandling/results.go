package resultshandling

import (
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/resultshandling/printer"
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

	resultsHandler.reporterObj.ActionSendReport(opaSessionObj)

	// TODO - get score from table
	return CalculatePostureScore(opaSessionObj.PostureReport)
}

// CalculatePostureScore calculate final score
func CalculatePostureScore(postureReport *reporthandling.PostureReport) float32 {
	totalResources := 0
	totalFailed := 0
	for _, frameworkReport := range postureReport.FrameworkReports {
		totalFailed += frameworkReport.GetNumberOfFailedResources()
		totalResources += frameworkReport.GetNumberOfResources()
	}
	if totalResources == 0 {
		return float32(0)
	}
	return (float32(totalResources) - float32(totalFailed)) / float32(totalResources)
}
