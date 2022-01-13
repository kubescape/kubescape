package resultshandling

import (
	"fmt"

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

	if err := resultsHandler.reporterObj.ActionSendReport(opaSessionObj); err != nil {
		fmt.Println(err)
	}

	// TODO - get score from table
	var score float32 = 0
	if opaSessionObj.PostureReport != nil {
		for i := range opaSessionObj.PostureReport.FrameworkReports {
			score += opaSessionObj.PostureReport.FrameworkReports[i].Score
		}
		score /= float32(len(opaSessionObj.PostureReport.FrameworkReports))
		resultsHandler.printerObj.Score(score)
	}

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
