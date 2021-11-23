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
	score := CalculatePostureScore(opaSessionObj.PostureReport)
	resultsHandler.printerObj.Score(score)

	return score
}

// CalculatePostureScore calculate final score
func CalculatePostureScore(postureReport *reporthandling.PostureReport) float32 {
	lowestScore := float32(100)
	for _, frameworkReport := range postureReport.FrameworkReports {
		totalFailed := frameworkReport.GetNumberOfFailedResources()
		totalResources := frameworkReport.GetNumberOfResources()

		frameworkScore := float32(0)
		if float32(totalResources) > 0 {
			frameworkScore = (float32(totalResources) - float32(totalFailed)) / float32(totalResources)
		}
		if lowestScore > frameworkScore {
			lowestScore = frameworkScore
		}
	}

	return lowestScore
}
