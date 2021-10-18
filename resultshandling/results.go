package resultshandling

import (
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/resultshandling/printer"
	"github.com/armosec/kubescape/resultshandling/reporter"
)

type ResultsHandler struct {
	opaSessionObj *chan *cautils.OPASessionObj
	reporterObj   *reporter.ReportEventReceiver
	printerObj    *printer.Printer
}

func NewResultsHandler(opaSessionObj *chan *cautils.OPASessionObj, reporterObj *reporter.ReportEventReceiver, printerObj *printer.Printer) *ResultsHandler {
	return &ResultsHandler{
		opaSessionObj: opaSessionObj,
		reporterObj:   reporterObj,
		printerObj:    printerObj,
	}
}

func (resultsHandler *ResultsHandler) HandleResults(scanInfo cautils.ScanInfo) float32 {

	opaSessionObj := <-*resultsHandler.opaSessionObj

	score := resultsHandler.printerObj.ActionPrint(opaSessionObj)

	// Don't send report for control scan
	if scanInfo.FrameworkScan {
		resultsHandler.reporterObj.ActionSendReportListenner(opaSessionObj)
	}

	return score
}
