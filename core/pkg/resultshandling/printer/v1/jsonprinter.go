package v1

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/armosec/kubescape/core/cautils"
	"github.com/armosec/kubescape/core/cautils/logger"
	"github.com/armosec/kubescape/core/pkg/resultshandling/printer"
)

type JsonPrinter struct {
	writer *os.File
}

func NewJsonPrinter() *JsonPrinter {
	return &JsonPrinter{}
}

func (jsonPrinter *JsonPrinter) SetWriter(outputFile string) {
	jsonPrinter.writer = printer.GetWriter(outputFile)
}

func (jsonPrinter *JsonPrinter) Score(score float32) {
	fmt.Fprintf(os.Stderr, "\nOverall risk-score (0- Excellent, 100- All failed): %d\n", cautils.Float32ToInt(score))
}

func (jsonPrinter *JsonPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj) {
	cautils.ReportV2ToV1(opaSessionObj)

	var postureReportStr []byte
	var err error

	if len(opaSessionObj.PostureReport.FrameworkReports) == 1 {
		postureReportStr, err = json.Marshal(opaSessionObj.PostureReport.FrameworkReports[0])
	} else {
		postureReportStr, err = json.Marshal(opaSessionObj.PostureReport.FrameworkReports)
	}

	if err != nil {
		logger.L().Fatal("failed to convert posture report object")
	}
	jsonPrinter.writer.Write(postureReportStr)
}
