package v1

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/resultshandling/printer"
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
	fmt.Fprintf(os.Stderr, "\nOverall risk-score (0- Excellent, 100- All failed): %d\n", int(score))
}

func (jsonPrinter *JsonPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj) {
	var postureReportStr []byte
	var err error

	if len(opaSessionObj.PostureReport.FrameworkReports) == 1 {
		postureReportStr, err = json.Marshal(opaSessionObj.PostureReport.FrameworkReports[0])
	} else {
		postureReportStr, err = json.Marshal(opaSessionObj.PostureReport.FrameworkReports)
	}

	if err != nil {
		fmt.Println("Failed to convert posture report object!")
		os.Exit(1)
	}
	jsonPrinter.writer.Write(postureReportStr)
}
func (jsonPrinter *JsonPrinter) FinalizeData(opaSessionObj *cautils.OPASessionObj) {
	reportV2ToV1(opaSessionObj)
}
