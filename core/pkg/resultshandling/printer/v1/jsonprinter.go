package printer

import (
	"encoding/json"
	"fmt"
	"os"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
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
	report := cautils.ReportV2ToV1(opaSessionObj)

	var postureReportStr []byte
	var err error

	if len(report.FrameworkReports) == 1 {
		postureReportStr, err = json.Marshal(report.FrameworkReports[0])
	} else {
		postureReportStr, err = json.Marshal(report.FrameworkReports)
	}

	if err != nil {
		logger.L().Fatal("failed to convert posture report object")
	}
	jsonPrinter.writer.Write(postureReportStr)
}
