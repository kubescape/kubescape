package printer

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/armosec/kubescape/cautils"
)

type JsonPrinter struct {
	writer *os.File
}

func NewJsonPrinter() *JsonPrinter {
	return &JsonPrinter{}
}

func (jsonPrinter *JsonPrinter) SetWriter(outputFile string) {
	jsonPrinter.writer = getWriter(outputFile)
}

func (jsonPrinter *JsonPrinter) Score(score float32) {
	fmt.Printf("\nFinal score: %d\n", int(score))
}

func (jsonPrinter *JsonPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj) {
	postureReportStr, err := json.Marshal(opaSessionObj.PostureReport.FrameworkReports[0])
	if err != nil {
		fmt.Println("Failed to convert posture report object!")
		os.Exit(1)
	}
	jsonPrinter.writer.Write(postureReportStr)
}
