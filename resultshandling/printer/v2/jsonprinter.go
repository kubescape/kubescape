package v2

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/logger"
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
	finalizeJson(opaSessionObj)
	r, err := json.Marshal(opaSessionObj.Report)
	if err != nil {
		logger.L().Fatal("failed to Marshal posture report object")
	}
	jsonPrinter.writer.Write(r)
}
