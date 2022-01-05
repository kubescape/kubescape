package printer

import (
	"fmt"
	"os"

	"github.com/armosec/kubescape/cautils"
)

var INDENT = "   "

const (
	PrettyFormat      string = "pretty-printer"
	JsonFormat        string = "json"
	JunitResultFormat string = "junit"
	PrometheusFormat  string = "prometheus"
)

type IPrinter interface {
	ActionPrint(opaSessionObj *cautils.OPASessionObj)
	SetWriter(outputFile string)
	Score(score float32)

	// FinalizeData convert 'opaSessionObj' data to be ready for printing/reporting
	FinalizeData(opaSessionObj *cautils.OPASessionObj)
}

func GetWriter(outputFile string) *os.File {
	os.Remove(outputFile)
	if outputFile != "" {
		f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("failed to open file for writing, reason: ", err.Error())
			return os.Stdout
		}
		return f
	}
	return os.Stdout

}
