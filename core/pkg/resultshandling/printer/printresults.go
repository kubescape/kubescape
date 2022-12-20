package printer

import (
	"fmt"
	"os"
	"path/filepath"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils"
)

var INDENT = "   "

const (
	PrettyFormat      string = "pretty-printer"
	JsonFormat        string = "json"
	JunitResultFormat string = "junit"
	PrometheusFormat  string = "prometheus"
	PdfFormat         string = "pdf"
	HtmlFormat        string = "html"
	SARIFFormat       string = "sarif"
)

type IPrinter interface {
	ActionPrint(opaSessionObj *cautils.OPASessionObj)
	SetWriter(outputFile string)
	Score(score float32)
}

func GetWriter(outputFile string) *os.File {
	if outputFile != "" {
		if err := os.MkdirAll(filepath.Dir(outputFile), os.ModePerm); err != nil {
			logger.L().Error(fmt.Sprintf("failed to create directory, reason: %s", err.Error()))
			return os.Stdout
		}
		f, err := os.Create(outputFile)
		if err != nil {
			logger.L().Error(fmt.Sprintf("failed to open file for writing, reason: %s", err.Error()))
			return os.Stdout
		}
		return f
	}
	return os.Stdout

}

func LogOutputFile(fileName string) {
	if fileName != os.Stdout.Name() && fileName != os.Stderr.Name() {
		logger.L().Success("Scan results saved", helpers.String("filename", fileName))
	}
}
