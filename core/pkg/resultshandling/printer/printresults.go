package printer

import (
	"fmt"
	"os"
	"path/filepath"

	logger "github.com/kubescape/go-logger"
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
