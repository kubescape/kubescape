package printer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
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
	PrintNextSteps()
	ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData)
	SetWriter(ctx context.Context, outputFile string)
	Score(score float32)
}

func GetWriter(ctx context.Context, outputFile string) *os.File {
	if outputFile != "" {
		if err := os.MkdirAll(filepath.Dir(outputFile), os.ModePerm); err != nil {
			logger.L().Ctx(ctx).Warning(fmt.Sprintf("failed to create directory, reason: %s", err.Error()))
			return os.Stdout
		}
		f, err := os.Create(outputFile)
		if err != nil {
			logger.L().Ctx(ctx).Warning(fmt.Sprintf("failed to open file for writing, reason: %s", err.Error()))
			return os.Stdout
		}
		return f
	}
	return os.Stdout

}

func LogOutputFile(fileName string) {
	if fileName != os.Stdout.Name() && fileName != os.Stderr.Name() && fileName != os.DevNull {
		logger.L().Success("Scan results saved", helpers.String("filename", fileName))
	}
}
