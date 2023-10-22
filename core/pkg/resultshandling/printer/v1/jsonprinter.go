package printer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
)

const (
	jsonOutputFile = "report"
	jsonOutputExt  = ".json"
)

var _ printer.IPrinter = &JsonPrinter{}

type JsonPrinter struct {
	writer *os.File
}

func NewJsonPrinter() *JsonPrinter {
	return &JsonPrinter{}
}

func (jsonPrinter *JsonPrinter) SetWriter(ctx context.Context, outputFile string) {
	if outputFile != "" {
		if strings.TrimSpace(outputFile) == "" {
			outputFile = jsonOutputFile
		}
		if filepath.Ext(strings.TrimSpace(outputFile)) != jsonOutputExt {
			outputFile = outputFile + jsonOutputExt
		}
	}
	jsonPrinter.writer = printer.GetWriter(ctx, outputFile)
}

func (jsonPrinter *JsonPrinter) Score(score float32) {
	fmt.Fprintf(os.Stderr, "\nOverall compliance-score (100- Excellent, 0- All failed): %d\n", cautils.Float32ToInt(score))
}

func (jsonPrinter *JsonPrinter) PrintNextSteps() {

}

func (jsonPrinter *JsonPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, _ []cautils.ImageScanData) {
	report := cautils.ReportV2ToV1(opaSessionObj)

	var postureReportStr []byte
	var err error

	if len(report.FrameworkReports) == 1 {
		postureReportStr, err = json.Marshal(report.FrameworkReports[0])
	} else {
		postureReportStr, err = json.Marshal(report.FrameworkReports)
	}

	if err != nil {
		logger.L().Ctx(ctx).Fatal("failed to convert posture report object")
	}

	_, err = jsonPrinter.writer.Write(postureReportStr)

	if err != nil {
		logger.L().Ctx(ctx).Fatal("failed to Write posture report object into JSON output")
	} else {
		printer.LogOutputFile(jsonPrinter.writer.Name())
	}
}
