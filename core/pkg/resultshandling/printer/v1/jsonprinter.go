package printer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
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

func (jsonPrinter *JsonPrinter) SetWriter(ctx context.Context, outputFile string) error {
	explicitOutput := outputFile != ""
	if outputFile != "" {
		if strings.TrimSpace(outputFile) == "" {
			outputFile = jsonOutputFile
		}
		if filepath.Ext(strings.TrimSpace(outputFile)) != jsonOutputExt {
			outputFile = outputFile + jsonOutputExt
		}
	}
	if explicitOutput {
		var err error
		jsonPrinter.writer, err = printer.GetWriterNoFallback(outputFile)
		return err
	}
	jsonPrinter.writer = printer.GetWriter(ctx, outputFile)
	return nil
}

func (jsonPrinter *JsonPrinter) Score(score float32) {
	fmt.Fprintf(os.Stderr, "\nOverall compliance-score (100- Excellent, 0- All failed): %d\n", cautils.ComplianceScoreToInt(score))
}

func (jsonPrinter *JsonPrinter) PrintNextSteps() {

}

func (jsonPrinter *JsonPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, _ []cautils.ImageScanData) error {
	report := cautils.ReportV2ToV1(opaSessionObj)

	var postureReportStr []byte
	var err error

	if len(report.FrameworkReports) == 1 {
		postureReportStr, err = json.Marshal(report.FrameworkReports[0])
	} else {
		postureReportStr, err = json.Marshal(report.FrameworkReports)
	}

	if err != nil {
		return fmt.Errorf("failed to convert posture report object: %w", err)
	}

	_, err = jsonPrinter.writer.Write(postureReportStr)

	if err != nil {
		return fmt.Errorf("failed to write posture report object into JSON output: %w", err)
	} else {
		printer.LogOutputFile(jsonPrinter.writer.Name())
	}
	return nil
}

func (p *JsonPrinter) CloseWriter() error {
	if p.writer != nil && p.writer != os.Stdout {
		return p.writer.Close()
	}
	return nil
}
