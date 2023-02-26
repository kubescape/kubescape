package printer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
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

func (jp *JsonPrinter) SetWriter(ctx context.Context, outputFile string) {
	if strings.TrimSpace(outputFile) == "" {
		outputFile = jsonOutputFile
	}
	if filepath.Ext(strings.TrimSpace(outputFile)) != jsonOutputExt {
		outputFile = outputFile + jsonOutputExt
	}
	jp.writer = printer.GetWriter(ctx, outputFile)
}

func (jp *JsonPrinter) Score(score float32) {
	fmt.Fprintf(os.Stderr, "\nOverall risk-score (0- Excellent, 100- All failed): %d\n", cautils.Float32ToInt(score))
}

func (jp *JsonPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj) {
	r, err := json.Marshal(FinalizeResults(opaSessionObj))
	if err != nil {
		logger.L().Ctx(ctx).Fatal("failed to Marshal posture report object")
	}

	if _, err := jp.writer.Write(r); err != nil {
		logger.L().Ctx(ctx).Error("failed to write results", helpers.Error(err))
	} else {
		printer.LogOutputFile(jp.writer.Name())
	}
}
