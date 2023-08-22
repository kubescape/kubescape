package printer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/grype/grype/presenter"
	"github.com/anchore/grype/grype/presenter/models"
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
	fmt.Fprintf(os.Stderr, "\nOverall compliance-score (100- Excellent, 0- All failed): %d\n", cautils.Float32ToInt(score))

}

func (jp *JsonPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) {
	var err error
	if opaSessionObj != nil {
		err = printConfigurationsScanning(opaSessionObj, ctx, jp)
	} else if imageScanData != nil {
		err = jp.PrintImageScan(ctx, imageScanData[0].PresenterConfig)
	} else {
		err = fmt.Errorf("no data provided")
	}

	if err != nil {
		logger.L().Ctx(ctx).Error("failed to write results in json format", helpers.Error(err))
		return
	}

	printer.LogOutputFile(jp.writer.Name())
}

func printConfigurationsScanning(opaSessionObj *cautils.OPASessionObj, ctx context.Context, jp *JsonPrinter) error {
	r, err := json.Marshal(FinalizeResults(opaSessionObj))
	if err != nil {
		return err
	}

	_, err = jp.writer.Write(r)
	return err
}

func (jp *JsonPrinter) PrintImageScan(ctx context.Context, scanResults *models.PresenterConfig) error {
	if scanResults == nil {
		return fmt.Errorf("no image vulnerability data provided")
	}

	presenterConfig, err := presenter.ValidatedConfig("json", "", false)
	if err != nil {
		return err
	}

	pres := presenter.GetPresenter(presenterConfig, *scanResults)

	return pres.Present(jp.writer)
}

func (jp *JsonPrinter) PrintNextSteps() {

}
