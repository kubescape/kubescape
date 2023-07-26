package printer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/grype/grype/presenter"
	"github.com/anchore/grype/grype/presenter/models"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
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

func printImageAndConfigurationScanning(output io.Writer, imageScanData *models.PresenterConfig, opaSessionObj *cautils.OPASessionObj) error {
	type Document struct {
		*models.Document                `json:",omitempty"`
		*reporthandlingv2.PostureReport `json:",omitempty"`
	}

	doc, err := models.NewDocument(imageScanData.Packages, imageScanData.Context, imageScanData.Matches, imageScanData.IgnoredMatches, imageScanData.MetadataProvider,
		imageScanData.AppConfig, imageScanData.DBStatus)
	if err != nil {
		return err
	}

	docForJson := Document{
		&doc,
		FinalizeResults(opaSessionObj),
	}

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(&docForJson)
}

func (jp *JsonPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) {
	var err error
	if opaSessionObj != nil && imageScanData != nil {
		err = printImageAndConfigurationScanning(jp.writer, imageScanData[0].PresenterConfig, opaSessionObj)
	} else if opaSessionObj != nil {
		err = printConfigurationsScanning(opaSessionObj, ctx, jp)
	} else if imageScanData != nil {
		err = jp.PrintImageScan(ctx, imageScanData[0].PresenterConfig)
	} else {
		err = fmt.Errorf("failed to print results, no data provided")
	}

	if err != nil {
		logger.L().Ctx(ctx).Error("failed to print results", helpers.Error(err))
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
	pres := presenter.GetPresenter("json", jp.writer.Name(), false, *scanResults)

	return pres.Present(jp.writer)
}

func (jp *JsonPrinter) PrintNextSteps() {

}
