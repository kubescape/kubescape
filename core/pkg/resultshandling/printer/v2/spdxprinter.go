package printer

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
)

const (
	spdxOutputFile = "sbom"
)

var _ printer.IPrinter = &SPDXPrinter{}

type SPDXPrinter struct {
	writer *os.File
}

func NewSPDXPrinter() *SPDXPrinter {
	return &SPDXPrinter{}
}

func (sp *SPDXPrinter) SetWriter(ctx context.Context, outputFile string) error {
	explicitOutput := outputFile != ""
	if outputFile != "" {
		if strings.TrimSpace(outputFile) == "" {
			outputFile = spdxOutputFile
		}
		if !strings.HasSuffix(strings.TrimSpace(outputFile), printer.SPDXOutputExt) {
			outputFile = outputFile + printer.SPDXOutputExt
		}
	}
	if explicitOutput {
		var err error
		sp.writer, err = printer.GetWriterNoFallback(outputFile)
		return err
	}
	sp.writer = printer.GetWriter(ctx, outputFile)
	return nil
}

// Score is a no-op: HandleResults only calls Score when opaSessionObj != nil
// (core/pkg/resultshandling/results.go), and this printer only ever runs
// against image scans, so it is never invoked in practice.
func (sp *SPDXPrinter) Score(score float32) {}

func (sp *SPDXPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error {
	if opaSessionObj != nil || len(imageScanData) == 0 {
		logger.L().Ctx(ctx).Error("spdx-json output is only supported for image scans")
		return fmt.Errorf("spdx-json output is only supported for image scans")
	}
	if imageScanData[0].SBOM == nil {
		logger.L().Ctx(ctx).Error("no SBOM data available for spdx-json output")
		return fmt.Errorf("no SBOM data available for spdx-json output")
	}

	encoder, err := spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to create spdx-json encoder", helpers.Error(err))
		return err
	}

	data, err := format.Encode(*imageScanData[0].SBOM, encoder)
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to encode SBOM as spdx-json", helpers.Error(err))
		return err
	}

	if _, err := sp.writer.Write(data); err != nil {
		logger.L().Ctx(ctx).Error("failed to write spdx-json output", helpers.Error(err))
		return err
	}

	printer.LogOutputFile(sp.writer.Name())
	return nil
}

func (sp *SPDXPrinter) PrintNextSteps() {}

func (sp *SPDXPrinter) CloseWriter() {
	if sp.writer != nil && sp.writer != os.Stdout {
		sp.writer.Close()
	}
}
