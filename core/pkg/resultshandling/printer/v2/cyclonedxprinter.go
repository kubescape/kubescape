package printer

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
)

const (
	cyclonedxOutputFile = "sbom"
)

var _ printer.IPrinter = &CycloneDXPrinter{}

type CycloneDXPrinter struct {
	writer *os.File
}

func NewCycloneDXPrinter() *CycloneDXPrinter {
	return &CycloneDXPrinter{}
}

func (cp *CycloneDXPrinter) SetWriter(ctx context.Context, outputFile string) error {
	explicitOutput := outputFile != ""
	if outputFile != "" {
		if strings.TrimSpace(outputFile) == "" {
			outputFile = cyclonedxOutputFile
		}
		if !strings.HasSuffix(strings.TrimSpace(outputFile), printer.CycloneDXOutputExt) {
			outputFile = outputFile + printer.CycloneDXOutputExt
		}
	}
	if explicitOutput {
		var err error
		cp.writer, err = printer.GetWriterNoFallback(outputFile)
		return err
	}
	cp.writer = printer.GetWriter(ctx, outputFile)
	return nil
}

// Score is a no-op: HandleResults only calls Score when opaSessionObj != nil
// (core/pkg/resultshandling/results.go), and this printer only ever runs
// against image scans, so it is never invoked in practice.
func (cp *CycloneDXPrinter) Score(score float32) {}

func (cp *CycloneDXPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error {
	if opaSessionObj != nil || len(imageScanData) == 0 {
		logger.L().Ctx(ctx).Error("cyclonedx-json output is only supported for image scans")
		return fmt.Errorf("cyclonedx-json output is only supported for image scans")
	}
	if imageScanData[0].SBOM == nil {
		logger.L().Ctx(ctx).Error("no SBOM data available for cyclonedx-json output")
		return fmt.Errorf("no SBOM data available for cyclonedx-json output")
	}

	encoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to create cyclonedx-json encoder", helpers.Error(err))
		return err
	}

	data, err := format.Encode(*imageScanData[0].SBOM, encoder)
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to encode SBOM as cyclonedx-json", helpers.Error(err))
		return err
	}

	if _, err := cp.writer.Write(data); err != nil {
		logger.L().Ctx(ctx).Error("failed to write cyclonedx-json output", helpers.Error(err))
		return err
	}

	printer.LogOutputFile(cp.writer.Name())
	return nil
}

func (cp *CycloneDXPrinter) PrintNextSteps() {}

// CloseWriter closes the CycloneDX output writer, returning any error from flushing or closing.
func (cp *CycloneDXPrinter) CloseWriter() error {
	if cp.writer != nil && cp.writer != os.Stdout {
		return cp.writer.Close()
	}
	return nil
}
