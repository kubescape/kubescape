package printer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
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
	if explicitOutput {
		var err error
		cp.writer, err = printer.GetWriterNoFallback(printer.ResolveOutputPath(printer.CycloneDXFormat, outputFile))
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

	encoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to create cyclonedx-json encoder", helpers.Error(err))
		return err
	}

	var encodedDocs []json.RawMessage
	for _, scan := range imageScanData {
		if scan.SBOM == nil {
			logger.L().Ctx(ctx).Warning("skipping image with no SBOM data available for cyclonedx-json output")
			continue
		}

		data, err := format.Encode(*scan.SBOM, encoder)
		if err != nil {
			logger.L().Ctx(ctx).Error("failed to encode SBOM as cyclonedx-json", helpers.Error(err))
			return err
		}

		encodedDocs = append(encodedDocs, json.RawMessage(data))
	}

	if len(encodedDocs) == 0 {
		logger.L().Ctx(ctx).Error("no SBOM data available for cyclonedx-json output")
		return fmt.Errorf("no SBOM data available for cyclonedx-json output")
	}

	var outputBytes []byte
	if len(encodedDocs) == 1 {
		outputBytes = encodedDocs[0]
	} else {
		outputBytes, err = json.MarshalIndent(encodedDocs, "", "  ")
		if err != nil {
			logger.L().Ctx(ctx).Error("failed to marshal multi-image cyclonedx-json output", helpers.Error(err))
			return err
		}
	}

	if _, err := cp.writer.Write(outputBytes); err != nil {
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
