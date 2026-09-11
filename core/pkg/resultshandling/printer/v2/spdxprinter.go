package printer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
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
	outputFile, explicitOutput := printer.ResolveOutputFile(printer.SPDXFormat, outputFile, spdxOutputFile)
	if explicitOutput {
		var err error
		sp.writer, err = printer.GetWriterNoFallback(outputFile)
		return err
	}
	sp.writer = printer.GetWriter(ctx, outputFile)
	return nil
}

func (sp *SPDXPrinter) Score(score float32) {}

func (sp *SPDXPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error {
	if len(imageScanData) == 0 {
		logger.L().Ctx(ctx).Error("spdx-json output requires scanned images")
		return fmt.Errorf("spdx-json output requires scanned images")
	}

	encoder, err := spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to create spdx-json encoder", helpers.Error(err))
		return err
	}

	var encodedDocs []json.RawMessage
	for _, scan := range imageScanData {
		if scan.SBOM == nil {
			logger.L().Ctx(ctx).Warning("skipping image with no SBOM data available for spdx-json output")
			continue
		}

		data, err := format.Encode(*scan.SBOM, encoder)
		if err != nil {
			logger.L().Ctx(ctx).Error("failed to encode SBOM as spdx-json", helpers.Error(err))
			return err
		}

		encodedDocs = append(encodedDocs, json.RawMessage(data))
	}

	if len(encodedDocs) == 0 {
		logger.L().Ctx(ctx).Error("no SBOM data available for spdx-json output")
		return fmt.Errorf("no SBOM data available for spdx-json output")
	}

	var outputBytes []byte
	if len(encodedDocs) == 1 {
		outputBytes = encodedDocs[0]
	} else {
		outputBytes, err = json.MarshalIndent(encodedDocs, "", "  ")
		if err != nil {
			logger.L().Ctx(ctx).Error("failed to marshal multi-image spdx-json output", helpers.Error(err))
			return err
		}
	}

	if _, err := sp.writer.Write(outputBytes); err != nil {
		logger.L().Ctx(ctx).Error("failed to write spdx-json output", helpers.Error(err))
		return err
	}

	printer.LogOutputFile(sp.writer.Name())
	return nil
}

func (sp *SPDXPrinter) PrintNextSteps() {}

// CloseWriter closes the SPDX output writer, returning any error from flushing or closing.
func (sp *SPDXPrinter) CloseWriter() error {
	if sp.writer != nil && sp.writer != os.Stdout {
		return sp.writer.Close()
	}
	return nil
}
