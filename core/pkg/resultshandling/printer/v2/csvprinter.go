package printer

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
)

const (
	csvOutputFile = "report"
)

var _ printer.IPrinter = &CsvPrinter{}

type CsvPrinter struct {
	writer *os.File
}

func NewCsvPrinter() *CsvPrinter {
	return &CsvPrinter{}
}

func (cp *CsvPrinter) SetWriter(ctx context.Context, outputFile string) {
	if outputFile != "" {
		if strings.TrimSpace(outputFile) == "" {
			outputFile = csvOutputFile
		}
		ext := filepath.Ext(strings.TrimSpace(outputFile))
		if ext != printer.CsvOutputExt {
			outputFile = outputFile + printer.CsvOutputExt
		}
	}
	cp.writer = printer.GetWriter(ctx, outputFile)
}

func (cp *CsvPrinter) Score(score float32) {
	// Handle invalid scores
	if score > 100 {
		score = 100
	} else if score < 0 {
		score = 0
	}

	fmt.Fprintf(os.Stderr, "\nOverall compliance-score (100- Excellent, 0- All failed): %d\n", cautils.ComplianceScoreToInt(score))
}

func (cp *CsvPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error {
	if opaSessionObj == nil {
		return fmt.Errorf("no data provided for CSV output")
	}

	finalizedReport := FinalizeResults(opaSessionObj)
	reportWithSeverity := ConvertToPostureReportWithSeverityLabelsAndCoverage(finalizedReport, opaSessionObj.LabelsToCopy, opaSessionObj.AllResources, &opaSessionObj.ScanCoverage)

	csvWriter := csv.NewWriter(cp.writer)

	// Write Header
	header := []string{
		"Control Name",
		"Control ID",
		"Severity",
		"Status",
		"Resource Name",
		"Resource Kind",
		"Resource Namespace",
		"API Version",
	}
	if err := csvWriter.Write(header); err != nil {
		logger.L().Ctx(ctx).Error("failed to write CSV header", helpers.Error(err))
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, result := range reportWithSeverity.Results {
		resID := result.ResourceID
		var resName, resKind, resNamespace, resApiVersion string

		// Try to find the resource object to extract metadata
		if resourceData, ok := opaSessionObj.AllResources[resID]; ok {
			resName = resourceData.GetName()
			resKind = resourceData.GetKind()
			resNamespace = resourceData.GetNamespace()
			resApiVersion = resourceData.GetApiVersion()
		}

		// Write each control association
		for _, assocCtrl := range result.AssociatedControls {
			ctrlID := assocCtrl.GetID()
			ctrlName := assocCtrl.GetName()

			// Severity is already populated
			severity := assocCtrl.Severity
			if severity == "" {
				severity = "Unknown"
			}

			status := string(assocCtrl.GetStatus(nil).Status())
			if status == "" {
				status = "unknown"
			}

			row := []string{
				ctrlName,
				ctrlID,
				severity,
				status,
				resName,
				resKind,
				resNamespace,
				resApiVersion,
			}
			if err := csvWriter.Write(row); err != nil {
				logger.L().Ctx(ctx).Error("failed to write CSV row", helpers.Error(err))
				return fmt.Errorf("failed to write CSV row: %w", err)
			}
		}
	}

	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		logger.L().Ctx(ctx).Error("failed to flush CSV writer", helpers.Error(err))
		return fmt.Errorf("failed to flush CSV writer: %w", err)
	}

	printer.LogOutputFile(cp.writer.Name())
	return nil
}

func (cp *CsvPrinter) PrintNextSteps() {
}

func (cp *CsvPrinter) CloseWriter() {
	if cp.writer != nil && cp.writer != os.Stdout {
		_ = cp.writer.Close()
	}
}
