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
	"github.com/kubescape/opa-utils/reporthandling/apis"
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

func (cp *CsvPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) {
	if opaSessionObj == nil {
		logger.L().Ctx(ctx).Error("no data provided for CSV output")
		return
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
		return
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
			
			// Find severity from SummaryDetails if available
			severity := "Unknown"
			if ctrlData, ok := reportWithSeverity.SummaryDetails.Controls[ctrlID]; ok {
				severity = apis.ControlSeverityToString(ctrlData.GetScoreFactor())
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
				return
			}
		}
	}

	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		logger.L().Ctx(ctx).Error("failed to flush CSV writer", helpers.Error(err))
		return
	}

	printer.LogOutputFile(cp.writer.Name())
}

func (cp *CsvPrinter) PrintNextSteps() {
}

func (cp *CsvPrinter) CloseWriter() {
	if cp.writer != nil && cp.writer != os.Stdout {
		cp.writer.Close()
	}
}
