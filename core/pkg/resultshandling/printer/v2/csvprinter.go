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
	reporthandling "github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
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

func (cp *CsvPrinter) SetWriter(ctx context.Context, outputFile string) error {
	explicitOutput := outputFile != ""
	if outputFile != "" {
		if strings.TrimSpace(outputFile) == "" {
			outputFile = csvOutputFile
		}
		ext := filepath.Ext(strings.TrimSpace(outputFile))
		if ext != printer.CsvOutputExt {
			outputFile = outputFile + printer.CsvOutputExt
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

func (cp *CsvPrinter) Score(score float32) {
	if score > 100 {
		score = 100
	} else if score < 0 {
		score = 0
	}

	fmt.Fprintf(os.Stderr, "\nOverall compliance-score (100- Excellent, 0- All failed): %d\n", cautils.ComplianceScoreToInt(score))
}

func (cp *CsvPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) (err error) {
	if opaSessionObj == nil {
		return fmt.Errorf("no data provided for CSV output")
	}

	finalizedReport := FinalizeResults(opaSessionObj)
	reportWithSeverity := ConvertToPostureReportWithSeverityLabelsAndCoverage(finalizedReport, opaSessionObj.LabelsToCopy, opaSessionObj.AllResources, &opaSessionObj.ScanCoverage)

	summaryControls := finalizedReport.SummaryDetails.Controls

	csvWriter := csv.NewWriter(cp.writer)
	defer func() {
		csvWriter.Flush()
		if flushErr := csvWriter.Error(); flushErr != nil {
			logger.L().Ctx(ctx).Error("failed to flush CSV writer", helpers.Error(flushErr))
			if err == nil {
				err = fmt.Errorf("failed to flush CSV writer: %w", flushErr)
			}
		}
		if err == nil {
			printer.LogOutputFile(cp.writer.Name())
		}
	}()

	header := []string{
		"Control Name",
		"Control ID",
		"Severity",
		"Status",
		"Resource Name",
		"Resource Kind",
		"Resource Namespace",
		"API Version",
		"Failed Paths",
		"Fix Paths",
		"Remediation",
		"Control URL",
		"Source Path",
	}
	if err := csvWriter.Write(header); err != nil {
		logger.L().Ctx(ctx).Error("failed to write CSV header", helpers.Error(err))
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, result := range reportWithSeverity.Results {
		resID := result.ResourceID
		var resName, resKind, resNamespace, resApiVersion string

		if resourceData, ok := opaSessionObj.AllResources[resID]; ok {
			resName = resourceData.GetName()
			resKind = resourceData.GetKind()
			resNamespace = resourceData.GetNamespace()
			resApiVersion = resourceData.GetApiVersion()
		}

		sourcePath := ""
		if src, ok := opaSessionObj.ResourceSource[resID]; ok {
			sourcePath = csvSourcePath(src)
		}

		resourceResult, hasResult := opaSessionObj.ResourcesResult[resID]

		for _, assocCtrl := range result.AssociatedControls {
			ctrlID := assocCtrl.GetID()
			ctrlName := assocCtrl.GetName()

			severity := assocCtrl.Severity
			if severity == "" {
				severity = "Unknown"
			}

			status := string(assocCtrl.GetStatus(nil).Status())
			if status == "" {
				status = "unknown"
			}

			failedPaths := ""
			fixPaths := ""
			if hasResult {
				failedPaths, fixPaths = csvControlPaths(resourceResult, ctrlID)
			}

			remediation := ""
			if ctrl := summaryControls.GetControl(reportsummary.EControlCriteriaID, ctrlID); ctrl != nil {
				remediation = ctrl.GetRemediation()
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
				failedPaths,
				fixPaths,
				remediation,
				cautils.GetControlLink(ctrlID),
				sourcePath,
			}
			if err := csvWriter.Write(row); err != nil {
				logger.L().Ctx(ctx).Error("failed to write CSV row", helpers.Error(err))
				return fmt.Errorf("failed to write CSV row: %w", err)
			}
		}
	}

	return nil
}

func (cp *CsvPrinter) PrintNextSteps() {
}

// CloseWriter closes the CSV output writer, returning any error from flushing or closing.
func (cp *CsvPrinter) CloseWriter() error {
	if cp.writer != nil && cp.writer != os.Stdout {
		return cp.writer.Close()
	}
	return nil
}

// csvControlPaths returns the semicolon-separated failed paths and fix paths
// for the given controlID in result. Both strings are empty when the control
// is not found or has no paths.
func csvControlPaths(result resourcesresults.Result, controlID string) (failedPaths, fixPaths string) {
	for i := range result.AssociatedControls {
		if result.AssociatedControls[i].GetID() != controlID {
			continue
		}
		var failed, fix []string
		for j := range result.AssociatedControls[i].ResourceAssociatedRules {
			for k := range result.AssociatedControls[i].ResourceAssociatedRules[j].Paths {
				p := result.AssociatedControls[i].ResourceAssociatedRules[j].Paths[k]
				if p.FailedPath != "" {
					failed = append(failed, p.FailedPath)
				}
				if p.FixPath.Path != "" {
					if p.FixPath.Value != "" {
						fix = append(fix, p.FixPath.Path+"="+p.FixPath.Value)
					} else {
						fix = append(fix, p.FixPath.Path)
					}
				}
			}
		}
		return strings.Join(failed, "; "), strings.Join(fix, "; ")
	}
	return "", ""
}

// csvSourcePath returns the best available source path from a Source entry.
// RelativePath is preferred because it is repo-relative and more portable.
func csvSourcePath(src reporthandling.Source) string {
	if src.RelativePath != "" {
		return src.RelativePath
	}
	return src.Path
}
