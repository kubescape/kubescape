package printer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/clio"
	grypejson "github.com/anchore/grype/grype/presenter/json"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

const (
	jsonOutputFile = "report"
)

var _ printer.IPrinter = &JsonPrinter{}

type JsonPrinter struct {
	writer      *os.File
	minSeverity string
}

func NewJsonPrinter(minSeverity string) *JsonPrinter {
	return &JsonPrinter{minSeverity: minSeverity}
}

func (jp *JsonPrinter) SetWriter(ctx context.Context, outputFile string) error {
	explicitOutput := outputFile != ""
	if outputFile != "" {
		if strings.TrimSpace(outputFile) == "" {
			outputFile = jsonOutputFile
		}
		if filepath.Ext(strings.TrimSpace(outputFile)) != printer.JsonOutputExt {
			outputFile = outputFile + printer.JsonOutputExt
		}
	}
	if explicitOutput {
		var err error
		jp.writer, err = printer.GetWriterNoFallback(outputFile)
		return err
	}
	jp.writer = printer.GetWriter(ctx, outputFile)
	return nil
}

func (jp *JsonPrinter) Score(score float32) {
	// Handle invalid scores
	if score > 100 {
		score = 100
	} else if score < 0 {
		score = 0
	}

	fmt.Fprintf(os.Stderr, "\nOverall compliance-score (100- Excellent, 0- All failed): %d\n", cautils.ComplianceScoreToInt(score))

}
func (jp *JsonPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error {
	var err error

	if opaSessionObj != nil {
		err = printConfigurationsScanning(opaSessionObj, imageScanData, jp)
	} else if len(imageScanData) > 0 {
		model, err2 := models.NewDocument(clio.Identification{}, imageScanData[0].Packages, imageScanData[0].Context,
			imageScanData[0].Matches, imageScanData[0].IgnoredMatches, imageScanData[0].VulnerabilityProvider, nil, nil, models.DefaultSortStrategy, false)
		if err2 != nil {
			return fmt.Errorf("failed to create document: %w", err2)
		}
		err = grypejson.NewPresenter(models.PresenterConfig{Document: model, SBOM: imageScanData[0].SBOM}).Present(jp.writer)
	} else {
		err = fmt.Errorf("no data provided")
	}

	if err != nil {
		logger.L().Ctx(ctx).Error("failed to write results in json format", helpers.Error(err))
		return fmt.Errorf("failed to write results in json format: %w", err)
	}

	printer.LogOutputFile(jp.writer.Name())
	return nil
}

func printConfigurationsScanning(opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData, jp *JsonPrinter) error {
	// Finalize into the report owned by this renderer before adding image data.
	// The same OPASessionObj is submitted after local output is written, so
	// enriching opaSessionObj.Report here would make --format change the backend
	// payload as a side effect.
	finalizedReport := FinalizeResults(opaSessionObj)

	if imageScanData != nil {
		imageScanSummary := buildMachineImageScanSummary(imageScanData)
		finalizedReport.SummaryDetails.Vulnerabilities.MapsSeverityToSummary = convertToReportSummary(imageScanSummary.MapsSeverityToSummary)
		finalizedReport.SummaryDetails.Vulnerabilities.CVESummary = convertToCVESummary(imageScanSummary.CVEs)
		finalizedReport.SummaryDetails.Vulnerabilities.PackageScores = convertToPackageScores(imageScanSummary.PackageScores)
		finalizedReport.SummaryDetails.Vulnerabilities.Images = imageScanSummary.Images
	}

	// Convert to PostureReportWithSeverity to add severity field to controls,
	// extract specified labels from workloads, and attach scan coverage gaps.
	reportWithSeverity := ConvertToPostureReportWithSeverityLabelsAndCoverage(finalizedReport, opaSessionObj.LabelsToCopy, opaSessionObj.AllResources, &opaSessionObj.ScanCoverage)
	reportWithSeverity.ExceptionAudit = opaSessionObj.ExceptionAudit
	FilterBySeverity(reportWithSeverity, jp.minSeverity)

	r, err := json.Marshal(reportWithSeverity)
	if err != nil {
		return err
	}
	_, err = jp.writer.Write(r)

	return err
}

func convertToPackageScores(packageScores map[string]*imageprinter.PackageScore) map[string]*reportsummary.PackageSummary {
	convertedPackageScores := make(map[string]*reportsummary.PackageSummary)
	for pkg, score := range packageScores {
		convertedPackageScores[pkg] = &reportsummary.PackageSummary{
			Name:                    score.Name,
			Version:                 score.Version,
			Score:                   score.Score,
			MapSeverityToCVEsNumber: score.MapSeverityToCVEsNumber,
		}
	}
	return convertedPackageScores
}

func convertToCVESummary(cves []imageprinter.CVE) []reportsummary.CVESummary {
	cveSummary := make([]reportsummary.CVESummary, len(cves))
	i := 0
	for _, cve := range cves {
		var a reportsummary.CVESummary
		a.Severity = cve.Severity
		a.ID = cve.ID
		a.Package = cve.Package
		a.Version = cve.Version
		a.FixVersions = cve.FixVersions
		a.FixedState = cve.FixedState
		cveSummary[i] = a
		i++
	}
	return cveSummary
}

func convertToReportSummary(input map[string]*imageprinter.SeveritySummary) map[string]*reportsummary.SeveritySummary {
	output := make(map[string]*reportsummary.SeveritySummary)
	for key, value := range input {
		output[key] = &reportsummary.SeveritySummary{
			NumberOfCVEs:        value.NumberOfCVEs,
			NumberOfFixableCVEs: value.NumberOfFixableCVEs,
		}
	}
	return output
}

func (jp *JsonPrinter) PrintNextSteps() {

}

// CloseWriter closes the JSON output writer, returning any error from flushing or closing.
func (p *JsonPrinter) CloseWriter() error {
	if p.writer != nil && p.writer != os.Stdout {
		return p.writer.Close()
	}
	return nil
}
