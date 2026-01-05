package printer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
	if outputFile != "" {
		if strings.TrimSpace(outputFile) == "" {
			outputFile = jsonOutputFile
		}
		if filepath.Ext(strings.TrimSpace(outputFile)) != jsonOutputExt {
			outputFile = outputFile + jsonOutputExt
		}
	}
	jp.writer = printer.GetWriter(ctx, outputFile)
}

func (jp *JsonPrinter) Score(score float32) {
	// Handle invalid scores
	if score > 100 {
		score = 100
	} else if score < 0 {
		score = 0
	}

	fmt.Fprintf(os.Stderr, "\nOverall compliance-score (100- Excellent, 0- All failed): %d\n", cautils.Float32ToInt(score))

}
func (jp *JsonPrinter) convertToImageScanSummary(imageScanData []cautils.ImageScanData) (*imageprinter.ImageScanSummary, error) {
	imageScanSummary := imageprinter.ImageScanSummary{
		CVEs:                  []imageprinter.CVE{},
		PackageScores:         map[string]*imageprinter.PackageScore{},
		MapsSeverityToSummary: map[string]*imageprinter.SeveritySummary{},
	}

	for i := range imageScanData {
		if !slices.Contains(imageScanSummary.Images, imageScanData[i].Image) {
			imageScanSummary.Images = append(imageScanSummary.Images, imageScanData[i].Image)
		}

		CVEs := extractCVEs(imageScanData[i].Matches)
		imageScanSummary.CVEs = append(imageScanSummary.CVEs, CVEs...)

		setPkgNameToScoreMap(imageScanData[i].Matches, imageScanSummary.PackageScores)

		setSeverityToSummaryMap(CVEs, imageScanSummary.MapsSeverityToSummary)
	}

	return &imageScanSummary, nil
}

func (jp *JsonPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) {
	var err error

	if opaSessionObj != nil {
		err = printConfigurationsScanning(opaSessionObj, imageScanData, jp)
	} else if imageScanData != nil {
		model, err2 := models.NewDocument(clio.Identification{}, imageScanData[0].Packages, imageScanData[0].Context,
			*imageScanData[0].RemainingMatches, imageScanData[0].IgnoredMatches, imageScanData[0].VulnerabilityProvider, nil, nil, models.DefaultSortStrategy, false)
		if err2 != nil {
			logger.L().Ctx(ctx).Error("failed to create document: %w", helpers.Error(err))
			return
		}
		err = grypejson.NewPresenter(models.PresenterConfig{Document: model, SBOM: imageScanData[0].SBOM}).Present(jp.writer)
	} else {
		err = fmt.Errorf("no data provided")
	}

	if err != nil {
		logger.L().Ctx(ctx).Error("failed to write results in json format", helpers.Error(err))
		return
	}

	printer.LogOutputFile(jp.writer.Name())
}

func printConfigurationsScanning(opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData, jp *JsonPrinter) error {

	if imageScanData != nil {
		imageScanSummary, err := jp.convertToImageScanSummary(imageScanData)
		if err != nil {
			logger.L().Error("failed to convert to image scan summary", helpers.Error(err))
			return err
		}
		opaSessionObj.Report.SummaryDetails.Vulnerabilities.MapsSeverityToSummary = convertToReportSummary(imageScanSummary.MapsSeverityToSummary)
		opaSessionObj.Report.SummaryDetails.Vulnerabilities.CVESummary = convertToCVESummary(imageScanSummary.CVEs)
		opaSessionObj.Report.SummaryDetails.Vulnerabilities.PackageScores = convertToPackageScores(imageScanSummary.PackageScores)
		opaSessionObj.Report.SummaryDetails.Vulnerabilities.Images = imageScanSummary.Images
	}

	// Convert to PostureReportWithSeverity to add severity field to controls
	// and extract specified labels from workloads
	finalizedReport := FinalizeResults(opaSessionObj)
	reportWithSeverity := ConvertToPostureReportWithSeverityAndLabels(finalizedReport, opaSessionObj.LabelsToCopy, opaSessionObj.AllResources)

	r, err := json.Marshal(reportWithSeverity)
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
