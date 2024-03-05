package printer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/presenter"
	"github.com/anchore/grype/grype/presenter/models"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"k8s.io/utils/strings/slices"
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

		presenterConfig := imageScanData[i].PresenterConfig
		doc, err := models.NewDocument(clio.Identification{}, presenterConfig.Packages, presenterConfig.Context, presenterConfig.Matches, presenterConfig.IgnoredMatches, presenterConfig.MetadataProvider, nil, presenterConfig.DBStatus)
		if err != nil {
			logger.L().Error(fmt.Sprintf("failed to create document for image: %v", imageScanData[i].Image), helpers.Error(err))
			continue
		}

		CVEs := extractCVEs(doc.Matches)
		imageScanSummary.CVEs = append(imageScanSummary.CVEs, CVEs...)

		setPkgNameToScoreMap(doc.Matches, imageScanSummary.PackageScores)

		setSeverityToSummaryMap(CVEs, imageScanSummary.MapsSeverityToSummary)
	}

	return &imageScanSummary, nil
}

func (jp *JsonPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) {
	var err error

	if opaSessionObj != nil {
		err = printConfigurationsScanning(opaSessionObj, ctx, imageScanData, jp)
	} else if imageScanData != nil {
		err = jp.PrintImageScan(ctx, imageScanData[0].PresenterConfig)
	} else {
		err = fmt.Errorf("no data provided")
	}

	if err != nil {
		logger.L().Ctx(ctx).Error("failed to write results in json format", helpers.Error(err))
		return
	}

	printer.LogOutputFile(jp.writer.Name())
}

func printConfigurationsScanning(opaSessionObj *cautils.OPASessionObj, ctx context.Context, imageScanData []cautils.ImageScanData, jp *JsonPrinter) error {

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

	r, err := json.Marshal(FinalizeResults(opaSessionObj))
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

func (jp *JsonPrinter) PrintImageScan(ctx context.Context, scanResults *models.PresenterConfig) error {
	if scanResults == nil {
		return fmt.Errorf("no image vulnerability data provided")
	}
	pres := presenter.GetPresenter("json", "", false, *scanResults)
	return pres.Present(jp.writer)
}

func (jp *JsonPrinter) PrintNextSteps() {

}
