package printer

import (
	"bytes"
	"context"
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
	"sigs.k8s.io/yaml"
)

const (
	yamlOutputFile = "report"
)

var _ printer.IPrinter = &YamlPrinter{}

type YamlPrinter struct {
	writer *os.File
}

func NewYamlPrinter() *YamlPrinter {
	return &YamlPrinter{}
}

func (yp *YamlPrinter) SetWriter(ctx context.Context, outputFile string) {
	if outputFile != "" {
		if strings.TrimSpace(outputFile) == "" {
			outputFile = yamlOutputFile
		}
		ext := filepath.Ext(strings.TrimSpace(outputFile))
		if ext != printer.YamlOutputExt && ext != ".yml" {
			outputFile = outputFile + printer.YamlOutputExt
		}
	}
	yp.writer = printer.GetWriter(ctx, outputFile)
}

func (yp *YamlPrinter) Score(score float32) {
	// Handle invalid scores
	if score > 100 {
		score = 100
	} else if score < 0 {
		score = 0
	}

	fmt.Fprintf(os.Stderr, "\nOverall compliance-score (100- Excellent, 0- All failed): %d\n", cautils.ComplianceScoreToInt(score))
}

func (yp *YamlPrinter) convertToImageScanSummary(imageScanData []cautils.ImageScanData) *imageprinter.ImageScanSummary {
	imageScanSummary := imageprinter.ImageScanSummary{
		CVEs:                  []imageprinter.CVE{},
		PackageScores:         map[string]*imageprinter.PackageScore{},
		MapsSeverityToSummary: map[string]*imageprinter.SeveritySummary{},
	}

	for i := range imageScanData {
		if !slices.Contains(imageScanSummary.Images, imageScanData[i].Image) {
			imageScanSummary.Images = append(imageScanSummary.Images, imageScanData[i].Image)
		}

		CVEs := extractCVEs(imageScanData[i].Matches, imageScanData[i].Image)
		imageScanSummary.CVEs = append(imageScanSummary.CVEs, CVEs...)

		setPkgNameToScoreMap(imageScanData[i].Matches, imageScanSummary.PackageScores)

		setSeverityToSummaryMap(CVEs, imageScanSummary.MapsSeverityToSummary)
	}

	return &imageScanSummary
}

func (yp *YamlPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) {
	var err error

	if opaSessionObj != nil {
		err = printConfigurationsScanningYaml(opaSessionObj, imageScanData, yp)
	} else if len(imageScanData) > 0 {
		model, err2 := models.NewDocument(clio.Identification{}, imageScanData[0].Packages, imageScanData[0].Context,
			imageScanData[0].Matches, imageScanData[0].IgnoredMatches, imageScanData[0].VulnerabilityProvider, nil, nil, models.DefaultSortStrategy, false)
		if err2 != nil {
			logger.L().Ctx(ctx).Error("failed to create document", helpers.Error(err2))
			return
		}

		// Use grype json presenter and convert json to yaml
		var buf bytes.Buffer
		err = grypejson.NewPresenter(models.PresenterConfig{Document: model, SBOM: imageScanData[0].SBOM}).Present(&buf)
		if err == nil {
			var yamlData []byte
			yamlData, err = yaml.JSONToYAML(buf.Bytes())
			if err == nil {
				_, err = yp.writer.Write(yamlData)
			}
		}
	} else {
		err = fmt.Errorf("no data provided")
	}

	if err != nil {
		logger.L().Ctx(ctx).Error("failed to write results in yaml format", helpers.Error(err))
		return
	}

	printer.LogOutputFile(yp.writer.Name())
}

func printConfigurationsScanningYaml(opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData, yp *YamlPrinter) error {

	if imageScanData != nil {
		imageScanSummary := yp.convertToImageScanSummary(imageScanData)
		opaSessionObj.Report.SummaryDetails.Vulnerabilities.MapsSeverityToSummary = convertToReportSummary(imageScanSummary.MapsSeverityToSummary)
		opaSessionObj.Report.SummaryDetails.Vulnerabilities.CVESummary = convertToCVESummary(imageScanSummary.CVEs)
		opaSessionObj.Report.SummaryDetails.Vulnerabilities.PackageScores = convertToPackageScores(imageScanSummary.PackageScores)
		opaSessionObj.Report.SummaryDetails.Vulnerabilities.Images = imageScanSummary.Images
	}

	// Convert to PostureReportWithSeverity to add severity field to controls,
	// extract specified labels from workloads, and attach scan coverage gaps.
	finalizedReport := FinalizeResults(opaSessionObj)
	reportWithSeverity := ConvertToPostureReportWithSeverityLabelsAndCoverage(finalizedReport, opaSessionObj.LabelsToCopy, opaSessionObj.AllResources, &opaSessionObj.ScanCoverage)

	r, err := yaml.Marshal(reportWithSeverity)
	if err != nil {
		return err
	}
	_, err = yp.writer.Write(r)

	return err
}

func (yp *YamlPrinter) PrintNextSteps() {

}

func (yp *YamlPrinter) CloseWriter() {
	if yp.writer != nil && yp.writer != os.Stdout {
		yp.writer.Close()
	}
}
