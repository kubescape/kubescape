package printer

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/clio"
	grypejson "github.com/anchore/grype/grype/presenter/json"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
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

func (yp *YamlPrinter) SetWriter(ctx context.Context, outputFile string) error {
	explicitOutput := outputFile != ""
	if outputFile != "" {
		if strings.TrimSpace(outputFile) == "" {
			outputFile = yamlOutputFile
		}
		ext := filepath.Ext(strings.TrimSpace(outputFile))
		if ext != printer.YamlOutputExt && ext != ".yml" {
			outputFile = outputFile + printer.YamlOutputExt
		}
	}
	if explicitOutput {
		var err error
		yp.writer, err = printer.GetWriterNoFallback(outputFile)
		return err
	}
	yp.writer = printer.GetWriter(ctx, outputFile)
	return nil
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

func (yp *YamlPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error {
	var err error

	if opaSessionObj != nil {
		err = printConfigurationsScanningYaml(opaSessionObj, imageScanData, yp)
	} else if len(imageScanData) > 0 {
		model, err2 := models.NewDocument(clio.Identification{}, imageScanData[0].Packages, imageScanData[0].Context,
			imageScanData[0].Matches, imageScanData[0].IgnoredMatches, imageScanData[0].VulnerabilityProvider, nil, nil, models.DefaultSortStrategy, false)
		if err2 != nil {
			return fmt.Errorf("failed to create document: %w", err2)
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
		return fmt.Errorf("failed to write results in yaml format: %w", err)
	}

	printer.LogOutputFile(yp.writer.Name())
	return nil
}

func printConfigurationsScanningYaml(opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData, yp *YamlPrinter) error {
	// Add combined-scan data to this renderer's finalized report. Mutating the
	// shared session here would also change the posture payload submitted after
	// local output has finished.
	finalizedReport := FinalizeResults(opaSessionObj)

	if imageScanData != nil {
		imageScanSummary := buildImageScanSummary(imageScanData)
		finalizedReport.SummaryDetails.Vulnerabilities.MapsSeverityToSummary = convertToReportSummary(imageScanSummary.MapsSeverityToSummary)
		finalizedReport.SummaryDetails.Vulnerabilities.CVESummary = convertToCVESummary(imageScanSummary.CVEs)
		finalizedReport.SummaryDetails.Vulnerabilities.PackageScores = convertToPackageScores(imageScanSummary.PackageScores)
		finalizedReport.SummaryDetails.Vulnerabilities.Images = imageScanSummary.Images
	}

	// Convert to PostureReportWithSeverity to add severity field to controls,
	// extract specified labels from workloads, and attach scan coverage gaps.
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

// CloseWriter closes the YAML output writer, returning any error from flushing or closing.
func (yp *YamlPrinter) CloseWriter() error {
	if yp.writer != nil && yp.writer != os.Stdout {
		return yp.writer.Close()
	}
	return nil
}
