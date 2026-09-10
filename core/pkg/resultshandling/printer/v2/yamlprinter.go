package printer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

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
	outputFile, explicitOutput := printer.ResolveOutputFile(printer.YamlFormat, outputFile, yamlOutputFile)
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
		err = printImageScanningYaml(imageScanData, yp)
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

func printImageScanningYaml(imageScanData []cautils.ImageScanData, yp *YamlPrinter) error {
	if len(imageScanData) == 1 {
		var buf bytes.Buffer
		if err := presentImageScan(imageScanData[0], &buf); err != nil {
			return fmt.Errorf("failed to create document: %w", err)
		}
		yamlData, err := yaml.JSONToYAML(buf.Bytes())
		if err != nil {
			return fmt.Errorf("failed to convert json to yaml: %w", err)
		}
		_, err = yp.writer.Write(yamlData)
		return err
	}

	documents := make([]json.RawMessage, 0, len(imageScanData))
	for i := range imageScanData {
		var buf bytes.Buffer
		if err := presentImageScan(imageScanData[i], &buf); err != nil {
			return err
		}
		documents = append(documents, json.RawMessage(bytes.TrimSpace(buf.Bytes())))
	}

	encoded, err := json.MarshalIndent(documents, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal multi-image json output: %w", err)
	}

	yamlData, err := yaml.JSONToYAML(encoded)
	if err != nil {
		return fmt.Errorf("failed to convert multi-image json to yaml: %w", err)
	}

	_, err = yp.writer.Write(yamlData)
	return err
}

func printConfigurationsScanningYaml(opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData, yp *YamlPrinter) error {
	// Add combined-scan data to this renderer's finalized report. Mutating the
	// shared session here would also change the posture payload submitted after
	// local output has finished.
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
