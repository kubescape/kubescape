package printer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/anchore/clio"
	grypejson "github.com/anchore/grype/grype/presenter/json"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

const (
	jsonOutputFile = "report"
)

var _ printer.IPrinter = &JsonPrinter{}

type JsonPrinter struct {
	writer *os.File
}

func NewJsonPrinter() *JsonPrinter {
	return &JsonPrinter{}
}

func (jp *JsonPrinter) SetWriter(ctx context.Context, outputFile string) error {
	explicitOutput := outputFile != ""
	if outputFile != "" {
		if strings.TrimSpace(outputFile) == "" {
			outputFile = jsonOutputFile
		}
		if !printer.HasOutputExt(strings.TrimSpace(outputFile), printer.JsonOutputExt) {
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
	if opaSessionObj.Report.ReportGenerationTime.IsZero() {
		opaSessionObj.Report.ReportGenerationTime = time.Now().UTC()
	}
	if opaSessionObj.Report.ClusterName == "" {
		opaSessionObj.Report.ClusterName = cautils.AdoptClusterName(scanContextName(opaSessionObj))
	}
	if opaSessionObj.Report.ReportID == "" {
		opaSessionObj.Report.ReportID = opaSessionObj.SessionID
	}

	reportHeader := PostureReportWithSeverity{
		ReportGenerationTime: opaSessionObj.Report.ReportGenerationTime.Format("2006-01-02T15:04:05Z07:00"),
		ClusterAPIServerInfo: opaSessionObj.Report.ClusterAPIServerInfo,
		ClusterCloudProvider: opaSessionObj.Report.ClusterCloudProvider,
		CustomerGUID:         opaSessionObj.Report.CustomerGUID,
		ClusterName:          opaSessionObj.Report.ClusterName,
		ReportID:             opaSessionObj.Report.ReportID,
		SummaryDetails: SummaryDetailsWithSeverity{
			Controls:                  enrichControlsWithSeverity(opaSessionObj.Report.SummaryDetails.Controls),
			Status:                    opaSessionObj.Report.SummaryDetails.Status,
			Frameworks:                opaSessionObj.Report.SummaryDetails.Frameworks,
			ResourcesSeverityCounters: opaSessionObj.Report.SummaryDetails.ResourcesSeverityCounters,
			ControlsSeverityCounters:  opaSessionObj.Report.SummaryDetails.ControlsSeverityCounters,
			StatusCounters:            opaSessionObj.Report.SummaryDetails.StatusCounters,
			Vulnerabilities:           opaSessionObj.Report.SummaryDetails.Vulnerabilities,
			Score:                     opaSessionObj.Report.SummaryDetails.Score,
			ComplianceScore:           opaSessionObj.Report.SummaryDetails.ComplianceScore,
		},
		Attributes:     opaSessionObj.Report.Attributes,
		Metadata:       *opaSessionObj.Metadata,
		ExceptionAudit: opaSessionObj.ExceptionAudit,
	}

	if imageScanData != nil {
		imageScanSummary := buildMachineImageScanSummary(imageScanData)
		reportHeader.SummaryDetails.Vulnerabilities.MapsSeverityToSummary = convertToReportSummary(imageScanSummary.MapsSeverityToSummary)
		reportHeader.SummaryDetails.Vulnerabilities.CVESummary = convertToCVESummary(imageScanSummary.CVEs)
		reportHeader.SummaryDetails.Vulnerabilities.PackageScores = convertToPackageScores(imageScanSummary.PackageScores)
		reportHeader.SummaryDetails.Vulnerabilities.Images = imageScanSummary.Images
	}

	var scanCoverage *cautils.ScanCoverage
	coverage := &opaSessionObj.ScanCoverage
	if coverage != nil && (len(coverage.FailedGVRPulls) > 0 || len(coverage.NotEvaluatedControls) > 0 || len(coverage.PartialGVRPulls) > 0 || len(coverage.PolicyDegradations) > 0 || len(coverage.VacuousFrameworks) > 0) {
		scanCoverage = coverage
	}
	reportHeader.ScanCoverage = scanCoverage

	var resourceLabels map[string]map[string]string
	if len(opaSessionObj.LabelsToCopy) > 0 && opaSessionObj.AllResources != nil {
		resourceLabels = extractResourceLabels(opaSessionObj.AllResources, opaSessionObj.LabelsToCopy)
	}
	reportHeader.ResourceLabels = resourceLabels

	b, err := json.Marshal(reportHeader)
	if err != nil {
		return err
	}
	
	// Write header up to the closing brace
	// b is guaranteed to end with '}' because it's marshaled from a struct
	if len(b) > 0 && b[len(b)-1] == '}' {
		b = b[:len(b)-1]
	}
	if _, err := jp.writer.Write(b); err != nil {
		return err
	}

	encoder := json.NewEncoder(jp.writer)
	
	resourceIDs := make([]string, 0, len(opaSessionObj.ResourcesResult))
	for resourceID := range opaSessionObj.ResourcesResult {
		resourceIDs = append(resourceIDs, resourceID)
	}
	sort.Strings(resourceIDs)

	if len(resourceIDs) > 0 {
		// Write results incrementally
		if _, err := jp.writer.Write([]byte(`,"results":[`)); err != nil {
			return err
		}

		for i, resourceID := range resourceIDs {
			if i > 0 {
				if _, err := jp.writer.Write([]byte(`,`)); err != nil {
					return err
				}
			}
			res := opaSessionObj.ResourcesResult[resourceID]
			if v, exist := opaSessionObj.ResourcesPrioritized[resourceID]; exist {
				res.PrioritizedResource = &v
			}
			
			enrichedControls := make([]ResourceAssociatedControlWithSeverity, len(res.AssociatedControls))
			for j, control := range res.AssociatedControls {
				severity := "Unknown"
				if controlSummary, exists := reportHeader.SummaryDetails.Controls[control.GetID()]; exists {
					severity = apis.ControlSeverityToString(controlSummary.GetScoreFactor())
				}
				enrichedControls[j] = ResourceAssociatedControlWithSeverity{
					ResourceAssociatedControl: control,
					Severity:                  severity,
				}
			}
			enrichedResult := ResultWithSeverity{
				ResourceID:          res.ResourceID,
				AssociatedControls:  enrichedControls,
				PrioritizedResource: res.PrioritizedResource,
			}
			
			if err := encoder.Encode(enrichedResult); err != nil {
				return err
			}
		}
		if _, err := jp.writer.Write([]byte(`]`)); err != nil {
			return err
		}
	}

	// Write resources incrementally
	if !opaSessionObj.OmitRawResources && len(resourceIDs) > 0 {
		// Check if we actually have any resources in AllResources
		hasResources := false
		for _, resourceID := range resourceIDs {
			if _, ok := opaSessionObj.AllResources[resourceID]; ok {
				hasResources = true
				break
			}
		}

		if hasResources {
			if _, err := jp.writer.Write([]byte(`,"resources":[`)); err != nil {
				return err
			}
			first := true
			for _, resourceID := range resourceIDs {
				if obj, ok := opaSessionObj.AllResources[resourceID]; ok {
					resource := *reporthandling.NewResourceIMetadata(obj)
					if r, ok := opaSessionObj.ResourceSource[resourceID]; ok {
						resource.SetSource(&r)
					}
					if !first {
						if _, err := jp.writer.Write([]byte(`,`)); err != nil {
							return err
						}
					}
					first = false
					if err := encoder.Encode(resource); err != nil {
						return err
					}
				}
			}
			if _, err := jp.writer.Write([]byte(`]`)); err != nil {
				return err
			}
		}
	}

	// Close the JSON object
	if _, err := jp.writer.Write([]byte(`}`)); err != nil {
		return err
	}

	return nil
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
