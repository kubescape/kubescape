package printer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
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
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
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
	outputFile, explicitOutput := printer.ResolveOutputFile(printer.JsonFormat, outputFile, jsonOutputFile)
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
		err = printImageScanning(imageScanData, jp)
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

// printImageScanning keeps grype's bare document shape for a single image and
// wraps several in an array, as the CycloneDX and SPDX printers already do.
func printImageScanning(imageScanData []cautils.ImageScanData, jp *JsonPrinter) error {
	if len(imageScanData) == 1 {
		return presentImageScan(imageScanData[0], jp.writer)
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
	_, err = jp.writer.Write(append(encoded, '\n'))
	return err
}

func presentImageScan(imageScanData cautils.ImageScanData, w io.Writer) error {
	model, err := models.NewDocument(clio.Identification{}, imageScanData.Packages, imageScanData.Context,
		imageScanData.Matches, imageScanData.IgnoredMatches, imageScanData.VulnerabilityProvider, nil, nil, models.DefaultSortStrategy, false)
	if err != nil {
		return fmt.Errorf("failed to create document: %w", err)
	}
	return grypejson.NewPresenter(models.PresenterConfig{Document: model, SBOM: imageScanData.SBOM}).Present(w)
}

func printConfigurationsScanning(opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData, jp *JsonPrinter) error {
	return writeConfigurationJSON(jp.writer, opaSessionObj, imageScanData)
}

func writeConfigurationJSON(w io.Writer, opaSessionObj *cautils.OPASessionObj, imageScanData []cautils.ImageScanData) error {
	// Finalize only the header on a local value. FinalizeResults would allocate
	// complete result/resource slices and sort shared controls in place.
	finalizedReport := *opaSessionObj.Report
	finalizedReport.Results = nil
	finalizedReport.Resources = nil
	finalizedReport.Metadata = reporthandlingv2.Metadata{}
	if opaSessionObj.Metadata != nil {
		finalizedReport.Metadata = *opaSessionObj.Metadata
	}
	if finalizedReport.ReportGenerationTime.IsZero() {
		finalizedReport.ReportGenerationTime = time.Now().UTC()
	}
	if finalizedReport.ClusterName == "" {
		finalizedReport.ClusterName = cautils.AdoptClusterName(scanContextName(opaSessionObj))
	}
	if finalizedReport.ReportID == "" {
		finalizedReport.ReportID = opaSessionObj.SessionID
	}

	if imageScanData != nil {
		imageScanSummary := buildMachineImageScanSummary(imageScanData)
		finalizedReport.SummaryDetails.Vulnerabilities.MapsSeverityToSummary = convertToReportSummary(imageScanSummary.MapsSeverityToSummary)
		finalizedReport.SummaryDetails.Vulnerabilities.CVESummary = convertToCVESummary(imageScanSummary.CVEs)
		finalizedReport.SummaryDetails.Vulnerabilities.PackageScores = convertToPackageScores(imageScanSummary.PackageScores)
		finalizedReport.SummaryDetails.Vulnerabilities.Images = imageScanSummary.Images
	}

	// Reuse the established header schema and coverage predicate, without
	// constructing any of the three resource-sized output collections.
	header := ConvertToPostureReportWithSeverityLabelsAndCoverage(&finalizedReport, nil, nil, &opaSessionObj.ScanCoverage)
	s := newJSONStream(w)
	s.raw("{")
	first := true
	s.field(&first, "generationTime", header.ReportGenerationTime)
	s.field(&first, "clusterAPIServerInfo", header.ClusterAPIServerInfo)
	s.field(&first, "clusterCloudProvider", header.ClusterCloudProvider)
	s.field(&first, "customerGUID", header.CustomerGUID)
	s.field(&first, "clusterName", header.ClusterName)
	s.field(&first, "reportGUID", header.ReportID)
	s.field(&first, "summaryDetails", header.SummaryDetails)
	s.field(&first, "attributes", header.Attributes)
	s.field(&first, "metadata", header.Metadata)
	if header.ScanCoverage != nil {
		s.field(&first, "scanCoverage", header.ScanCoverage)
	}
	if opaSessionObj.ExceptionAudit != nil {
		s.field(&first, "exceptionAudit", opaSessionObj.ExceptionAudit)
	}
	if len(opaSessionObj.NamespaceSummaries) > 0 {
		s.field(&first, "namespaceSummaries", opaSessionObj.NamespaceSummaries)
	}
	if s.err != nil {
		return s.err
	}

	resourceIDs := make([]string, 0, len(opaSessionObj.ResourcesResult))
	for id := range opaSessionObj.ResourcesResult {
		resourceIDs = append(resourceIDs, id)
	}
	sort.Strings(resourceIDs)
	if len(resourceIDs) > 0 {
		s.key(&first, "results")
		s.raw("[")
		firstResult := true
		for _, id := range resourceIDs {
			if s.err != nil {
				return s.err
			}
			result := opaSessionObj.ResourcesResult[id]
			if prioritized, ok := opaSessionObj.ResourcesPrioritized[id]; ok {
				result.PrioritizedResource = &prioritized
			}
			enriched := enrichResultWithSeverity(result, opaSessionObj.Report.SummaryDetails.Controls, opaSessionObj.AllResources[result.ResourceID])
			slices.SortFunc(enriched.AssociatedControls, func(a, b ResourceAssociatedControlWithSeverity) int {
				return strings.Compare(a.ControlID, b.ControlID)
			})
			s.separator(&firstResult)
			s.value(enriched)
		}
		s.raw("]")
	}
	if !opaSessionObj.OmitRawResources {
		firstResource := true
		for _, id := range resourceIDs {
			if s.err != nil {
				return s.err
			}
			result := opaSessionObj.ResourcesResult[id]
			obj, ok := opaSessionObj.AllResources[result.ResourceID]
			if !ok {
				continue
			}
			if firstResource {
				s.key(&first, "resources")
				s.raw("[")
			}
			resource := reporthandling.NewResourceIMetadata(obj)
			if source, ok := opaSessionObj.ResourceSource[result.ResourceID]; ok {
				resource.SetSource(&source)
			}
			s.separator(&firstResource)
			s.value(resource)
		}
		if !firstResource {
			s.raw("]")
		}
	}
	if len(opaSessionObj.LabelsToCopy) > 0 && s.err == nil {
		// Labels apply to all resources, including those without a result.
		ids := make([]string, 0, len(opaSessionObj.AllResources))
		for id := range opaSessionObj.AllResources {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		firstLabels := true
		for _, id := range ids {
			if s.err != nil {
				return s.err
			}
			labels := extractResourceLabelsForResource(opaSessionObj.AllResources[id], opaSessionObj.LabelsToCopy)
			if len(labels) == 0 {
				continue
			}
			if firstLabels {
				s.key(&first, "resourceLabels")
				s.raw("{")
			}
			s.field(&firstLabels, id, labels)
		}
		if !firstLabels {
			s.raw("}")
		}
	}
	s.raw("}\n")
	return s.err
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
