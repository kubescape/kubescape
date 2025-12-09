package printer

import (
	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/match"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

const indicator = "†"

// ControlSummaryWithSeverity wraps ControlSummary to add severity field for JSON output
type ControlSummaryWithSeverity struct {
	reportsummary.ControlSummary
	Severity string `json:"severity"`
}

// ResourceAssociatedControlWithSeverity wraps ResourceAssociatedControl to add severity field
type ResourceAssociatedControlWithSeverity struct {
	resourcesresults.ResourceAssociatedControl
	Severity string `json:"severity"`
}

// ResultWithSeverity wraps Result to include severity in associated controls
type ResultWithSeverity struct {
	ResourceID          string                                  `json:"resourceID"`
	AssociatedControls  []ResourceAssociatedControlWithSeverity `json:"controls,omitempty"`
	PrioritizedResource *prioritization.PrioritizedResource     `json:"prioritizedResource,omitempty"`
}

// SummaryDetailsWithSeverity wraps SummaryDetails to include enriched controls
type SummaryDetailsWithSeverity struct {
	Controls                  map[string]ControlSummaryWithSeverity `json:"controls,omitempty"`
	Status                    apis.ScanningStatus                   `json:"status"`
	Frameworks                []reportsummary.FrameworkSummary      `json:"frameworks"`
	ResourcesSeverityCounters reportsummary.SeverityCounters        `json:"resourcesSeverityCounters,omitempty"`
	ControlsSeverityCounters  reportsummary.SeverityCounters        `json:"controlsSeverityCounters,omitempty"`
	StatusCounters            reportsummary.StatusCounters          `json:"ResourceCounters"`
	Vulnerabilities           reportsummary.VulnerabilitySummary    `json:"vulnerabilities,omitempty"`
	Score                     float32                               `json:"score"`
	ComplianceScore           float32                               `json:"complianceScore"`
}

// PostureReportWithSeverity wraps PostureReport to include severity in controls
type PostureReportWithSeverity struct {
	ReportGenerationTime string                            `json:"generationTime"`
	ClusterAPIServerInfo interface{}                       `json:"clusterAPIServerInfo"`
	ClusterCloudProvider string                            `json:"clusterCloudProvider"`
	CustomerGUID         string                            `json:"customerGUID"`
	ClusterName          string                            `json:"clusterName"`
	SummaryDetails       SummaryDetailsWithSeverity        `json:"summaryDetails,omitempty"`
	Resources            []reporthandling.Resource         `json:"resources,omitempty"`
	Attributes           []reportsummary.PostureAttributes `json:"attributes"`
	Results              []ResultWithSeverity              `json:"results,omitempty"`
	Metadata             reporthandlingv2.Metadata         `json:"metadata,omitempty"`
}

// enrichControlsWithSeverity adds severity field to controls based on scoreFactor
func enrichControlsWithSeverity(controls reportsummary.ControlSummaries) map[string]ControlSummaryWithSeverity {
	enrichedControls := make(map[string]ControlSummaryWithSeverity)
	for controlID, control := range controls {
		enrichedControl := ControlSummaryWithSeverity{
			ControlSummary: control,
			Severity:       apis.ControlSeverityToString(control.GetScoreFactor()),
		}
		enrichedControls[controlID] = enrichedControl
	}
	return enrichedControls
}

// enrichResultsWithSeverity adds severity field to controls in results
func enrichResultsWithSeverity(results []resourcesresults.Result, controlSummaries reportsummary.ControlSummaries) []ResultWithSeverity {
	enrichedResults := make([]ResultWithSeverity, len(results))
	for i, result := range results {
		enrichedControls := make([]ResourceAssociatedControlWithSeverity, len(result.AssociatedControls))
		for j, control := range result.AssociatedControls {
			// Get the severity from the control summary
			severity := "Unknown"
			if controlSummary, exists := controlSummaries[control.GetID()]; exists {
				severity = apis.ControlSeverityToString(controlSummary.GetScoreFactor())
			}
			enrichedControls[j] = ResourceAssociatedControlWithSeverity{
				ResourceAssociatedControl: control,
				Severity:                  severity,
			}
		}
		enrichedResults[i] = ResultWithSeverity{
			ResourceID:          result.ResourceID,
			AssociatedControls:  enrichedControls,
			PrioritizedResource: result.PrioritizedResource,
		}
	}
	return enrichedResults
}

// ConvertToPostureReportWithSeverity converts PostureReport to PostureReportWithSeverity
func ConvertToPostureReportWithSeverity(report *reporthandlingv2.PostureReport) *PostureReportWithSeverity {
	if report == nil {
		return nil
	}
	enrichedControls := enrichControlsWithSeverity(report.SummaryDetails.Controls)
	enrichedResults := enrichResultsWithSeverity(report.Results, report.SummaryDetails.Controls)

	return &PostureReportWithSeverity{
		ReportGenerationTime: report.ReportGenerationTime.Format("2006-01-02T15:04:05Z07:00"),
		ClusterAPIServerInfo: report.ClusterAPIServerInfo,
		ClusterCloudProvider: report.ClusterCloudProvider,
		CustomerGUID:         report.CustomerGUID,
		ClusterName:          report.ClusterName,
		SummaryDetails: SummaryDetailsWithSeverity{
			Controls:                  enrichedControls,
			Status:                    report.SummaryDetails.Status,
			Frameworks:                report.SummaryDetails.Frameworks,
			ResourcesSeverityCounters: report.SummaryDetails.ResourcesSeverityCounters,
			ControlsSeverityCounters:  report.SummaryDetails.ControlsSeverityCounters,
			StatusCounters:            report.SummaryDetails.StatusCounters,
			Vulnerabilities:           report.SummaryDetails.Vulnerabilities,
			Score:                     report.SummaryDetails.Score,
			ComplianceScore:           report.SummaryDetails.ComplianceScore,
		},
		Resources:  report.Resources,
		Attributes: report.Attributes,
		Results:    enrichedResults,
		Metadata:   report.Metadata,
	}
}

// FinalizeResults finalize the results objects by copying data from map to lists
func FinalizeResults(data *cautils.OPASessionObj) *reporthandlingv2.PostureReport {
	report := reporthandlingv2.PostureReport{
		SummaryDetails:       data.Report.SummaryDetails,
		Metadata:             *data.Metadata,
		ClusterAPIServerInfo: data.Report.ClusterAPIServerInfo,
		ReportGenerationTime: data.Report.ReportGenerationTime,
		Attributes:           data.Report.Attributes,
		ClusterName:          data.Report.ClusterName,
		CustomerGUID:         data.Report.CustomerGUID,
		ClusterCloudProvider: data.Report.ClusterCloudProvider,
	}

	report.Results = make([]resourcesresults.Result, len(data.ResourcesResult))
	finalizeResults(report.Results, data.ResourcesResult, data.ResourcesPrioritized)

	if !data.OmitRawResources {
		report.Resources = finalizeResources(report.Results, data.AllResources, data.ResourceSource)
	}

	return &report
}
func finalizeResults(results []resourcesresults.Result, resourcesResult map[string]resourcesresults.Result, prioritizedResources map[string]prioritization.PrioritizedResource) {
	index := 0
	for resourceID := range resourcesResult {
		results[index] = resourcesResult[resourceID]

		// Add prioritization information to the result
		if v, exist := prioritizedResources[resourceID]; exist {
			results[index].PrioritizedResource = &v
		}
		index++
	}
}

type infoStars struct {
	stars string
	info  string
}

func mapInfoToPrintInfo(controls reportsummary.ControlSummaries) []infoStars {
	infoToPrintInfo := []infoStars{}
	infoToPrintInfoMap := map[string]interface{}{}
	starCount := indicator
	for _, control := range controls {
		if control.GetStatus().IsSkipped() && control.GetStatus().Info() != "" {
			if _, ok := infoToPrintInfoMap[control.GetStatus().Info()]; !ok {
				infoToPrintInfo = append(infoToPrintInfo, infoStars{
					info:  control.GetStatus().Info(),
					stars: starCount,
				})
				starCount += indicator
				infoToPrintInfoMap[control.GetStatus().Info()] = nil
			}
		}
	}
	return infoToPrintInfo
}

func finalizeResources(results []resourcesresults.Result, allResources map[string]workloadinterface.IMetadata, resourcesSource map[string]reporthandling.Source) []reporthandling.Resource {
	resources := make([]reporthandling.Resource, 0)
	for i := range results {
		if obj, ok := allResources[results[i].ResourceID]; ok {
			resource := *reporthandling.NewResourceIMetadata(obj)
			if r, ok := resourcesSource[results[i].ResourceID]; ok {
				resource.SetSource(&r)
			}
			resources = append(resources, resource)
		}
	}
	return resources
}

func setSeverityToSummaryMap(cves []imageprinter.CVE, mapSeverityToSummary map[string]*imageprinter.SeveritySummary) {
	for _, cve := range cves {
		if _, ok := mapSeverityToSummary[cve.Severity]; !ok {
			mapSeverityToSummary[cve.Severity] = &imageprinter.SeveritySummary{}
		}

		mapSeverityToSummary[cve.Severity].NumberOfCVEs += 1

		if cve.FixedState == string(v5.FixedState) {
			mapSeverityToSummary[cve.Severity].NumberOfFixableCVEs = mapSeverityToSummary[cve.Severity].NumberOfFixableCVEs + 1
		}
	}
}

func setPkgNameToScoreMap(matches match.Matches, pkgScores map[string]*imageprinter.PackageScore) {
	for _, m := range matches.Sorted() {
		// key is pkg name + version to avoid version conflicts
		key := m.Package.Name + m.Package.Version

		if _, ok := pkgScores[key]; !ok {
			pkgScores[key] = &imageprinter.PackageScore{
				Version:                 m.Package.Version,
				Name:                    m.Package.Name,
				MapSeverityToCVEsNumber: make(map[string]int, 0),
			}
		}

		if _, ok := pkgScores[key].MapSeverityToCVEsNumber[m.Vulnerability.Metadata.Severity]; !ok {
			pkgScores[key].MapSeverityToCVEsNumber[m.Vulnerability.Metadata.Severity] = 1
		} else {
			pkgScores[key].MapSeverityToCVEsNumber[m.Vulnerability.Metadata.Severity] += 1
		}

		pkgScores[key].Score += utils.ImageSeverityToInt(m.Vulnerability.Metadata.Severity)
	}
}

func extractCVEs(matches match.Matches) []imageprinter.CVE {
	var CVEs []imageprinter.CVE
	for _, m := range matches.Sorted() {
		cve := imageprinter.CVE{
			ID:          m.Vulnerability.Metadata.ID,
			Severity:    m.Vulnerability.Metadata.Severity,
			Package:     m.Package.Name,
			Version:     m.Package.Version,
			FixVersions: m.Vulnerability.Fix.Versions,
			FixedState:  m.Vulnerability.Fix.State.String(),
		}
		CVEs = append(CVEs, cve)
	}
	return CVEs
}
