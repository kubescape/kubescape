package printer

import (
	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/match"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

const indicator = "†"

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
