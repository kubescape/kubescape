package printer

import (
	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/presenter/models"
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

// finalizeV2Report finalize the results objects by copying data from map to lists
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

func setPkgNameToScoreMap(matches []models.Match, pkgScores map[string]*imageprinter.PackageScore) {
	for i := range matches {
		// key is pkg name + version to avoid version conflicts
		key := matches[i].Artifact.Name + matches[i].Artifact.Version

		if _, ok := pkgScores[key]; !ok {
			pkgScores[key] = &imageprinter.PackageScore{
				Version:                 matches[i].Artifact.Version,
				Name:                    matches[i].Artifact.Name,
				MapSeverityToCVEsNumber: make(map[string]int, 0),
			}
		}

		if _, ok := pkgScores[key].MapSeverityToCVEsNumber[matches[i].Vulnerability.Severity]; !ok {
			pkgScores[key].MapSeverityToCVEsNumber[matches[i].Vulnerability.Severity] = 1
		} else {
			pkgScores[key].MapSeverityToCVEsNumber[matches[i].Vulnerability.Severity] += 1
		}

		pkgScores[key].Score += utils.ImageSeverityToInt(matches[i].Vulnerability.Severity)
	}
}

func extractCVEs(matches []models.Match) []imageprinter.CVE {
	CVEs := []imageprinter.CVE{}
	for i := range matches {
		cve := imageprinter.CVE{
			ID:          matches[i].Vulnerability.ID,
			Severity:    matches[i].Vulnerability.Severity,
			Package:     matches[i].Artifact.Name,
			Version:     matches[i].Artifact.Version,
			FixVersions: matches[i].Vulnerability.Fix.Versions,
			FixedState:  matches[i].Vulnerability.Fix.State,
		}
		CVEs = append(CVEs, cve)
	}
	return CVEs
}
