package printer

import (
	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

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
	starCount := "*"
	for _, control := range controls {
		if control.GetStatus().IsSkipped() && control.GetStatus().Info() != "" {
			if _, ok := infoToPrintInfoMap[control.GetStatus().Info()]; !ok {
				infoToPrintInfo = append(infoToPrintInfo, infoStars{
					info:  control.GetStatus().Info(),
					stars: starCount,
				})
				starCount += "*"
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

func insertSeveritiesSummariesIntoMap(mapSeverityToSummary map[string]*imageprinter.SeveritySummary, imageScanSummary imageprinter.ImageScanSummary) {
	for k, v := range mapSeverityToSummary {
		severitySummary, ok := imageScanSummary.MapsSeverityToSummary[k]
		if !ok {
			imageScanSummary.MapsSeverityToSummary[k] = v
			continue
		}
		severitySummary.NumberOfCVEs = severitySummary.NumberOfCVEs + v.NumberOfCVEs
		severitySummary.NumberOfFixableCVEs = severitySummary.NumberOfFixableCVEs + v.NumberOfFixableCVEs
		imageScanSummary.MapsSeverityToSummary[k] = severitySummary
	}
}

func insertPackageScoresIntoMap(mapPackageNameToScore map[string]*imageprinter.PackageScore, imageScanSummary imageprinter.ImageScanSummary) {
	for k, v := range mapPackageNameToScore {
		pkgScore, ok := imageScanSummary.PackageScores[k]
		if !ok {
			imageScanSummary.PackageScores[k] = v
			continue
		}
		pkgScore.Score = pkgScore.Score + v.Score
		imageScanSummary.PackageScores[k] = pkgScore
	}
}

func extractSeverityToSummaryMap(cves []imageprinter.CVE) map[string]*imageprinter.SeveritySummary {
	mapSeverityToSummary := map[string]*imageprinter.SeveritySummary{}
	for _, cve := range cves {
		if _, ok := mapSeverityToSummary[cve.Severity]; !ok {
			mapSeverityToSummary[cve.Severity] = &imageprinter.SeveritySummary{}
		}
		mapSeverityToSummary[cve.Severity].NumberOfCVEs = mapSeverityToSummary[cve.Severity].NumberOfCVEs + 1
		if cve.FixedState == string(v5.FixedState) {
			mapSeverityToSummary[cve.Severity].NumberOfFixableCVEs = mapSeverityToSummary[cve.Severity].NumberOfFixableCVEs + 1
		}
	}
	return mapSeverityToSummary
}

func extractPkgNameToScore(doc models.Document) map[string]*imageprinter.PackageScore {
	mapPackageNameToScore := make(map[string]*imageprinter.PackageScore, 0)
	for _, cve := range doc.Matches {
		if _, ok := mapPackageNameToScore[cve.Artifact.Name]; !ok {
			mapPackageNameToScore[cve.Artifact.Name] = &imageprinter.PackageScore{
				Score: 0,
			}
		}
		mapPackageNameToScore[cve.Artifact.Name].Score = mapPackageNameToScore[cve.Artifact.Name].Score + utils.ImageSeverityToInt(cve.Vulnerability.Severity)
		mapPackageNameToScore[cve.Artifact.Name].Version = cve.Artifact.Version
	}
	return mapPackageNameToScore
}

func extractCVEs(doc models.Document) []imageprinter.CVE {
	cves := []imageprinter.CVE{}
	for _, match := range doc.Matches {
		cve := imageprinter.CVE{
			ID:          match.Vulnerability.ID,
			Severity:    match.Vulnerability.Severity,
			Package:     match.Artifact.Name,
			Version:     match.Artifact.Version,
			FixVersions: match.Vulnerability.Fix.Versions,
			FixedState:  match.Vulnerability.Fix.State,
		}
		cves = append(cves, cve)
	}
	return cves
}
