package containerscan

import (
	"github.com/armosec/armoapi-go/identifiers"
	cautils "github.com/armosec/utils-k8s-go/armometadata"
)

// Summarize generates a summary of the scan result report.
func (scanresult *ScanResultReport) Summarize() *ElasticContainerScanSummaryResult {
	designatorsObj, ctxList := scanresult.GetDesignatorsNContext()
	summary := &ElasticContainerScanSummaryResult{
		Designators:              *designatorsObj,
		Context:                  ctxList,
		CustomerGUID:             scanresult.CustomerGUID,
		ImgTag:                   scanresult.ImgTag,
		ImgHash:                  scanresult.ImgHash,
		WLID:                     scanresult.WLID,
		Timestamp:                scanresult.Timestamp,
		ContainerName:            scanresult.ContainerName,
		ContainerScanID:          scanresult.AsFNVHash(),
		ListOfDangerousArtifcats: scanresult.ListOfDangerousArtifcats,
	}

	summary.Cluster = designatorsObj.Attributes[identifiers.AttributeCluster]
	summary.Namespace = designatorsObj.Attributes[identifiers.AttributeNamespace]

	imageInfo, e2 := cautils.ImageTagToImageInfo(scanresult.ImgTag)
	if e2 == nil {
		summary.Registry = imageInfo.Registry
		summary.VersionImage = imageInfo.VersionImage
	}

	summary.PackagesName = make([]string, 0)

	severitiesStats := map[string]SeverityStats{}

	uniqueVulsMap := make(map[string]bool)
	for _, layer := range scanresult.Layers {
		summary.PackagesName = append(summary.PackagesName, (layer.GetPackagesNames())...)
		for _, vul := range layer.Vulnerabilities {
			if _, isOk := uniqueVulsMap[vul.Name]; isOk {
				continue
			}
			uniqueVulsMap[vul.Name] = true

			// TODO: maybe add all severities just to have a placeholders
			if !KnownSeverities[vul.Severity] {
				vul.Severity = UnknownSeverity
			}

			vulnSeverityStats, ok := severitiesStats[vul.Severity]
			if !ok {
				vulnSeverityStats = SeverityStats{Severity: vul.Severity}
			}

			vulnSeverityStats.TotalCount++
			summary.TotalCount++
			isFixed := CalculateFixed(vul.Fixes) > 0
			if isFixed {
				vulnSeverityStats.FixAvailableOfTotalCount++
				summary.FixAvailableOfTotalCount++
			}
			isRCE := vul.IsRCE()
			if isRCE {
				vulnSeverityStats.RCECount++
				summary.RCECount++
			}
			if vul.Relevancy == Relevant {
				vulnSeverityStats.RelevantCount++
				summary.RelevantCount++
				if isFixed {
					vulnSeverityStats.FixAvailableForRelevantCount++
					summary.FixAvailableForRelevantCount++
				}

			}
			severitiesStats[vul.Severity] = vulnSeverityStats
		}
	}
	summary.Status = "Success"

	// if criticalStats, hasCritical := severitiesStats[CriticalSeverity]; hasCritical && criticalStats.TotalCount > 0 {
	// 	summary.Status = "Fail"
	// }
	// if highStats, hasHigh := severitiesStats[HighSeverity]; hasHigh && highStats.RelevantCount > 0 {
	// 	summary.Status = "Fail"
	// }

	for sever := range severitiesStats {
		summary.SeveritiesStats = append(summary.SeveritiesStats, severitiesStats[sever])
	}
	return summary
}
