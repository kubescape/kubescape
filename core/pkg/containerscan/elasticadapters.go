package containerscan

import (
	"github.com/armosec/armoapi-go/armotypes"
	cautils "github.com/armosec/utils-k8s-go/armometadata"
)

// ToFlatVulnerabilities - returnsgit p
func (scanresult *ScanResultReport) ToFlatVulnerabilities() []*ElasticContainerVulnerabilityResult {
	vuls := make([]*ElasticContainerVulnerabilityResult, 0)
	vul2indx := make(map[string]int)
	scanID := scanresult.AsFNVHash()
	designatorsObj, ctxList := scanresult.GetDesignatorsNContext()
	for _, layer := range scanresult.Layers {
		for _, vul := range layer.Vulnerabilities {
			esLayer := ESLayer{LayerHash: layer.LayerHash, ParentLayerHash: layer.ParentLayerHash}
			if indx, isOk := vul2indx[vul.Name]; isOk {
				vuls[indx].Layers = append(vuls[indx].Layers, esLayer)
				continue
			}
			result := &ElasticContainerVulnerabilityResult{WLID: scanresult.WLID,
				Timestamp:   scanresult.Timestamp,
				Designators: *designatorsObj,
				Context:     ctxList}

			result.Vulnerability = vul
			result.Layers = make([]ESLayer, 0)
			result.Layers = append(result.Layers, esLayer)
			result.ContainerScanID = scanID

			result.IsFixed = CalculateFixed(vul.Fixes)
			result.RelevantLinks = append(result.RelevantLinks, "https://nvd.nist.gov/vuln/detail/"+vul.Name)
			result.RelevantLinks = append(result.RelevantLinks, vul.Link)
			result.Vulnerability.Link = "https://nvd.nist.gov/vuln/detail/" + vul.Name

			result.Categories.IsRCE = result.IsRCE()
			vuls = append(vuls, result)
			vul2indx[vul.Name] = len(vuls) - 1

		}
	}
	// find first introduced
	for i, v := range vuls {
		earlyLayer := ""
		for _, layer := range v.Layers {
			if layer.ParentLayerHash == earlyLayer {
				earlyLayer = layer.LayerHash
			}
		}
		vuls[i].IntroducedInLayer = earlyLayer

	}

	return vuls
}

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

	summary.Cluster = designatorsObj.Attributes[armotypes.AttributeCluster]
	summary.Namespace = designatorsObj.Attributes[armotypes.AttributeNamespace]

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
