package containerscan

import "github.com/armosec/capacketsgo/cautils"

// ToFlatVulnerabilities - returnsgit p
func (scanresult *ScanResultReport) ToFlatVulnerabilities() []*ElasticContainerVulnerabilityResult {
	vuls := make([]*ElasticContainerVulnerabilityResult, 0)
	vul2indx := make(map[string]int, 0)
	for _, layer := range scanresult.Layers {
		for _, vul := range layer.Vulnerabilities {
			esLayer := ESLayer{LayerHash: layer.LayerHash, ParentLayerHash: layer.ParentLayerHash}
			if indx, isOk := vul2indx[vul.Name]; isOk {
				vuls[indx].Layers = append(vuls[indx].Layers, esLayer)
				continue
			}
			result := &ElasticContainerVulnerabilityResult{WLID: scanresult.WLID, Timestamp: scanresult.Timestamp}
			result.Vulnerability = vul
			result.Layers = make([]ESLayer, 0)
			result.Layers = append(result.Layers, esLayer)
			result.ContainerScanID = scanresult.AsSha256()

			result.IsFixed = CalculateFixed(vul.Fixes)
			result.RelevantLinks = append(result.RelevantLinks, "https://nvd.nist.gov/vuln/detail/"+vul.Name)
			result.RelevantLinks = append(result.RelevantLinks, vul.Link)
			result.Vulnerability.Link = "https://nvd.nist.gov/vuln/detail/" + vul.Name
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

func (scanresult *ScanResultReport) Summerize() *ElasticContainerScanSummaryResult {
	summary := &ElasticContainerScanSummaryResult{
		CustomerGUID:             scanresult.CustomerGUID,
		ImgTag:                   scanresult.ImgTag,
		ImgHash:                  scanresult.ImgHash,
		WLID:                     scanresult.WLID,
		Timestamp:                scanresult.Timestamp,
		ContainerName:            scanresult.ContainerName,
		ContainerScanID:          scanresult.AsSha256(),
		ListOfDangerousArtifcats: scanresult.ListOfDangerousArtifcats,
		RCESummary:               make(map[string]int64),
	}

	obj, e := cautils.SpiffeToSpiffeInfo(scanresult.WLID)

	if e == nil {
		summary.Cluster = obj.Level0
		summary.Namespace = obj.Level1
	}

	imageInfo, e2 := cautils.ImageTagToImageInfo(scanresult.ImgTag)
	if e2 == nil {
		summary.Registry = imageInfo.Registry
		summary.VersionImage = imageInfo.VersionImage
	}

	summary.PackagesName = make([]string, 0)

	summary.Severity = make([]string, 0)
	summary.Relevancy = make([]string, 0)
	summary.FixAvailble = make([]string, 0)

	summary.SeveritiesSum = make([]RelevanciesSum, 0)
	summary.RelevanciesSum = make([]RelevanciesSum, 0)
	summary.FixAvailbleSum = make([]RelevanciesSum, 0)

	uniqueVulsMap := make(map[string]bool, 0)
	for _, layer := range scanresult.Layers {
		summary.PackagesName = append(summary.PackagesName, (layer.GetPackagesNames())...)
		for _, vul := range layer.Vulnerabilities {

			if _, isOk := uniqueVulsMap[vul.Name]; isOk {
				continue
			}
			uniqueVulsMap[vul.Name] = true

			if vul.IsRCE() {
				summary.RCESummary[vul.Severity]++
			}

			switch vul.Relevancy {
			case Relevant:
				summary.NumOfRelevantIssues++
			case Irelevant:
				summary.NumOfIrelevantIssues++
			default: //includes unknown as well
				summary.NumOfUnknownIssues++
			}

			switch vul.Severity {
			case NegligibleSeverity:
				summary.NumOfNegligibleSeverity++
				if vul.Relevancy == Relevant {
					summary.NumOfRelevantNegligibleSeverity++
				}

				if CalculateFixed(vul.Fixes) > 0 {
					summary.NumOfFixAvailableNegligibleSeverity++
				}
			case LowSeverity:
				summary.NumOfLowSeverity++

				if vul.Relevancy == Relevant {
					summary.NumOfRelevantLowSeverity++
				}

				if CalculateFixed(vul.Fixes) > 0 {
					summary.NumOfFixAvailableLowSeverity++
				}
			case MediumSeverity:
				summary.NumOfMediumSeverity++

				if vul.Relevancy == Relevant {
					summary.NumOfRelevantMediumSeverity++
				}

				if CalculateFixed(vul.Fixes) > 0 {
					summary.NumOfFixAvailableMediumSeverity++
				}
			case HighSeverity:
				summary.NumOfHighSeverity++

				if vul.Relevancy == Relevant {
					summary.NumOfRelevantHighSeverity++
				}

				if CalculateFixed(vul.Fixes) > 0 {
					summary.NumOfFixAvailableHighSeverity++
				}
			case CriticalSeverity:
				summary.NumOfCriticalSeverity++

				if vul.Relevancy == Relevant {
					summary.NumOfRelevantCriticalSeverity++
				}

				if CalculateFixed(vul.Fixes) > 0 {
					summary.NumOfFixAvailableCriticalSeverity++
				}
			default: //includes unknown as well
				summary.NumOfUnknownSeverity++
				if vul.Relevancy == Relevant {
					summary.NumOfRelevantUnknownSeverity++
				}

				if CalculateFixed(vul.Fixes) > 0 {
					summary.NumOfFixAvailableUnknownSeverity++
				}
			}

		}
	}
	if summary.NumOfCriticalSeverity > 0 || summary.NumOfRelevantHighSeverity > 3 {
		summary.Status = "Fail"
	} else {
		summary.Status = "Success"
	}

	//Negligible
	if summary.NumOfNegligibleSeverity > 0 {
		summary.Severity = append(summary.Severity, "Negligible")
		summary.SeveritiesSum = append(summary.SeveritiesSum, RelevanciesSum{Relevancy: "Negligible", Sum: summary.NumOfNegligibleSeverity})

		if summary.NumOfRelevantNegligibleSeverity > 0 {
			summary.Relevancy = append(summary.Relevancy, "Negligible")
			summary.RelevanciesSum = append(summary.RelevanciesSum, RelevanciesSum{Relevancy: "Negligible", Sum: summary.NumOfRelevantNegligibleSeverity})
		}

		if summary.NumOfFixAvailableNegligibleSeverity > 0 {
			summary.FixAvailble = append(summary.FixAvailble, "Negligible")
			summary.FixAvailbleSum = append(summary.FixAvailbleSum, RelevanciesSum{Relevancy: "Negligible", Sum: summary.NumOfFixAvailableNegligibleSeverity})
		}
	}

	if summary.NumOfLowSeverity > 0 {
		summary.Severity = append(summary.Severity, "Low")
		summary.SeveritiesSum = append(summary.SeveritiesSum, RelevanciesSum{Relevancy: "Low", Sum: summary.NumOfLowSeverity})

		if summary.NumOfRelevantLowSeverity > 0 {
			summary.Relevancy = append(summary.Relevancy, "Low")
			summary.RelevanciesSum = append(summary.RelevanciesSum, RelevanciesSum{Relevancy: "Low", Sum: summary.NumOfRelevantLowSeverity})
		}

		if summary.NumOfFixAvailableLowSeverity > 0 {
			summary.FixAvailble = append(summary.FixAvailble, "Low")
			summary.FixAvailbleSum = append(summary.FixAvailbleSum, RelevanciesSum{Relevancy: "Low", Sum: summary.NumOfFixAvailableLowSeverity})
		}
	}

	if summary.NumOfMediumSeverity > 0 {
		summary.Severity = append(summary.Severity, "Medium")
		summary.SeveritiesSum = append(summary.SeveritiesSum, RelevanciesSum{Relevancy: "Medium", Sum: summary.NumOfMediumSeverity})

		if summary.NumOfRelevantMediumSeverity > 0 {
			summary.Relevancy = append(summary.Relevancy, "Medium")
			summary.RelevanciesSum = append(summary.RelevanciesSum, RelevanciesSum{Relevancy: "Medium", Sum: summary.NumOfRelevantMediumSeverity})
		}

		if summary.NumOfFixAvailableMediumSeverity > 0 {
			summary.FixAvailble = append(summary.FixAvailble, "Medium")
			summary.FixAvailbleSum = append(summary.FixAvailbleSum, RelevanciesSum{Relevancy: "Medium", Sum: summary.NumOfFixAvailableMediumSeverity})
		}
	}

	if summary.NumOfHighSeverity > 0 {
		summary.Severity = append(summary.Severity, "High")
		summary.SeveritiesSum = append(summary.SeveritiesSum, RelevanciesSum{Relevancy: "High", Sum: summary.NumOfHighSeverity})

		if summary.NumOfRelevantHighSeverity > 0 {
			summary.Relevancy = append(summary.Relevancy, "High")
			summary.RelevanciesSum = append(summary.RelevanciesSum, RelevanciesSum{Relevancy: "High", Sum: summary.NumOfRelevantHighSeverity})
		}

		if summary.NumOfFixAvailableHighSeverity > 0 {
			summary.FixAvailble = append(summary.FixAvailble, "High")
			summary.FixAvailbleSum = append(summary.FixAvailbleSum, RelevanciesSum{Relevancy: "High", Sum: summary.NumOfFixAvailableHighSeverity})
		}
	}

	if summary.NumOfCriticalSeverity > 0 {
		summary.Severity = append(summary.Severity, "Critical")
		summary.SeveritiesSum = append(summary.SeveritiesSum, RelevanciesSum{Relevancy: "Critical", Sum: summary.NumOfCriticalSeverity})

		if summary.NumOfRelevantCriticalSeverity > 0 {
			summary.Relevancy = append(summary.Relevancy, "Critical")
			summary.RelevanciesSum = append(summary.RelevanciesSum, RelevanciesSum{Relevancy: "Critical", Sum: summary.NumOfRelevantCriticalSeverity})
		}

		if summary.NumOfFixAvailableCriticalSeverity > 0 {
			summary.FixAvailble = append(summary.FixAvailble, "Critical")
			summary.FixAvailbleSum = append(summary.FixAvailbleSum, RelevanciesSum{Relevancy: "Critical", Sum: summary.NumOfFixAvailableCriticalSeverity})
		}
	}

	if summary.NumOfUnknownSeverity > 0 {
		summary.Severity = append(summary.Severity, "Unknown")
		summary.SeveritiesSum = append(summary.SeveritiesSum, RelevanciesSum{Relevancy: "Unknown", Sum: summary.NumOfUnknownSeverity})

		if summary.NumOfRelevantUnknownSeverity > 0 {
			summary.Relevancy = append(summary.Relevancy, "Unknown")
			summary.RelevanciesSum = append(summary.RelevanciesSum, RelevanciesSum{Relevancy: "Unknown", Sum: summary.NumOfRelevantUnknownSeverity})
		}

		if summary.NumOfFixAvailableUnknownSeverity > 0 {
			summary.FixAvailble = append(summary.FixAvailble, "Unknown")
			summary.FixAvailbleSum = append(summary.FixAvailbleSum, RelevanciesSum{Relevancy: "Unknown", Sum: summary.NumOfFixAvailableUnknownSeverity})
		}
	}

	return summary
}
