package v1

import (
	"encoding/json"
	"fmt"

	"github.com/kubescape/kubescape/v2/core/pkg/containerscan"
	"github.com/kubescape/kubescape/v2/core/pkg/registryadaptors/registryvulnerabilities"
)

func (armoCivAdaptor *KSCivAdaptor) getImageLastScanId(imageID *registryvulnerabilities.ContainerImageIdentifier) (string, error) {
	filter := []map[string]string{{"imageTag": imageID.Tag, "status": "Success"}}
	pageSize := 1
	pageNumber := 1
	request := V2ListRequest{PageSize: &pageSize, PageNum: &pageNumber, InnerFilters: filter, OrderBy: "timestamp:desc"}
	requestBody, _ := json.Marshal(request)
	requestUrl := fmt.Sprintf("https://%s/api/v1/vulnerability/scanResultsSumSummary?customerGUID=%s", armoCivAdaptor.ksCloudAPI.GetCloudAPIURL(), armoCivAdaptor.ksCloudAPI.GetAccountID())

	resp, err := armoCivAdaptor.ksCloudAPI.Post(requestUrl, map[string]string{"Content-Type": "application/json"}, requestBody)
	if err != nil {
		return "", err
	}

	scanSummartResult := struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		Response []containerscan.ElasticContainerScanSummaryResult `json:"response"`
		Cursor   string                                            `json:"cursor"`
	}{}
	err = json.Unmarshal([]byte(resp), &scanSummartResult)
	if err != nil {
		return "", err
	}

	if len(scanSummartResult.Response) < pageSize {
		return "", fmt.Errorf("did not get response for image %s", imageID.Tag)
	}

	return scanSummartResult.Response[0].ContainerScanID, nil
}

func responseObjectToVulnerabilities(vulnerabilitiesList containerscan.VulnerabilitiesList) []registryvulnerabilities.Vulnerability {
	vulnerabilities := make([]registryvulnerabilities.Vulnerability, len(vulnerabilitiesList))
	for i, vulnerabilityEntry := range vulnerabilitiesList {
		vulnerabilities[i].Description = vulnerabilityEntry.Description
		vulnerabilities[i].Fixes = make([]registryvulnerabilities.FixedIn, len(vulnerabilityEntry.Fixes))
		for j, fix := range vulnerabilityEntry.Fixes {
			vulnerabilities[i].Fixes[j].ImgTag = fix.ImgTag
			vulnerabilities[i].Fixes[j].Name = fix.Name
			vulnerabilities[i].Fixes[j].Version = fix.Version
		}
		vulnerabilities[i].HealthStatus = vulnerabilityEntry.HealthStatus
		vulnerabilities[i].Link = vulnerabilityEntry.Link
		vulnerabilities[i].Metadata = vulnerabilityEntry.Metadata
		vulnerabilities[i].Name = vulnerabilityEntry.Name
		vulnerabilities[i].PackageVersion = vulnerabilityEntry.PackageVersion
		vulnerabilities[i].RelatedPackageName = vulnerabilityEntry.RelatedPackageName
		vulnerabilities[i].Relevancy = vulnerabilityEntry.Relevancy
		vulnerabilities[i].Severity = vulnerabilityEntry.Severity
		vulnerabilities[i].UrgentCount = vulnerabilityEntry.UrgentCount
		vulnerabilities[i].Categories = registryvulnerabilities.Categories{
			IsRCE: vulnerabilityEntry.Categories.IsRCE,
		}
	}
	return vulnerabilities
}
