package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/armosec/kubescape/containerscan"
	"github.com/armosec/kubescape/registryadaptors/registryvulnerabilities"
)

func NewArmoAdaptor(registry string, credentials map[string]string) (*ArmoCivAdaptor, error) {
	var accountId string
	var accessKey string
	var clientId string
	var ok bool
	if accountId, ok = credentials["accountId"]; !ok {
		return nil, fmt.Errorf("define accountId in credentials")
	}
	if clientId, ok = credentials["clientId"]; !ok {
		return nil, fmt.Errorf("define clientId in credentials")
	}
	if accessKey, ok = credentials["accessKey"]; !ok {
		return nil, fmt.Errorf("define accessKey in credentials")
	}
	armoCivAdaptor := ArmoCivAdaptor{registry: registry, accountId: accountId, clientId: clientId, accessKey: accessKey}
	err := armoCivAdaptor.initializeUrls()
	if err != nil {
		return nil, err
	}
	return &armoCivAdaptor, nil
}

func (armoCivAdaptor *ArmoCivAdaptor) Login() error {
	feLoginData := FeLoginData{ClientId: armoCivAdaptor.clientId, Secret: armoCivAdaptor.accessKey}
	body, _ := json.Marshal(feLoginData)

	authApiTokenEndpoint := fmt.Sprintf("%s/frontegg/identity/resources/auth/v1/api-token", armoCivAdaptor.armoUrls.AuthUrl)
	resp, err := http.Post(authApiTokenEndpoint, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error authenticating: %d", resp.StatusCode)
	}

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var feLoginResponse FeLoginResponse
	err = json.Unmarshal(responseBody, &feLoginResponse)
	armoCivAdaptor.feToken = feLoginResponse
	if err != nil {
		return err
	}
	/* Now we have JWT */

	armoCivAdaptor.authCookie, err = armoCivAdaptor.getAuthCookie()
	if err != nil {
		return err
	}

	return nil
}
func (armoCivAdaptor *ArmoCivAdaptor) GetImagesVulnerabilities(imageIDs []registryvulnerabilities.ContainerImageIdentifier) ([]registryvulnerabilities.ContainerImageVulnerabilityReport, error) {
	resultList := make([]registryvulnerabilities.ContainerImageVulnerabilityReport, 0)
	for _, imageID := range imageIDs {
		result, err := armoCivAdaptor.GetImageVulnerability(&imageID)
		if err == nil {
			resultList = append(resultList, *result)
		}
	}
	return resultList, nil
}

func (armoCivAdaptor *ArmoCivAdaptor) GetImageVulnerability(imageID *registryvulnerabilities.ContainerImageIdentifier) (*registryvulnerabilities.ContainerImageVulnerabilityReport, error) {
	// First
	containerScanId, err := armoCivAdaptor.getImageLastScanId(imageID)
	if err != nil {
		return nil, err
	}
	filter := []map[string]string{{"containersScanID": containerScanId}}
	pageSize := 300
	pageNumber := 1
	request := V2ListRequest{PageSize: &pageSize, PageNum: &pageNumber, InnerFilters: filter, OrderBy: "timestamp:desc"}
	requestBody, _ := json.Marshal(request)
	requestUrl := fmt.Sprintf("%s/api/v1/vulnerability/scanResultsDetails?customerGUID=%s", armoCivAdaptor.armoUrls.BackendUrl, armoCivAdaptor.accountId)
	client := &http.Client{}
	httpRequest, err := http.NewRequest("POST", requestUrl, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", armoCivAdaptor.feToken.Token))
	httpRequest.Header.Set("Cookie", fmt.Sprintf("auth=%s", armoCivAdaptor.authCookie))
	resp, err := client.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error requests %s with %d", requestUrl, resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	scanDetailsResult := struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		Response containerscan.VulnerabilitiesList `json:"response"`
		Cursor   string                            `json:"cursor"`
	}{}
	err = json.Unmarshal(body, &scanDetailsResult)
	if err != nil {
		return nil, err
	}

	vulnerabilities := make([]registryvulnerabilities.Vulnerability, len(scanDetailsResult.Response))
	for i, vulnerabilityEntry := range scanDetailsResult.Response {
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
	}

	resultImageVulnerabilityReport := registryvulnerabilities.ContainerImageVulnerabilityReport{
		ImageID:         *imageID,
		Vulnerabilities: vulnerabilities,
	}

	return &resultImageVulnerabilityReport, nil
}

func (armoCivAdaptor *ArmoCivAdaptor) DescribeAdaptor() string {
	// TODO
	return ""
}

func (armoCivAdaptor *ArmoCivAdaptor) GetImagesInformation(imageIDs []registryvulnerabilities.ContainerImageIdentifier) ([]registryvulnerabilities.ContainerImageInformation, error) {
	// TODO
	return []registryvulnerabilities.ContainerImageInformation{}, nil
}

func (armoCivAdaptor *ArmoCivAdaptor) GetImagesScanStatus(imageIDs []registryvulnerabilities.ContainerImageIdentifier) ([]registryvulnerabilities.ContainerImageScanStatus, error) {
	// TODO
	return []registryvulnerabilities.ContainerImageScanStatus{}, nil
}
