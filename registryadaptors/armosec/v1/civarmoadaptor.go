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
	var accountID string
	var accessKey string
	var clientID string
	var ok bool
	if accountID, ok = credentials["accountID"]; !ok {
		return nil, fmt.Errorf("define accountID in credentials")
	}
	if clientID, ok = credentials["clientID"]; !ok {
		return nil, fmt.Errorf("define clientID in credentials")
	}
	if accessKey, ok = credentials["accessKey"]; !ok {
		return nil, fmt.Errorf("define accessKey in credentials")
	}
	armoCivAdaptor := ArmoCivAdaptor{registry: registry, clientID: clientID, accountID: accountID, accessKey: accessKey}
	err := armoCivAdaptor.initializeUrls()
	if err != nil {
		return nil, err
	}
	return &armoCivAdaptor, nil
}

func (armoCivAdaptor *ArmoCivAdaptor) Login() error {
	feLoginData := FeLoginData{ClientId: armoCivAdaptor.clientID, Secret: armoCivAdaptor.accessKey}
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

	if err = json.Unmarshal(responseBody, &feLoginResponse); err != nil {
		return err
	}
	armoCivAdaptor.feToken = feLoginResponse

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
	if containerScanId == "" {
		return nil, fmt.Errorf("last scan ID is empty")
	}

	filter := []map[string]string{{"containersScanID": containerScanId}}
	pageSize := 300
	pageNumber := 1
	request := V2ListRequest{PageSize: &pageSize, PageNum: &pageNumber, InnerFilters: filter, OrderBy: "timestamp:desc"}
	requestBody, _ := json.Marshal(request)
	requestUrl := fmt.Sprintf("%s/api/v1/vulnerability/scanResultsDetails?customerGUID=%s", armoCivAdaptor.armoUrls.BackendUrl, armoCivAdaptor.accountID)
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

	vulnerabilities := responseObjectToVulnerabilities(scanDetailsResult.Response)

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
