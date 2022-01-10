package containerimages

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/armosec/kubescape/containerscan"
)

type FeLoginData struct {
	Secret   string `json:"secret"`
	ClientId string `json:"clientId"`
}

type FeLoginResponse struct {
	Token        string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int32  `json:"expiresIn"`
	Expires      string `json:"expires"`
}

type ArmoBeConfiguration struct {
	BackendUrl string `json:"backend"`
	AuthUrl    string `json:"authUrl"`
}
type ArmoSelectCustomer struct {
	SelectedCustomerGuid string `json:"selectedCustomer"`
}

type ArmoCivAdaptor struct {
	registry   string
	accountId  string
	clientId   string
	accessKey  string
	feToken    FeLoginResponse
	armoUrls   ArmoBeConfiguration
	authCookie string
}

func CreateArmoAdaptor(registry string, credentials map[string]string) (*ArmoCivAdaptor, error) {
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

func (armoCivAdaptor *ArmoCivAdaptor) initializeUrls() error {
	configUrl := fmt.Sprintf("https://%s/assets/configs/config.json", armoCivAdaptor.registry)
	resp, err := http.Get(configUrl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cannot retrieve backend config file %s: status %d", configUrl, resp.StatusCode)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	err = json.Unmarshal(body, &armoCivAdaptor.armoUrls)
	if err != nil {
		return err
	}
	return nil

}

func (armoCivAdaptor *ArmoCivAdaptor) getAuthCookie() (string, error) {
	selectCustomer := ArmoSelectCustomer{SelectedCustomerGuid: armoCivAdaptor.accountId}
	requestBody, _ := json.Marshal(selectCustomer)
	requestUrl := fmt.Sprintf("%s/api/v1/openid_customers", armoCivAdaptor.armoUrls.BackendUrl)
	client := &http.Client{}
	httpRequest, err := http.NewRequest(http.MethodPost, requestUrl, bytes.NewBuffer(requestBody))
	if err != nil {
		return "", err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", armoCivAdaptor.feToken.Token))
	httpResponse, err := client.Do(httpRequest)
	if err != nil {
		return "", err
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error getting cookie at %s: status %d", requestUrl, httpResponse.StatusCode)
	}

	cookies := httpResponse.Header.Get("set-cookie")
	if len(cookies) == 0 {
		return "", fmt.Errorf("no cookie field in response from %s", requestUrl)
	}

	authCookie := ""
	for _, cookie := range strings.Split(cookies, ";") {
		kv := strings.Split(cookie, "=")
		if kv[0] == "auth" {
			authCookie = kv[1]
		}
	}

	if len(authCookie) == 0 {
		return "", fmt.Errorf("no auth cookie field in response from %s", requestUrl)
	}

	return authCookie, nil
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

func (armoCivAdaptor *ArmoCivAdaptor) getImageLastScanId(imageID *ContainerImageIdentifier) (string, error) {
	filter := []map[string]string{{"imageTag": imageID.Tag}}
	pageSize := 1
	pageNumber := 1
	request := V2ListRequest{PageSize: &pageSize, PageNum: &pageNumber, InnerFilters: filter, OrderBy: "timestamp:desc"}
	requestBody, _ := json.Marshal(request)
	requestUrl := fmt.Sprintf("%s/api/v1/vulnerability/scanResultsSumSummary?customerGUID=%s", armoCivAdaptor.armoUrls.BackendUrl, armoCivAdaptor.accountId)
	client := &http.Client{}
	httpRequest, err := http.NewRequest("POST", requestUrl, bytes.NewBuffer(requestBody))
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", armoCivAdaptor.feToken.Token))
	httpRequest.Header.Set("Cookie", fmt.Sprintf("auth=%s", armoCivAdaptor.authCookie))
	resp, err := client.Do(httpRequest)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error requests %s with %d", requestUrl, resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
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
	err = json.Unmarshal(body, &scanSummartResult)
	if err != nil {
		return "", err
	}

	if len(scanSummartResult.Response) < pageSize {
		return "", fmt.Errorf("did not get response for image %s", imageID.Tag)
	}

	return scanSummartResult.Response[0].ContainerScanID, nil
}

func (armoCivAdaptor *ArmoCivAdaptor) GetImageVulnerabilties(imageIDs []ContainerImageIdentifier) ([]ContainerImageVulnerabilityReport, error) {
	resultList := make([]ContainerImageVulnerabilityReport, 0)
	for _, imageID := range imageIDs {
		result, err := armoCivAdaptor.GetImageVulnerabilty(&imageID)
		if err == nil {
			resultList = append(resultList, *result)
		}
	}
	return resultList, nil
}

func (armoCivAdaptor *ArmoCivAdaptor) GetImageVulnerabilty(imageID *ContainerImageIdentifier) (*ContainerImageVulnerabilityReport, error) {
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

	vulnerabilities := make([]Vulnerability, len(scanDetailsResult.Response))
	for i, vulnerabilityEntry := range scanDetailsResult.Response {
		vulnerabilities[i].Description = vulnerabilityEntry.Description
		vulnerabilities[i].Fixes = make([]FixedIn, len(vulnerabilityEntry.Fixes))
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

	resultImageVulnerabilityReport := ContainerImageVulnerabilityReport{
		ImageID:         *imageID,
		Vulnerabilities: vulnerabilities,
	}

	return &resultImageVulnerabilityReport, nil
}

func (armoCivAdaptor *ArmoCivAdaptor) GetImagesVulnerabilties(imageIDs []ContainerImageIdentifier) ([]ContainerImageVulnerabilityReport, error) {
	return nil, nil
}
