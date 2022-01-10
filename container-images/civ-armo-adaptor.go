package containerimages

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
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
	/*fmt.Println(requestUrl)
	fmt.Println(httpRequest.Header.Get("Content-Type"))
	fmt.Println(httpRequest.Header.Get("Authorization"))
	fmt.Println(string(requestBody))*/
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

func (armoCivAdaptor *ArmoCivAdaptor) GetImageVulnerabilties(imageID *ContainerImageIdentifier) (*ContainerImageVulnerability, error) {
	filter := []map[string]string{{"imageTag": imageID.Tag}}
	pageSize := 100
	pageNumber := 1
	request := V2ListRequest{PageSize: &pageSize, PageNum: &pageNumber, InnerFilters: filter, OrderBy: "timestamp:desc"}
	requestBody, _ := json.Marshal(request)
	requestUrl := fmt.Sprintf("%s/api/v1/vulnerability/scanResultsSumSummary?customerGUID=%s", armoCivAdaptor.armoUrls.BackendUrl, armoCivAdaptor.accountId)
	client := &http.Client{}
	httpRequest, err := http.NewRequest("POST", requestUrl, bytes.NewBuffer(requestBody))
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", armoCivAdaptor.feToken.Token))
	httpRequest.Header.Set("Cookie", fmt.Sprintf("auth=%s", armoCivAdaptor.authCookie))
	//fmt.Printf("**** token %s\n", armoCivAdaptor.feToken.Token)
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

	fmt.Println(string(body))

	/*err = json.Unmarshal(body, &feLoginResponse)
	if err != nil {
		return nil, err
	}*/

	return nil, nil
	// https://api-dev.armo.cloud/api/v1/vulnerability/scanResultsSumSummary?customerGUID=1e3a88bf-92ce-44f8-914e-cbe71830d566%22
}

func (armoCivAdaptor *ArmoCivAdaptor) GetImagesVulnerabilties(imageIDs []ContainerImageIdentifier) ([]ContainerImageVulnerability, error) {
	return nil, nil
}
