package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/armosec/kubescape/containerscan"
	"github.com/armosec/kubescape/registryadaptors/registryvulnerabilities"
)

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

func (armoCivAdaptor *ArmoCivAdaptor) getImageLastScanId(imageID *registryvulnerabilities.ContainerImageIdentifier) (string, error) {
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
