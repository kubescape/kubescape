package getter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

var NativeFrameworks = []string{"nsa", "mitre", "armobest", "devopsbest"}

func (armoAPI *ArmoAPI) getFrameworkURL(frameworkName string) string {
	u := url.URL{}
	u.Scheme = "https"
	u.Host = armoAPI.apiURL
	u.Path = "api/v1/armoFrameworks"
	q := u.Query()
	q.Add("customerGUID", armoAPI.getCustomerGUIDFallBack())
	if isNativeFramework(frameworkName) {
		q.Add("frameworkName", strings.ToUpper(frameworkName))
	} else {
		// For customer framework has to be the way it was added
		q.Add("frameworkName", frameworkName)
	}
	u.RawQuery = q.Encode()

	return u.String()
}

func (armoAPI *ArmoAPI) getListFrameworkURL() string {
	u := url.URL{}
	u.Scheme = "https"
	u.Host = armoAPI.apiURL
	u.Path = "api/v1/armoFrameworks"
	q := u.Query()
	q.Add("customerGUID", armoAPI.getCustomerGUIDFallBack())
	u.RawQuery = q.Encode()

	return u.String()
}
func (armoAPI *ArmoAPI) getExceptionsURL(clusterName string) string {
	u := url.URL{}
	u.Scheme = "https"
	u.Host = armoAPI.apiURL
	u.Path = "api/v1/armoPostureExceptions"

	q := u.Query()
	q.Add("customerGUID", armoAPI.getCustomerGUIDFallBack())
	// if clusterName != "" { // TODO - fix customer name support in Armo BE
	// 	q.Add("clusterName", clusterName)
	// }
	u.RawQuery = q.Encode()

	return u.String()
}

func (armoAPI *ArmoAPI) exceptionsURL(exceptionsPolicyName string) string {
	u := url.URL{}
	u.Scheme = "https"
	u.Host = armoAPI.apiURL
	u.Path = "api/v1/postureExceptionPolicy"

	q := u.Query()
	q.Add("customerGUID", armoAPI.getCustomerGUIDFallBack())
	if exceptionsPolicyName != "" { // for delete
		q.Add("policyName", exceptionsPolicyName)
	}

	u.RawQuery = q.Encode()

	return u.String()
}

func (armoAPI *ArmoAPI) getAccountConfigDefault(clusterName string) string {
	config := armoAPI.getAccountConfig(clusterName)
	url := config + "&scope=default"
	return url
}

func (armoAPI *ArmoAPI) getAccountConfig(clusterName string) string {
	u := url.URL{}
	u.Scheme = "https"
	u.Host = armoAPI.apiURL
	u.Path = "api/v1/armoCustomerConfiguration"

	q := u.Query()
	q.Add("customerGUID", armoAPI.getCustomerGUIDFallBack())
	if clusterName != "" { // TODO - fix customer name support in Armo BE
		q.Add("clusterName", clusterName)
	}
	u.RawQuery = q.Encode()

	return u.String()
}

func (armoAPI *ArmoAPI) getAccountURL() string {
	u := url.URL{}
	u.Scheme = "https"
	u.Host = armoAPI.apiURL
	u.Path = "api/v1/createTenant"
	return u.String()
}

func (armoAPI *ArmoAPI) getApiToken() string {
	u := url.URL{}
	u.Scheme = "https"
	u.Host = armoAPI.authURL
	u.Path = "frontegg/identity/resources/auth/v1/api-token"
	return u.String()
}

func (armoAPI *ArmoAPI) getOpenidCustomers() string {
	u := url.URL{}
	u.Scheme = "https"
	u.Host = armoAPI.apiURL
	u.Path = "api/v1/openid_customers"
	return u.String()
}

func (armoAPI *ArmoAPI) getAuthCookie() (string, error) {
	selectCustomer := ArmoSelectCustomer{SelectedCustomerGuid: armoAPI.accountID}
	requestBody, _ := json.Marshal(selectCustomer)
	client := &http.Client{}
	httpRequest, err := http.NewRequest(http.MethodPost, armoAPI.getOpenidCustomers(), bytes.NewBuffer(requestBody))
	if err != nil {
		return "", err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", armoAPI.feToken.Token))
	httpResponse, err := client.Do(httpRequest)
	if err != nil {
		return "", err
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get cookie from %s: status %d", armoAPI.getOpenidCustomers(), httpResponse.StatusCode)
	}

	cookies := httpResponse.Header.Get("set-cookie")
	if len(cookies) == 0 {
		return "", fmt.Errorf("no cookie field in response from %s", armoAPI.getOpenidCustomers())
	}

	authCookie := ""
	for _, cookie := range strings.Split(cookies, ";") {
		kv := strings.Split(cookie, "=")
		if kv[0] == "auth" {
			authCookie = kv[1]
		}
	}

	if len(authCookie) == 0 {
		return "", fmt.Errorf("no auth cookie field in response from %s", armoAPI.getOpenidCustomers())
	}

	return authCookie, nil
}
func (armoAPI *ArmoAPI) appendAuthHeaders(headers map[string]string) {

	if armoAPI.feToken.Token != "" {
		headers["Authorization"] = fmt.Sprintf("Bearer %s", armoAPI.feToken.Token)
	}
	if armoAPI.authCookie != "" {
		headers["Cookie"] = fmt.Sprintf("auth=%s", armoAPI.authCookie)
	}
}

func (armoAPI *ArmoAPI) getCustomerGUIDFallBack() string {
	if armoAPI.accountID != "" {
		return armoAPI.accountID
	}
	return "11111111-1111-1111-1111-111111111111"
}
