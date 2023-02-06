package getter

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

var NativeFrameworks = []string{"allcontrols", "nsa", "mitre"}

func (api *KSCloudAPI) getFrameworkURL(frameworkName string) string {
	u := url.URL{}
	u.Scheme, u.Host = parseHost(api.GetCloudAPIURL())
	u.Path = "api/v1/armoFrameworks"
	q := u.Query()
	q.Add("customerGUID", api.getCustomerGUIDFallBack())
	if isNativeFramework(frameworkName) {
		q.Add("frameworkName", strings.ToUpper(frameworkName))
	} else {
		// For customer framework has to be the way it was added
		q.Add("frameworkName", frameworkName)
	}
	u.RawQuery = q.Encode()

	return u.String()
}

func (api *KSCloudAPI) getAttackTracksURL() string {
	u := url.URL{}
	u.Scheme, u.Host = parseHost(api.GetCloudAPIURL())
	u.Path = "api/v1/attackTracks"
	q := u.Query()
	q.Add("customerGUID", api.getCustomerGUIDFallBack())
	u.RawQuery = q.Encode()

	return u.String()
}

func (api *KSCloudAPI) getListFrameworkURL() string {
	u := url.URL{}
	u.Scheme, u.Host = parseHost(api.GetCloudAPIURL())
	u.Path = "api/v1/armoFrameworks"
	q := u.Query()
	q.Add("customerGUID", api.getCustomerGUIDFallBack())
	u.RawQuery = q.Encode()

	return u.String()
}
func (api *KSCloudAPI) getExceptionsURL(clusterName string) string {
	u := url.URL{}
	u.Scheme, u.Host = parseHost(api.GetCloudAPIURL())
	u.Path = "api/v1/armoPostureExceptions"

	q := u.Query()
	q.Add("customerGUID", api.getCustomerGUIDFallBack())
	// if clusterName != "" { // TODO - fix customer name support in Armo BE
	// 	q.Add("clusterName", clusterName)
	// }
	u.RawQuery = q.Encode()

	return u.String()
}

func (api *KSCloudAPI) exceptionsURL(exceptionsPolicyName string) string {
	u := url.URL{}
	u.Scheme, u.Host = parseHost(api.GetCloudAPIURL())
	u.Path = "api/v1/postureExceptionPolicy"

	q := u.Query()
	q.Add("customerGUID", api.getCustomerGUIDFallBack())
	if exceptionsPolicyName != "" { // for delete
		q.Add("policyName", exceptionsPolicyName)
	}

	u.RawQuery = q.Encode()

	return u.String()
}

func (api *KSCloudAPI) getAccountConfigDefault(clusterName string) string {
	config := api.getAccountConfig(clusterName)
	url := config + "&scope=customer"
	return url
}

func (api *KSCloudAPI) getAccountConfig(clusterName string) string {
	u := url.URL{}
	u.Scheme, u.Host = parseHost(api.GetCloudAPIURL())
	u.Path = "api/v1/armoCustomerConfiguration"

	q := u.Query()
	q.Add("customerGUID", api.getCustomerGUIDFallBack())
	if clusterName != "" { // TODO - fix customer name support in Armo BE
		q.Add("clusterName", clusterName)
	}
	u.RawQuery = q.Encode()

	return u.String()
}

func (api *KSCloudAPI) getAccountURL() string {
	u := url.URL{}
	u.Scheme, u.Host = parseHost(api.GetCloudAPIURL())
	u.Path = "api/v1/createTenant"
	return u.String()
}

func (api *KSCloudAPI) getApiToken() string {
	u := url.URL{}
	u.Scheme, u.Host = parseHost(api.GetCloudAuthURL())
	u.Path = "identity/resources/auth/v1/api-token"
	return u.String()
}

func (api *KSCloudAPI) getOpenidCustomers() string {
	u := url.URL{}
	u.Scheme, u.Host = parseHost(api.GetCloudAPIURL())
	u.Path = "api/v1/openid_customers"
	return u.String()
}

func (api *KSCloudAPI) getAuthCookie() (string, error) {
	selectCustomer := KSCloudSelectCustomer{SelectedCustomerGuid: api.accountID}
	requestBody, _ := json.Marshal(selectCustomer)
	client := &http.Client{}
	httpRequest, err := http.NewRequest(http.MethodPost, api.getOpenidCustomers(), bytes.NewBuffer(requestBody))
	if err != nil {
		return "", err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", api.feToken.Token))
	httpResponse, err := client.Do(httpRequest)
	if err != nil {
		return "", err
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get cookie from %s: status %d", api.getOpenidCustomers(), httpResponse.StatusCode)
	}

	cookies := httpResponse.Header.Get("set-cookie")
	if len(cookies) == 0 {
		return "", fmt.Errorf("no cookie field in response from %s", api.getOpenidCustomers())
	}

	authCookie := ""
	for _, cookie := range strings.Split(cookies, ";") {
		kv := strings.Split(cookie, "=")
		if kv[0] == "auth" {
			authCookie = kv[1]
		}
	}

	if len(authCookie) == 0 {
		return "", fmt.Errorf("no auth cookie field in response from %s", api.getOpenidCustomers())
	}

	return authCookie, nil
}
func (api *KSCloudAPI) appendAuthHeaders(headers map[string]string) {

	if api.feToken.Token != "" {
		headers["Authorization"] = fmt.Sprintf("Bearer %s", api.feToken.Token)
	}
	if api.authCookie != "" {
		headers["Cookie"] = fmt.Sprintf("auth=%s", api.authCookie)
	}
}

func (api *KSCloudAPI) getCustomerGUIDFallBack() string {
	if api.accountID != "" {
		return api.accountID
	}
	return "11111111-1111-1111-1111-111111111111"
}

func parseHost(host string) (string, string) {
	if strings.HasPrefix(host, "http://") {
		return "http", strings.Replace(host, "http://", "", 1)
	}

	// default scheme
	return "https", strings.Replace(host, "https://", "", 1)
}

func isNativeFramework(framework string) bool {
	return contains(NativeFrameworks, framework)
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if strings.EqualFold(v, str) {
			return true
		}
	}
	return false
}
