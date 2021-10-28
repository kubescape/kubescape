package getter

import (
	"net/url"
	"strings"
)

func (armoAPI *ArmoAPI) getFrameworkURL(frameworkName string) string {
	u := url.URL{}
	u.Scheme = "https"
	u.Host = armoAPI.apiURL
	u.Path = "v1/armoFrameworks"
	q := u.Query()
	q.Add("customerGUID", "11111111-1111-1111-1111-111111111111")
	q.Add("frameworkName", strings.ToUpper(frameworkName))
	q.Add("getRules", "true")
	u.RawQuery = q.Encode()

	return u.String()
}

func (armoAPI *ArmoAPI) getExceptionsURL(customerGUID, clusterName string) string {
	u := url.URL{}
	u.Scheme = "https"
	u.Host = armoAPI.apiURL
	u.Path = "api/v1/armoPostureExceptions"

	q := u.Query()
	q.Add("customerGUID", customerGUID)
	// if clusterName != "" { // TODO - fix customer name support in Armo BE
	// 	q.Add("clusterName", clusterName)
	// }
	u.RawQuery = q.Encode()

	return u.String()
}

func (armoAPI *ArmoAPI) getAccountConfig(customerGUID, clusterName string) string {
	u := url.URL{}
	u.Scheme = "https"
	u.Host = armoAPI.apiURL
	u.Path = "api/v1/customerConfiguration"

	q := u.Query()
	q.Add("customerGUID", customerGUID)
	if clusterName != "" { // TODO - fix customer name support in Armo BE
		q.Add("clusterName", clusterName)
	}
	u.RawQuery = q.Encode()

	return u.String()
}

func (armoAPI *ArmoAPI) getCustomerURL() string {
	u := url.URL{}
	u.Scheme = "https"
	u.Host = armoAPI.apiURL
	u.Path = "api/v1/createTenant"
	return u.String()
}
