package getter

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/armosec/opa-utils/reporthandling"
)

var NativeFrameworks = []string{"nsa", "mitre", "armobest"}

func (armoAPI *ArmoAPI) getFrameworkURL(frameworkName string) string {
	u := url.URL{}
	u.Scheme = "https"
	u.Host = armoAPI.apiURL
	u.Path = "api/v1/armoFrameworks"
	q := u.Query()
	q.Add("customerGUID", armoAPI.customerGUID)
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
	q.Add("customerGUID", armoAPI.customerGUID)
	u.RawQuery = q.Encode()

	return u.String()
}

func (armoAPI *ArmoAPI) GetCustomFrameworksForCustomer(customerGUID string) ([]string, error) {
	respStr, err := HttpGetter(armoAPI.httpClient, armoAPI.getListFrameworkURL(), nil)
	if err != nil {
		return nil, err
	}
	frs := []reporthandling.Framework{}
	frameworkList := []string{}
	err = json.Unmarshal([]byte(respStr), &frs)

	for _, fr := range frs {
		frameworkList = append(frameworkList, fr.Name)
	}

	return frameworkList, nil
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
	u.Path = "api/v1/armoCustomerConfiguration"

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
