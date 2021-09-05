package getter

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/armosec/kubescape/cautils/armotypes"
	"github.com/armosec/kubescape/cautils/opapolicy"
)

// =======================================================================================================================
// =============================================== ArmoAPI ===============================================================
// =======================================================================================================================

// Armo API for downloading policies
type ArmoAPI struct {
	httpClient *http.Client
	baseURL    string
}

func NewArmoAPI() *ArmoAPI {
	return &ArmoAPI{
		httpClient: &http.Client{},
		baseURL:    "https://dashbe.auprod1.cyberarmorsoft.com",
	}
}
func (armoAPI *ArmoAPI) GetFramework(name string) (*opapolicy.Framework, error) {
	respStr, err := HttpGetter(armoAPI.httpClient, armoAPI.getFrameworkURL(name))
	if err != nil {
		return nil, err
	}

	framework := &opapolicy.Framework{}
	if err = JSONDecoder(respStr).Decode(framework); err != nil {
		return nil, err
	}
	SaveFrameworkInFile(framework, GetDefaultPath(name))

	return framework, err
}

func (armoAPI *ArmoAPI) getFrameworkURL(frameworkName string) string {
	requestURI := "v1/armoFrameworks"
	requestURI += fmt.Sprintf("?customerGUID=%s", "11111111-1111-1111-1111-111111111111")
	requestURI += fmt.Sprintf("&frameworkName=%s", strings.ToUpper(frameworkName))
	requestURI += "&getRules=true"

	return urlEncoder(fmt.Sprintf("%s/%s", armoAPI.baseURL, requestURI))
}

func (armoAPI *ArmoAPI) GetExceptions(customerGUID, clusterName string) ([]armotypes.PostureExceptionPolicy, error) {
	exceptions := []armotypes.PostureExceptionPolicy{}
	if customerGUID == "" {
		return exceptions, nil
	}
	respStr, err := HttpGetter(armoAPI.httpClient, armoAPI.getExceptionsURL(customerGUID, clusterName))
	if err != nil {
		return nil, err
	}

	if err = JSONDecoder(respStr).Decode(&exceptions); err != nil {
		return nil, err
	}

	return exceptions, nil
}

func (armoAPI *ArmoAPI) getExceptionsURL(customerGUID, clusterName string) string {
	requestURI := "api/v1/armoPostureExceptions"
	requestURI += fmt.Sprintf("?customerGUID=%s", customerGUID)
	if clusterName != "" {
		requestURI += fmt.Sprintf("&clusterName=%s", clusterName)
	}
	return urlEncoder(fmt.Sprintf("%s/%s", armoAPI.baseURL, requestURI))
}
