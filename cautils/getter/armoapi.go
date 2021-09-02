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
	hostURL    string
}

func NewArmoAPI() *ArmoAPI {
	return &ArmoAPI{
		httpClient: &http.Client{},
		hostURL:    "https://dashbe.eustage2.cyberarmorsoft.com",
	}
}
func (armoAPI *ArmoAPI) GetFramework(name string) (*opapolicy.Framework, error) {
	armoAPI.setURL(name)
	respStr, err := HttpGetter(armoAPI.httpClient, armoAPI.hostURL)
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

func (armoAPI *ArmoAPI) setURL(frameworkName string) {
	requestURI := "v1/armoFrameworks"
	requestURI += fmt.Sprintf("?customerGUID=%s", "11111111-1111-1111-1111-111111111111")
	requestURI += fmt.Sprintf("&frameworkName=%s", strings.ToUpper(frameworkName))
	requestURI += "&getRules=true"

	armoAPI.hostURL = urlEncoder(fmt.Sprintf("%s/%s", armoAPI.hostURL, requestURI))
}

func (armoAPI *ArmoAPI) GetExceptions(scope, customerName, namespace string) ([]armotypes.PostureExceptionPolicy, error) {
	return []armotypes.PostureExceptionPolicy{}, nil
}
