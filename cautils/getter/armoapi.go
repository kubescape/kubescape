package getter

import (
	"net/http"

	"github.com/armosec/kubescape/cautils/armotypes"
	"github.com/armosec/kubescape/cautils/opapolicy"
)

// =======================================================================================================================
// =============================================== ArmoAPI ===============================================================
// =======================================================================================================================

const (
	ArmoBEURL = "eggdashbe.eudev3.cyberarmorsoft.com"
	ArmoERURL = "report.eudev3.cyberarmorsoft.com"
	ArmoFEURL = "armoui.eudev3.cyberarmorsoft.com"
	// ArmoURL = "https://dashbe.euprod1.cyberarmorsoft.com"
)

// Armo API for downloading policies
type ArmoAPI struct {
	httpClient *http.Client
}

func NewArmoAPI() *ArmoAPI {
	return &ArmoAPI{
		httpClient: &http.Client{},
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

func (armoAPI *ArmoAPI) GetCustomerGUID() (*TenantResponse, error) {
	respStr, err := HttpGetter(armoAPI.httpClient, armoAPI.getCustomerURL())
	if err != nil {
		return nil, err
	}
	tenant := &TenantResponse{}
	if err = JSONDecoder(respStr).Decode(tenant); err != nil {
		return nil, err
	}

	return tenant, nil
}

type TenantResponse struct {
	TenantID string `json:"tenantId"`
	Token    string `json:"token"`
	Expires  string `json:"expires"`
}
