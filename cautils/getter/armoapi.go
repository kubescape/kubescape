package getter

import (
	"fmt"
	"net/http"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/opa-utils/reporthandling"
)

// =======================================================================================================================
// =============================================== ArmoAPI ===============================================================
// =======================================================================================================================

var (
	// ATTENTION!!!
	// Changes in this URLs variable names, or in the usage is affecting the build process! BE CAREFULL
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
func (armoAPI *ArmoAPI) GetFramework(name string) (*reporthandling.Framework, error) {
	respStr, err := HttpGetter(armoAPI.httpClient, armoAPI.getFrameworkURL(name))
	if err != nil {
		return nil, err
	}

	framework := &reporthandling.Framework{}
	if err = JSONDecoder(respStr).Decode(framework); err != nil {
		return nil, err
	}
	SaveFrameworkInFile(framework, GetDefaultPath(name+".json"))

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

func (armoAPI *ArmoAPI) GetCustomerGUID(customerGUID string) (*TenantResponse, error) {
	url := armoAPI.getCustomerURL()
	if customerGUID != "" {
		url = fmt.Sprintf("%s?customerGUID=%s", url, customerGUID)
	}
	respStr, err := HttpGetter(armoAPI.httpClient, url)
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
	TenantID  string `json:"tenantId"`
	Token     string `json:"token"`
	Expires   string `json:"expires"`
	AdminMail string `json:"adminMail,omitempty"`
}
