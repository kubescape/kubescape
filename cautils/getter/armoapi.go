package getter

import (
	"fmt"
	"net/http"
	"time"

	"github.com/armosec/kubescape/cautils/armotypes"
	"github.com/armosec/kubescape/cautils/opapolicy"
	"github.com/golang/glog"
)

// =======================================================================================================================
// =============================================== ArmoAPI ===============================================================
// =======================================================================================================================

var (
	// ATTENTION!!!
	// Changes in this URLs variable names, or in the usage is affecting the build process! BE CAREFULL
	armoERURL = "report.armo.cloud"
	armoBEURL = "api.armo.cloud"
	armoFEURL = "portal.armo.cloud"

	armoDevERURL = "report.eudev3.cyberarmorsoft.com"
	armoDevBEURL = "eggdashbe.eudev3.cyberarmorsoft.com"
	armoDevFEURL = "armoui.eudev3.cyberarmorsoft.com"
)

// Armo API for downloading policies
type ArmoAPI struct {
	httpClient *http.Client
	apiURL     string
	erURL      string
	feURL      string
}

var globalArmoAPIConnecctor *ArmoAPI

func SetARMOAPIConnector(armoAPI *ArmoAPI) {
	globalArmoAPIConnecctor = armoAPI
}

func GetArmoAPIConnector() *ArmoAPI {
	if globalArmoAPIConnecctor == nil {
		glog.Error("returning nil API connector")
	}
	return globalArmoAPIConnecctor
}

func NewARMOAPIDev() *ArmoAPI {
	apiObj := newArmoAPI()

	apiObj.apiURL = armoDevBEURL
	apiObj.erURL = armoDevERURL
	apiObj.feURL = armoDevFEURL

	return apiObj
}

func NewARMOAPIProd() *ArmoAPI {
	apiObj := newArmoAPI()

	apiObj.apiURL = armoBEURL
	apiObj.erURL = armoERURL
	apiObj.feURL = armoFEURL

	return apiObj
}

func NewARMOAPICustomized(armoERURL, armoBEURL, armoFEURL string) *ArmoAPI {
	apiObj := newArmoAPI()

	apiObj.erURL = armoERURL
	apiObj.apiURL = armoBEURL
	apiObj.feURL = armoFEURL

	return apiObj
}

func newArmoAPI() *ArmoAPI {
	return &ArmoAPI{
		httpClient: &http.Client{Timeout: time.Duration(61) * time.Second},
	}
}

func (armoAPI *ArmoAPI) GetFrontendURL() string {
	return armoAPI.feURL
}

func (armoAPI *ArmoAPI) GetReportReceiverURL() string {
	return armoAPI.erURL
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
