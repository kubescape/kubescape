package getter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/opa-utils/reporthandling"
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
	armoDevFEURL = "armoui-dev.eudev3.cyberarmorsoft.com"
)

// Armo API for downloading policies
type ArmoAPI struct {
	httpClient   *http.Client
	apiURL       string
	erURL        string
	feURL        string
	customerGUID string
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
func (armoAPI *ArmoAPI) SetCustomerGUID(customerGUID string) {
	armoAPI.customerGUID = customerGUID

}
func (armoAPI *ArmoAPI) GetFrontendURL() string {
	return armoAPI.feURL
}

func (armoAPI *ArmoAPI) GetReportReceiverURL() string {
	return armoAPI.erURL
}

func (armoAPI *ArmoAPI) GetFramework(name string) (*reporthandling.Framework, error) {
	respStr, err := HttpGetter(armoAPI.httpClient, armoAPI.getFrameworkURL(name), nil)
	if err != nil {
		return nil, nil
	}

	framework := &reporthandling.Framework{}
	if err = JSONDecoder(respStr).Decode(framework); err != nil {
		return nil, err
	}
	SaveInFile(framework, GetDefaultPath(name+".json"))

	return framework, err
}

func (armoAPI *ArmoAPI) GetFrameworks() ([]reporthandling.Framework, error) {
	respStr, err := HttpGetter(armoAPI.httpClient, armoAPI.getListFrameworkURL(), nil)
	if err != nil {
		return nil, nil
	}

	frameworks := []reporthandling.Framework{}
	if err = JSONDecoder(respStr).Decode(&frameworks); err != nil {
		return nil, err
	}
	// SaveInFile(framework, GetDefaultPath(name+".json"))

	return frameworks, err
}

func (armoAPI *ArmoAPI) GetControl(policyName string) (*reporthandling.Control, error) {
	return nil, fmt.Errorf("control api is not public")
}

func (armoAPI *ArmoAPI) GetExceptions(clusterName string) ([]armotypes.PostureExceptionPolicy, error) {
	exceptions := []armotypes.PostureExceptionPolicy{}

	respStr, err := HttpGetter(armoAPI.httpClient, armoAPI.getExceptionsURL(clusterName), nil)
	if err != nil {
		return nil, err
	}

	if err = JSONDecoder(respStr).Decode(&exceptions); err != nil {
		return nil, err
	}

	return exceptions, nil
}

func (armoAPI *ArmoAPI) GetCustomerGUID() (*TenantResponse, error) {
	url := armoAPI.getCustomerURL()
	if armoAPI.customerGUID != "" {
		url = fmt.Sprintf("%s?customerGUID=%s", url, armoAPI.customerGUID)
	}
	respStr, err := HttpGetter(armoAPI.httpClient, url, nil)
	if err != nil {
		return nil, err
	}
	tenant := &TenantResponse{}
	if err = JSONDecoder(respStr).Decode(tenant); err != nil {
		return nil, err
	}

	return tenant, nil
}

// ControlsInputs  // map[<control name>][<input arguments>]
func (armoAPI *ArmoAPI) GetAccountConfig(clusterName string) (*armotypes.CustomerConfig, error) {
	accountConfig := &armotypes.CustomerConfig{}
	if armoAPI.customerGUID == "" {
		return accountConfig, nil
	}
	respStr, err := HttpGetter(armoAPI.httpClient, armoAPI.getAccountConfig(clusterName), nil)
	if err != nil {
		return nil, err
	}

	if err = JSONDecoder(respStr).Decode(&accountConfig); err != nil {
		return nil, err
	}

	return accountConfig, nil
}

// ControlsInputs  // map[<control name>][<input arguments>]
func (armoAPI *ArmoAPI) GetControlsInputs(clusterName string) (map[string][]string, error) {
	accountConfig, err := armoAPI.GetAccountConfig(clusterName)
	if err == nil {
		return accountConfig.Settings.PostureControlInputs, nil
	}
	return nil, err
}

func (armoAPI *ArmoAPI) ListCustomFrameworks() ([]string, error) {
	respStr, err := HttpGetter(armoAPI.httpClient, armoAPI.getListFrameworkURL(), nil)
	if err != nil {
		return nil, err
	}
	frs := []reporthandling.Framework{}
	if err = json.Unmarshal([]byte(respStr), &frs); err != nil {
		return nil, err
	}

	frameworkList := []string{}
	for _, fr := range frs {
		if !isNativeFramework(fr.Name) {
			frameworkList = append(frameworkList, fr.Name)
		}
	}

	return frameworkList, nil
}

func (armoAPI *ArmoAPI) ListFrameworks() ([]string, error) {
	respStr, err := HttpGetter(armoAPI.httpClient, armoAPI.getListFrameworkURL(), nil)
	if err != nil {
		return nil, err
	}
	frs := []reporthandling.Framework{}
	if err = json.Unmarshal([]byte(respStr), &frs); err != nil {
		return nil, err
	}

	frameworkList := []string{}
	for _, fr := range frs {
		if isNativeFramework(fr.Name) {
			frameworkList = append(frameworkList, strings.ToLower(fr.Name))
		} else {
			frameworkList = append(frameworkList, fr.Name)
		}
	}

	return frameworkList, nil
}

func (armoAPI *ArmoAPI) ListControls(l ListType) ([]string, error) {
	return nil, fmt.Errorf("control api is not public")
}

type TenantResponse struct {
	TenantID  string `json:"tenantId"`
	Token     string `json:"token"`
	Expires   string `json:"expires"`
	AdminMail string `json:"adminMail,omitempty"`
}
