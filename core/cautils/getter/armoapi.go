package getter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/kubescape/core/cautils/logger"
	"github.com/armosec/kubescape/core/cautils/logger/helpers"
	"github.com/armosec/opa-utils/reporthandling"
)

// =======================================================================================================================
// =============================================== ArmoAPI ===============================================================
// =======================================================================================================================

var (
	// ATTENTION!!!
	// Changes in this URLs variable names, or in the usage is affecting the build process! BE CAREFUL
	armoERURL   = "report.armo.cloud"
	armoBEURL   = "api.armo.cloud"
	armoFEURL   = "portal.armo.cloud"
	armoAUTHURL = "auth.armo.cloud"

	armoStageERURL   = "report-ks.eustage2.cyberarmorsoft.com"
	armoStageBEURL   = "api-stage.armo.cloud"
	armoStageFEURL   = "armoui.eustage2.cyberarmorsoft.com"
	armoStageAUTHURL = "eggauth.eustage2.cyberarmorsoft.com"

	armoDevERURL   = "report.eudev3.cyberarmorsoft.com"
	armoDevBEURL   = "api-dev.armo.cloud"
	armoDevFEURL   = "armoui-dev.eudev3.cyberarmorsoft.com"
	armoDevAUTHURL = "eggauth.eudev3.cyberarmorsoft.com"
)

// Armo API for downloading policies
type ArmoAPI struct {
	httpClient *http.Client
	apiURL     string
	authURL    string
	erURL      string
	feURL      string
	accountID  string
	clientID   string
	secretKey  string
	feToken    FeLoginResponse
	authCookie string
	loggedIn   bool
}

var globalArmoAPIConnector *ArmoAPI

func SetARMOAPIConnector(armoAPI *ArmoAPI) {
	logger.L().Debug("Armo URLs", helpers.String("api", armoAPI.apiURL), helpers.String("auth", armoAPI.authURL), helpers.String("report", armoAPI.erURL), helpers.String("UI", armoAPI.feURL))
	globalArmoAPIConnector = armoAPI
}

func GetArmoAPIConnector() *ArmoAPI {
	if globalArmoAPIConnector == nil {
		// logger.L().Error("returning nil API connector")
		SetARMOAPIConnector(NewARMOAPIProd())
	}
	return globalArmoAPIConnector
}

func NewARMOAPIDev() *ArmoAPI {
	apiObj := newArmoAPI()

	apiObj.apiURL = armoDevBEURL
	apiObj.authURL = armoDevAUTHURL
	apiObj.erURL = armoDevERURL
	apiObj.feURL = armoDevFEURL

	return apiObj
}

func NewARMOAPIProd() *ArmoAPI {
	apiObj := newArmoAPI()

	apiObj.apiURL = armoBEURL
	apiObj.erURL = armoERURL
	apiObj.feURL = armoFEURL
	apiObj.authURL = armoAUTHURL

	return apiObj
}

func NewARMOAPIStaging() *ArmoAPI {
	apiObj := newArmoAPI()

	apiObj.apiURL = armoStageBEURL
	apiObj.erURL = armoStageERURL
	apiObj.feURL = armoStageFEURL
	apiObj.authURL = armoStageAUTHURL

	return apiObj
}

func NewARMOAPICustomized(armoERURL, armoBEURL, armoFEURL, armoAUTHURL string) *ArmoAPI {
	apiObj := newArmoAPI()

	apiObj.erURL = armoERURL
	apiObj.apiURL = armoBEURL
	apiObj.feURL = armoFEURL
	apiObj.authURL = armoAUTHURL

	return apiObj
}

func newArmoAPI() *ArmoAPI {
	return &ArmoAPI{
		httpClient: &http.Client{Timeout: time.Duration(61) * time.Second},
		loggedIn:   false,
	}
}

func (armoAPI *ArmoAPI) Post(fullURL string, headers map[string]string, body []byte) (string, error) {
	if headers == nil {
		headers = make(map[string]string)
	}
	armoAPI.appendAuthHeaders(headers)
	return HttpPost(armoAPI.httpClient, fullURL, headers, body)
}

func (armoAPI *ArmoAPI) Delete(fullURL string, headers map[string]string) (string, error) {
	if headers == nil {
		headers = make(map[string]string)
	}
	armoAPI.appendAuthHeaders(headers)
	return HttpDelete(armoAPI.httpClient, fullURL, headers)
}
func (armoAPI *ArmoAPI) Get(fullURL string, headers map[string]string) (string, error) {
	if headers == nil {
		headers = make(map[string]string)
	}
	armoAPI.appendAuthHeaders(headers)
	return HttpGetter(armoAPI.httpClient, fullURL, headers)
}

func (armoAPI *ArmoAPI) GetAccountID() string          { return armoAPI.accountID }
func (armoAPI *ArmoAPI) IsLoggedIn() bool              { return armoAPI.loggedIn }
func (armoAPI *ArmoAPI) GetClientID() string           { return armoAPI.clientID }
func (armoAPI *ArmoAPI) GetSecretKey() string          { return armoAPI.secretKey }
func (armoAPI *ArmoAPI) GetFrontendURL() string        { return armoAPI.feURL }
func (armoAPI *ArmoAPI) GetAPIURL() string             { return armoAPI.apiURL }
func (armoAPI *ArmoAPI) GetReportReceiverURL() string  { return armoAPI.erURL }
func (armoAPI *ArmoAPI) SetAccountID(accountID string) { armoAPI.accountID = accountID }
func (armoAPI *ArmoAPI) SetClientID(clientID string)   { armoAPI.clientID = clientID }
func (armoAPI *ArmoAPI) SetSecretKey(secretKey string) { armoAPI.secretKey = secretKey }

func (armoAPI *ArmoAPI) GetFramework(name string) (*reporthandling.Framework, error) {
	respStr, err := armoAPI.Get(armoAPI.getFrameworkURL(name), nil)
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
	respStr, err := armoAPI.Get(armoAPI.getListFrameworkURL(), nil)
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

	respStr, err := armoAPI.Get(armoAPI.getExceptionsURL(clusterName), nil)
	if err != nil {
		return nil, err
	}

	if err = JSONDecoder(respStr).Decode(&exceptions); err != nil {
		return nil, err
	}

	return exceptions, nil
}

func (armoAPI *ArmoAPI) GetTenant() (*TenantResponse, error) {
	url := armoAPI.getAccountURL()
	if armoAPI.accountID != "" {
		url = fmt.Sprintf("%s?customerGUID=%s", url, armoAPI.accountID)
	}
	respStr, err := armoAPI.Get(url, nil)
	if err != nil {
		return nil, err
	}
	tenant := &TenantResponse{}
	if err = JSONDecoder(respStr).Decode(tenant); err != nil {
		return nil, err
	}
	if tenant.TenantID != "" {
		armoAPI.accountID = tenant.TenantID
	}
	return tenant, nil
}

// ControlsInputs  // map[<control name>][<input arguments>]
func (armoAPI *ArmoAPI) GetAccountConfig(clusterName string) (*armotypes.CustomerConfig, error) {
	accountConfig := &armotypes.CustomerConfig{}
	if armoAPI.accountID == "" {
		return accountConfig, nil
	}
	respStr, err := armoAPI.Get(armoAPI.getAccountConfig(clusterName), nil)
	if err != nil {
		return nil, err
	}

	if err = JSONDecoder(respStr).Decode(&accountConfig); err != nil {
		// try with default scope
		respStr, err = armoAPI.Get(armoAPI.getAccountConfigDefault(clusterName), nil)
		if err != nil {
			return nil, err
		}
		if err = JSONDecoder(respStr).Decode(&accountConfig); err != nil {
			return nil, err
		}
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
	respStr, err := armoAPI.Get(armoAPI.getListFrameworkURL(), nil)
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
	respStr, err := armoAPI.Get(armoAPI.getListFrameworkURL(), nil)
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

func (armoAPI *ArmoAPI) PostExceptions(exceptions []armotypes.PostureExceptionPolicy) error {

	for i := range exceptions {
		ex, err := json.Marshal(exceptions[i])
		if err != nil {
			return err
		}
		_, err = armoAPI.Post(armoAPI.exceptionsURL(""), map[string]string{"Content-Type": "application/json"}, ex)
		if err != nil {
			return err
		}
	}
	return nil
}

func (armoAPI *ArmoAPI) DeleteException(exceptionName string) error {

	_, err := armoAPI.Delete(armoAPI.exceptionsURL(exceptionName), nil)
	if err != nil {
		return err
	}
	return nil
}
func (armoAPI *ArmoAPI) Login() error {
	if armoAPI.accountID == "" {
		return fmt.Errorf("failed to login, missing accountID")
	}
	if armoAPI.clientID == "" {
		return fmt.Errorf("failed to login, missing clientID")
	}
	if armoAPI.secretKey == "" {
		return fmt.Errorf("failed to login, missing secretKey")
	}

	// init URLs
	feLoginData := FeLoginData{ClientId: armoAPI.clientID, Secret: armoAPI.secretKey}
	body, _ := json.Marshal(feLoginData)

	resp, err := http.Post(armoAPI.getApiToken(), "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error authenticating: %d", resp.StatusCode)
	}

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var feLoginResponse FeLoginResponse

	if err = json.Unmarshal(responseBody, &feLoginResponse); err != nil {
		return err
	}
	armoAPI.feToken = feLoginResponse

	/* Now we have JWT */

	armoAPI.authCookie, err = armoAPI.getAuthCookie()
	if err != nil {
		return err
	}
	armoAPI.loggedIn = true
	return nil
}
