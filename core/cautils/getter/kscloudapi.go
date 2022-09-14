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
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/opa-utils/reporthandling"
)

var (
	ksCloudERURL   = "report.armo.cloud"
	ksCloudBEURL   = "api.armosec.io"
	ksCloudFEURL   = "cloud.armosec.io"
	ksCloudAUTHURL = "auth.armosec.io"

	ksCloudStageERURL   = "report-ks.eustage2.cyberarmorsoft.com"
	ksCloudStageBEURL   = "api-stage.armosec.io"
	ksCloudStageFEURL   = "armoui-stage.armosec.io"
	ksCloudStageAUTHURL = "eggauth-stage.armosec.io"

	ksCloudDevERURL   = "report.eudev3.cyberarmorsoft.com"
	ksCloudDevBEURL   = "api-dev.armosec.io"
	ksCloudDevFEURL   = "cloud-dev.armosec.io"
	ksCloudDevAUTHURL = "eggauth-dev.armosec.io"
)

// KSCloudAPI allows accessing the API of the Kubescape Cloud offering
type KSCloudAPI struct {
	httpClient *http.Client
	apiURL     string
	authURL    string
	erURL      string
	feURL      string
	accountID  string
	clientID   string
	secretKey  string
	authCookie string
	feToken    FeLoginResponse
	loggedIn   bool
}

var globalKSCloudAPIConnector *KSCloudAPI

func SetKSCloudAPIConnector(ksCloudAPI *KSCloudAPI) {
	logger.L().Debug("Kubescape Cloud URLs", helpers.String("api", ksCloudAPI.apiURL), helpers.String("auth", ksCloudAPI.authURL), helpers.String("report", ksCloudAPI.erURL), helpers.String("UI", ksCloudAPI.feURL))
	globalKSCloudAPIConnector = ksCloudAPI
}

func GetKSCloudAPIConnector() *KSCloudAPI {
	if globalKSCloudAPIConnector == nil {
		SetKSCloudAPIConnector(NewKSCloudAPIProd())
	}
	return globalKSCloudAPIConnector
}

func NewKSCloudAPIDev() *KSCloudAPI {
	apiObj := newKSCloudAPI()

	apiObj.apiURL = ksCloudDevBEURL
	apiObj.authURL = ksCloudDevAUTHURL
	apiObj.erURL = ksCloudDevERURL
	apiObj.feURL = ksCloudDevFEURL

	return apiObj
}

func NewKSCloudAPIProd() *KSCloudAPI {
	apiObj := newKSCloudAPI()

	apiObj.apiURL = ksCloudBEURL
	apiObj.erURL = ksCloudERURL
	apiObj.feURL = ksCloudFEURL
	apiObj.authURL = ksCloudAUTHURL

	return apiObj
}

func NewKSCloudAPIStaging() *KSCloudAPI {
	apiObj := newKSCloudAPI()

	apiObj.apiURL = ksCloudStageBEURL
	apiObj.erURL = ksCloudStageERURL
	apiObj.feURL = ksCloudStageFEURL
	apiObj.authURL = ksCloudStageAUTHURL

	return apiObj
}

func NewKSCloudAPICustomized(ksCloudERURL, ksCloudBEURL, ksCloudFEURL, ksCloudAUTHURL string) *KSCloudAPI {
	apiObj := newKSCloudAPI()

	apiObj.erURL = ksCloudERURL
	apiObj.apiURL = ksCloudBEURL
	apiObj.feURL = ksCloudFEURL
	apiObj.authURL = ksCloudAUTHURL

	return apiObj
}

func newKSCloudAPI() *KSCloudAPI {
	return &KSCloudAPI{
		httpClient: &http.Client{Timeout: time.Duration(61) * time.Second},
		loggedIn:   false,
	}
}

func (api *KSCloudAPI) Post(fullURL string, headers map[string]string, body []byte) (string, error) {
	if headers == nil {
		headers = make(map[string]string)
	}
	api.appendAuthHeaders(headers)
	return HttpPost(api.httpClient, fullURL, headers, body)
}

func (api *KSCloudAPI) Delete(fullURL string, headers map[string]string) (string, error) {
	if headers == nil {
		headers = make(map[string]string)
	}
	api.appendAuthHeaders(headers)
	return HttpDelete(api.httpClient, fullURL, headers)
}
func (api *KSCloudAPI) Get(fullURL string, headers map[string]string) (string, error) {
	if headers == nil {
		headers = make(map[string]string)
	}
	api.appendAuthHeaders(headers)
	return HttpGetter(api.httpClient, fullURL, headers)
}

func (api *KSCloudAPI) GetAccountID() string          { return api.accountID }
func (api *KSCloudAPI) IsLoggedIn() bool              { return api.loggedIn }
func (api *KSCloudAPI) GetClientID() string           { return api.clientID }
func (api *KSCloudAPI) GetSecretKey() string          { return api.secretKey }
func (api *KSCloudAPI) GetFrontendURL() string        { return api.feURL }
func (api *KSCloudAPI) GetApiURL() string             { return api.apiURL }
func (api *KSCloudAPI) GetAuthURL() string            { return api.authURL }
func (api *KSCloudAPI) GetReportReceiverURL() string  { return api.erURL }
func (api *KSCloudAPI) SetAccountID(accountID string) { api.accountID = accountID }
func (api *KSCloudAPI) SetClientID(clientID string)   { api.clientID = clientID }
func (api *KSCloudAPI) SetSecretKey(secretKey string) { api.secretKey = secretKey }

func (api *KSCloudAPI) GetFramework(name string) (*reporthandling.Framework, error) {
	respStr, err := api.Get(api.getFrameworkURL(name), nil)
	if err != nil {
		return nil, nil
	}

	framework := &reporthandling.Framework{}
	if err = JSONDecoder(respStr).Decode(framework); err != nil {
		return nil, err
	}

	return framework, err
}

func (api *KSCloudAPI) GetFrameworks() ([]reporthandling.Framework, error) {
	respStr, err := api.Get(api.getListFrameworkURL(), nil)
	if err != nil {
		return nil, nil
	}

	frameworks := []reporthandling.Framework{}
	if err = JSONDecoder(respStr).Decode(&frameworks); err != nil {
		return nil, err
	}

	return frameworks, err
}

func (api *KSCloudAPI) GetControl(policyName string) (*reporthandling.Control, error) {
	return nil, fmt.Errorf("control api is not public")
}

func (api *KSCloudAPI) GetExceptions(clusterName string) ([]armotypes.PostureExceptionPolicy, error) {
	exceptions := []armotypes.PostureExceptionPolicy{}

	respStr, err := api.Get(api.getExceptionsURL(clusterName), nil)
	if err != nil {
		return nil, err
	}

	if err = JSONDecoder(respStr).Decode(&exceptions); err != nil {
		return nil, err
	}

	return exceptions, nil
}

func (api *KSCloudAPI) GetTenant() (*TenantResponse, error) {
	url := api.getAccountURL()
	if api.accountID != "" {
		url = fmt.Sprintf("%s?customerGUID=%s", url, api.accountID)
	}
	respStr, err := api.Get(url, nil)
	if err != nil {
		return nil, err
	}
	tenant := &TenantResponse{}
	if err = JSONDecoder(respStr).Decode(tenant); err != nil {
		return nil, err
	}
	if tenant.TenantID != "" {
		api.accountID = tenant.TenantID
	}
	return tenant, nil
}

// ControlsInputs  // map[<control name>][<input arguments>]
func (api *KSCloudAPI) GetAccountConfig(clusterName string) (*armotypes.CustomerConfig, error) {
	accountConfig := &armotypes.CustomerConfig{}
	if api.accountID == "" {
		return accountConfig, nil
	}
	respStr, err := api.Get(api.getAccountConfig(clusterName), nil)
	if err != nil {
		return nil, err
	}

	if err = JSONDecoder(respStr).Decode(&accountConfig); err != nil {
		// try with default scope
		respStr, err = api.Get(api.getAccountConfigDefault(clusterName), nil)
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
func (api *KSCloudAPI) GetControlsInputs(clusterName string) (map[string][]string, error) {
	accountConfig, err := api.GetAccountConfig(clusterName)
	if err == nil {
		return accountConfig.Settings.PostureControlInputs, nil
	}
	return nil, err
}

func (api *KSCloudAPI) ListCustomFrameworks() ([]string, error) {
	respStr, err := api.Get(api.getListFrameworkURL(), nil)
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

func (api *KSCloudAPI) ListFrameworks() ([]string, error) {
	respStr, err := api.Get(api.getListFrameworkURL(), nil)
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

func (api *KSCloudAPI) ListControls(l ListType) ([]string, error) {
	return nil, fmt.Errorf("control api is not public")
}

func (api *KSCloudAPI) PostExceptions(exceptions []armotypes.PostureExceptionPolicy) error {

	for i := range exceptions {
		ex, err := json.Marshal(exceptions[i])
		if err != nil {
			return err
		}
		_, err = api.Post(api.exceptionsURL(""), map[string]string{"Content-Type": "application/json"}, ex)
		if err != nil {
			return err
		}
	}
	return nil
}

func (api *KSCloudAPI) DeleteException(exceptionName string) error {

	_, err := api.Delete(api.exceptionsURL(exceptionName), nil)
	if err != nil {
		return err
	}
	return nil
}
func (api *KSCloudAPI) Login() error {
	if api.accountID == "" {
		return fmt.Errorf("failed to login, missing accountID")
	}
	if api.clientID == "" {
		return fmt.Errorf("failed to login, missing clientID")
	}
	if api.secretKey == "" {
		return fmt.Errorf("failed to login, missing secretKey")
	}

	// init URLs
	feLoginData := FeLoginData{ClientId: api.clientID, Secret: api.secretKey}
	body, _ := json.Marshal(feLoginData)

	resp, err := http.Post(api.getApiToken(), "application/json", bytes.NewBuffer(body))
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
	api.feToken = feLoginResponse

	/* Now we have JWT */

	api.authCookie, err = api.getAuthCookie()
	if err != nil {
		return err
	}
	api.loggedIn = true
	return nil
}
