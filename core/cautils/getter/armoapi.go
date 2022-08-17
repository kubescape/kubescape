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
	"github.com/armosec/opa-utils/reporthandling"
	logger "github.com/dwertent/go-logger"
	"github.com/dwertent/go-logger/helpers"
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
	feToken    FeLoginResponse
	authCookie string
	loggedIn   bool
}

var globalKSCloudAPIConnector *KSCloudAPI

func SetKSCloudAPIConnector(ksCloudAPI *KSCloudAPI) {
	logger.L().Debug("Armo URLs", helpers.String("api", ksCloudAPI.apiURL), helpers.String("auth", ksCloudAPI.authURL), helpers.String("report", ksCloudAPI.erURL), helpers.String("UI", ksCloudAPI.feURL))
	globalKSCloudAPIConnector = ksCloudAPI
}

func GetKSCloudAPIConnector() *KSCloudAPI {
	if globalKSCloudAPIConnector == nil {
		SetKSCloudAPIConnector(NewKSCloudAPIProd())
	}
	return globalKSCloudAPIConnector
}

func NewKSCloudAPIDev() *KSCloudAPI {
	apiObj := newArmoAPI()

	apiObj.apiURL = ksCloudDevBEURL
	apiObj.authURL = ksCloudDevAUTHURL
	apiObj.erURL = ksCloudDevERURL
	apiObj.feURL = ksCloudDevFEURL

	return apiObj
}

func NewKSCloudAPIProd() *KSCloudAPI {
	apiObj := newArmoAPI()

	apiObj.apiURL = ksCloudBEURL
	apiObj.erURL = ksCloudERURL
	apiObj.feURL = ksCloudFEURL
	apiObj.authURL = ksCloudAUTHURL

	return apiObj
}

func NewKSCloudAPIStaging() *KSCloudAPI {
	apiObj := newArmoAPI()

	apiObj.apiURL = ksCloudStageBEURL
	apiObj.erURL = ksCloudStageERURL
	apiObj.feURL = ksCloudStageFEURL
	apiObj.authURL = ksCloudStageAUTHURL

	return apiObj
}

func NewARMOAPICustomized(armoERURL, armoBEURL, armoFEURL, armoAUTHURL string) *KSCloudAPI {
	apiObj := newArmoAPI()

	apiObj.erURL = armoERURL
	apiObj.apiURL = armoBEURL
	apiObj.feURL = armoFEURL
	apiObj.authURL = armoAUTHURL

	return apiObj
}

func newArmoAPI() *KSCloudAPI {
	return &KSCloudAPI{
		httpClient: &http.Client{Timeout: time.Duration(61) * time.Second},
		loggedIn:   false,
	}
}

func (armoAPI *KSCloudAPI) Post(fullURL string, headers map[string]string, body []byte) (string, error) {
	if headers == nil {
		headers = make(map[string]string)
	}
	armoAPI.appendAuthHeaders(headers)
	return HttpPost(armoAPI.httpClient, fullURL, headers, body)
}

func (armoAPI *KSCloudAPI) Delete(fullURL string, headers map[string]string) (string, error) {
	if headers == nil {
		headers = make(map[string]string)
	}
	armoAPI.appendAuthHeaders(headers)
	return HttpDelete(armoAPI.httpClient, fullURL, headers)
}
func (armoAPI *KSCloudAPI) Get(fullURL string, headers map[string]string) (string, error) {
	if headers == nil {
		headers = make(map[string]string)
	}
	armoAPI.appendAuthHeaders(headers)
	return HttpGetter(armoAPI.httpClient, fullURL, headers)
}

func (armoAPI *KSCloudAPI) GetAccountID() string          { return armoAPI.accountID }
func (armoAPI *KSCloudAPI) IsLoggedIn() bool              { return armoAPI.loggedIn }
func (armoAPI *KSCloudAPI) GetClientID() string           { return armoAPI.clientID }
func (armoAPI *KSCloudAPI) GetSecretKey() string          { return armoAPI.secretKey }
func (armoAPI *KSCloudAPI) GetFrontendURL() string        { return armoAPI.feURL }
func (armoAPI *KSCloudAPI) GetApiURL() string             { return armoAPI.apiURL }
func (armoAPI *KSCloudAPI) GetAuthURL() string            { return armoAPI.authURL }
func (armoAPI *KSCloudAPI) GetReportReceiverURL() string  { return armoAPI.erURL }
func (armoAPI *KSCloudAPI) SetAccountID(accountID string) { armoAPI.accountID = accountID }
func (armoAPI *KSCloudAPI) SetClientID(clientID string)   { armoAPI.clientID = clientID }
func (armoAPI *KSCloudAPI) SetSecretKey(secretKey string) { armoAPI.secretKey = secretKey }

func (armoAPI *KSCloudAPI) GetFramework(name string) (*reporthandling.Framework, error) {
	respStr, err := armoAPI.Get(armoAPI.getFrameworkURL(name), nil)
	if err != nil {
		return nil, nil
	}

	framework := &reporthandling.Framework{}
	if err = JSONDecoder(respStr).Decode(framework); err != nil {
		return nil, err
	}

	return framework, err
}

func (armoAPI *KSCloudAPI) GetFrameworks() ([]reporthandling.Framework, error) {
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

func (armoAPI *KSCloudAPI) GetControl(policyName string) (*reporthandling.Control, error) {
	return nil, fmt.Errorf("control api is not public")
}

func (armoAPI *KSCloudAPI) GetExceptions(clusterName string) ([]armotypes.PostureExceptionPolicy, error) {
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

func (armoAPI *KSCloudAPI) GetTenant() (*TenantResponse, error) {
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
func (armoAPI *KSCloudAPI) GetAccountConfig(clusterName string) (*armotypes.CustomerConfig, error) {
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
func (armoAPI *KSCloudAPI) GetControlsInputs(clusterName string) (map[string][]string, error) {
	accountConfig, err := armoAPI.GetAccountConfig(clusterName)
	if err == nil {
		return accountConfig.Settings.PostureControlInputs, nil
	}
	return nil, err
}

func (armoAPI *KSCloudAPI) ListCustomFrameworks() ([]string, error) {
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

func (armoAPI *KSCloudAPI) ListFrameworks() ([]string, error) {
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

func (armoAPI *KSCloudAPI) ListControls(l ListType) ([]string, error) {
	return nil, fmt.Errorf("control api is not public")
}

func (armoAPI *KSCloudAPI) PostExceptions(exceptions []armotypes.PostureExceptionPolicy) error {

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

func (armoAPI *KSCloudAPI) DeleteException(exceptionName string) error {

	_, err := armoAPI.Delete(armoAPI.exceptionsURL(exceptionName), nil)
	if err != nil {
		return err
	}
	return nil
}
func (armoAPI *KSCloudAPI) Login() error {
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
