package getter

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	// Kubescape API endpoints

	// production
	ksCloudERURL   = "report.armo.cloud" // API reports URL
	ksCloudBEURL   = "api.armosec.io"    // API backend URL
	ksCloudFEURL   = "cloud.armosec.io"  // API frontend (UI) URIL
	ksCloudAUTHURL = "auth.armosec.io"   // API login URL

	// staging
	ksCloudStageERURL   = "report-ks.eustage2.cyberarmorsoft.com"
	ksCloudStageBEURL   = "api-stage.armosec.io"
	ksCloudStageFEURL   = "armoui-stage.armosec.io"
	ksCloudStageAUTHURL = "eggauth-stage.armosec.io"

	// dev
	ksCloudDevERURL   = "report.eudev3.cyberarmorsoft.com"
	ksCloudDevBEURL   = "api-dev.armosec.io"
	ksCloudDevFEURL   = "cloud-dev.armosec.io"
	ksCloudDevAUTHURL = "eggauth-dev.armosec.io"

	// Kubescape API routes
	pathAttackTracks    = "/api/v1/attackTracks"
	pathFrameworks      = "/api/v1/armoFrameworks"
	pathExceptions      = "/api/v1/armoPostureExceptions"
	pathTenant          = "/api/v1/tenants/createTenant"
	pathExceptionPolicy = "/api/v1/postureExceptionPolicy"
	pathCustomerConfig  = "/api/v1/armoCustomerConfiguration"
	pathLogin           = "/identity/resources/auth/v1/api-token"
	pathToken           = "/api/v1/openid_customers" //nolint:gosec

	// reports upload route
	pathReport = "/k8s/v2/postureReport"

	// Kubescape UI routes
	pathUIScan       = "/compliance/%s"
	pathUIRBAC       = "/rbac-visualizer"
	pathUIRepository = "/repository-scanning/%s"
	pathUIDashboard  = "/dashboard/"
	pathUISign       = "/account/sign-up"
)

const (
	// default dummy GUID when not defined
	fallbackGUID = "11111111-1111-1111-1111-111111111111"

	// URL query parameters
	queryParamGUID          = "customerGUID"
	queryParamScope         = "scope"
	queryParamFrameworkName = "frameworkName"
	queryParamPolicyName    = "policyName"
	queryParamClusterName   = "clusterName"
	queryParamContextName   = "contextName"

	queryParamUTMSource = "utm_source"
	queryParamUTMMedium = "utm_medium"
	// queryParamUTMCampaign     = "utm_campaign"
	queryParamReport          = "reportGUID"
	queryParamInvitationToken = "invitationToken"

	authenticationCookie = "auth"
)

var (
	// Errors returned by the API

	ErrLoginMissingAccountID = errors.New("failed to login, missing accountID")
	ErrLoginMissingClientID  = errors.New("failed to login, missing clientID")
	ErrLoginMissingSecretKey = errors.New("failed to login, missing secretKey")
	ErrAPINotPublic          = errors.New("control api is not public")
)

var (
	// globalKSCloudAPIConnector is a static global instance of the KS Cloud client,
	// to be initialized with SetKSCloudAPIConnector.
	globalKSCloudAPIConnector *KSCloudAPI

	_ IPolicyGetter         = &KSCloudAPI{}
	_ IExceptionsGetter     = &KSCloudAPI{}
	_ IAttackTracksGetter   = &KSCloudAPI{}
	_ IControlsInputsGetter = &KSCloudAPI{}
)

// KSCloudAPI allows to access the API of the Kubescape Cloud offering.
type KSCloudAPI struct {
	authCookie *http.Cookie
	*ksCloudOptions
	authhost        string
	cloudAPIURL     string
	secretKey       string
	accountID       string
	cloudAuthURL    string
	invitationToken string
	reporthost      string
	scheme          string
	host            string
	authscheme      string
	clientID        string
	uischeme        string
	uihost          string
	reportscheme    string
	feToken         feLoginResponse
	loggedIn        bool
}

// SetKSCloudAPIConnector registers a global instance of the KS Cloud client.
//
// NOTE: cannot be used concurrently.
func SetKSCloudAPIConnector(ksCloudAPI *KSCloudAPI) {
	globalKSCloudAPIConnector = ksCloudAPI
}

// GetKSCloudAPIConnector returns a shallow clone of the KS Cloud client registered for this package.
//
// NOTE: cannot be used concurrently with SetKSCloudAPIConnector.
func GetKSCloudAPIConnector() *KSCloudAPI {
	if globalKSCloudAPIConnector == nil {
		SetKSCloudAPIConnector(NewKSCloudAPIProd())
	}

	// we return a shallow clone that may be freely modified by the caller.
	client := *globalKSCloudAPIConnector
	options := *globalKSCloudAPIConnector.ksCloudOptions
	client.ksCloudOptions = &options

	return &client
}

// NewKSCloudAPIDev returns a KS Cloud client pointing to a development environment.
func NewKSCloudAPIDev(opts ...KSCloudOption) *KSCloudAPI {
	devOpts := []KSCloudOption{
		WithFrontendURL(ksCloudDevFEURL),
		WithReportURL(ksCloudDevERURL),
	}
	devOpts = append(devOpts, opts...)

	apiObj := newKSCloudAPI(
		ksCloudDevBEURL,
		ksCloudDevAUTHURL,
		devOpts...,
	)

	return apiObj
}

// NewKSCloudAPIDProd returns a KS Cloud client pointing to a production environment.
func NewKSCloudAPIProd(opts ...KSCloudOption) *KSCloudAPI {
	prodOpts := []KSCloudOption{
		WithFrontendURL(ksCloudFEURL),
		WithReportURL(ksCloudERURL),
	}
	prodOpts = append(prodOpts, opts...)

	return newKSCloudAPI(
		ksCloudBEURL,
		ksCloudAUTHURL,
		prodOpts...,
	)
}

// NewKSCloudAPIStaging returns a KS Cloud client pointing to a testing environment.
func NewKSCloudAPIStaging(opts ...KSCloudOption) *KSCloudAPI {
	stagingOpts := []KSCloudOption{
		WithFrontendURL(ksCloudStageFEURL),
		WithReportURL(ksCloudStageERURL),
	}
	stagingOpts = append(stagingOpts, opts...)

	return newKSCloudAPI(
		ksCloudStageBEURL,
		ksCloudStageAUTHURL,
		stagingOpts...,
	)
}

// NewKSCloudAPICustomed returns a KS Cloud client with configurable API and authentication endpoints.
func NewKSCloudAPICustomized(ksCloudAPIURL, ksCloudAuthURL string, opts ...KSCloudOption) *KSCloudAPI {
	return newKSCloudAPI(
		ksCloudAPIURL,
		ksCloudAuthURL,
		opts...,
	)
}

func newKSCloudAPI(apiURL, authURL string, opts ...KSCloudOption) *KSCloudAPI {
	api := &KSCloudAPI{
		cloudAPIURL:    apiURL,
		cloudAuthURL:   authURL,
		ksCloudOptions: ksCloudOptionsWithDefaults(opts),
	}

	api.SetCloudAPIURL(apiURL)
	api.SetCloudAuthURL(authURL)
	api.SetCloudUIURL(api.cloudUIURL)
	api.SetCloudReportURL(api.cloudReportURL)

	return api
}

// Get retrieves an API resource.
//
// The response is serialized as a string.
//
// The caller may specify extra headers.
//
// By default, all authentication headers are added.
func (api *KSCloudAPI) Get(fullURL string, headers map[string]string) (string, error) {
	rdr, size, err := api.get(fullURL, withExtraHeaders(headers))
	if err != nil {
		return "", err
	}
	defer rdr.Close()

	return readString(rdr, size)
}

// Post creates an API resource.
//
// The response is serialized as a string.
//
// The caller may specify extra headers.
//
// By default, the body content type is set to JSON and all authentication headers are added.
func (api *KSCloudAPI) Post(fullURL string, headers map[string]string, body []byte) (string, error) {
	rdr, size, err := api.post(fullURL, body, withContentJSON(true), withExtraHeaders(headers))
	if err != nil {
		return "", err
	}
	defer rdr.Close()

	return readString(rdr, size)
}

// Delete an API resource.
//
// The response is serialized as a string.
//
// The caller may specify extra headers.
//
// By default, all authentication headers are added.
func (api *KSCloudAPI) Delete(fullURL string, headers map[string]string) (string, error) {
	rdr, size, err := api.delete(fullURL, withExtraHeaders(headers))
	if err != nil {
		return "", err
	}
	defer rdr.Close()

	return readString(rdr, size)
}

// GetAccountID returns the customer account's GUID.
func (api *KSCloudAPI) GetAccountID() string { return api.accountID }

// IsLoggedIn indicates if the client has sucessfully authenticated.
func (api *KSCloudAPI) IsLoggedIn() bool { return api.loggedIn }

func (api *KSCloudAPI) GetClientID() string        { return api.clientID }
func (api *KSCloudAPI) GetSecretKey() string       { return api.secretKey }
func (api *KSCloudAPI) GetCloudReportURL() string  { return api.cloudReportURL }
func (api *KSCloudAPI) GetCloudAPIURL() string     { return api.cloudAPIURL }
func (api *KSCloudAPI) GetCloudUIURL() string      { return api.cloudUIURL }
func (api *KSCloudAPI) GetCloudAuthURL() string    { return api.cloudAuthURL }
func (api *KSCloudAPI) GetInvitationToken() string { return api.invitationToken }

func (api *KSCloudAPI) SetAccountID(accountID string)   { api.accountID = accountID }
func (api *KSCloudAPI) SetClientID(clientID string)     { api.clientID = clientID }
func (api *KSCloudAPI) SetSecretKey(secretKey string)   { api.secretKey = secretKey }
func (api *KSCloudAPI) SetInvitationToken(token string) { api.invitationToken = token }

func (api *KSCloudAPI) SetCloudAPIURL(cloudAPIURL string) {
	api.cloudAPIURL = cloudAPIURL
	api.scheme, api.host = parseHost(cloudAPIURL)
}

func (api *KSCloudAPI) SetCloudUIURL(cloudUIURL string) {
	api.cloudUIURL = cloudUIURL
	api.uischeme, api.uihost = parseHost(cloudUIURL)
}

func (api *KSCloudAPI) SetCloudAuthURL(cloudAuthURL string) {
	api.cloudAuthURL = cloudAuthURL
	api.authscheme, api.authhost = parseHost(cloudAuthURL)
}

func (api *KSCloudAPI) SetCloudReportURL(cloudReportURL string) {
	api.cloudReportURL = cloudReportURL
	api.reportscheme, api.reporthost = parseHost(cloudReportURL)
}

func (api *KSCloudAPI) GetAttackTracks() ([]AttackTrack, error) {
	rdr, _, err := api.get(api.getAttackTracksURL())
	if err != nil {
		return nil, err
	}
	defer rdr.Close()

	attackTracks, err := decode[[]AttackTrack](rdr)
	if err != nil {
		return nil, err
	}

	return attackTracks, nil
}

func (api *KSCloudAPI) getAttackTracksURL() string {
	return api.buildAPIURL(
		pathAttackTracks,
		api.paramsWithGUID()...,
	)
}

// GetFramework retrieves a framework by name.
func (api *KSCloudAPI) GetFramework(frameworkName string) (*Framework, error) {
	rdr, _, err := api.get(api.getFrameworkURL(frameworkName))
	if err != nil {
		return nil, err
	}
	defer rdr.Close()

	framework, err := decode[Framework](rdr)
	if err != nil {
		return nil, err
	}

	return &framework, err
}

func (api *KSCloudAPI) getFrameworkURL(frameworkName string) string {
	if isNativeFramework(frameworkName) {
		// Native framework name is normalized as upper case, but for a custom framework the name remains unaltered
		frameworkName = strings.ToUpper(frameworkName)
	}

	return api.buildAPIURL(
		pathFrameworks,
		append(
			api.paramsWithGUID(),
			queryParamFrameworkName, frameworkName,
		)...,
	)
}

// GetFrameworks returns all registered frameworks.
func (api *KSCloudAPI) GetFrameworks() ([]Framework, error) {
	rdr, _, err := api.get(api.getListFrameworkURL())
	if err != nil {
		return nil, err
	}
	defer rdr.Close()

	frameworks, err := decode[[]Framework](rdr)
	if err != nil {
		return nil, err
	}

	return frameworks, err
}

func (api *KSCloudAPI) getListFrameworkURL() string {
	return api.buildAPIURL(
		pathFrameworks,
		api.paramsWithGUID()...,
	)
}

// ListCustomFrameworks lists the names of all non-native frameworks that have been registered for this account.
func (api *KSCloudAPI) ListCustomFrameworks() ([]string, error) {
	frameworks, err := api.GetFrameworks()
	if err != nil {
		return nil, err
	}

	frameworkList := make([]string, 0, len(frameworks))
	for _, framework := range frameworks {
		if isNativeFramework(framework.Name) {
			continue
		}

		frameworkList = append(frameworkList, framework.Name)
	}

	return frameworkList, nil
}

// ListFrameworks list the names of all registered frameworks.
func (api *KSCloudAPI) ListFrameworks() ([]string, error) {
	frameworks, err := api.GetFrameworks()
	if err != nil {
		return nil, err
	}

	frameworkList := make([]string, 0, len(frameworks))
	for _, framework := range frameworks {
		name := framework.Name
		if isNativeFramework(framework.Name) {
			name = strings.ToLower(framework.Name)
		}

		frameworkList = append(frameworkList, name)
	}

	return frameworkList, nil
}

// GetExceptions returns exception policies.
func (api *KSCloudAPI) GetExceptions(clusterName string) ([]PostureExceptionPolicy, error) {
	rdr, _, err := api.get(api.getExceptionsURL(clusterName))
	if err != nil {
		return nil, err
	}
	defer rdr.Close()

	exceptions, err := decode[[]PostureExceptionPolicy](rdr)
	if err != nil {
		return nil, err
	}

	return exceptions, nil
}

func (api *KSCloudAPI) getExceptionsURL(clusterName string) string {
	return api.buildAPIURL(
		pathExceptions,
		api.paramsWithGUID()...,
	)
	// queryParamClusterName, clusterName, // TODO - fix customer name support in Armo BE
}

// GetTenant retrieves the credentials for the calling tenant.
//
// The tenant ID overides any already provided account ID.
func (api *KSCloudAPI) GetTenant() (*TenantResponse, error) {
	rdr, _, err := api.get(api.getTenantURL())
	if err != nil {
		return nil, err
	}
	defer rdr.Close()

	tenant, err := decode[TenantResponse](rdr)
	if err != nil {
		return nil, err
	}

	if tenant.TenantID != "" {
		api.accountID = tenant.TenantID
	}

	return &tenant, nil
}

func (api *KSCloudAPI) getTenantURL() string {
	var params []string
	if api.accountID != "" {
		params = []string{
			queryParamGUID, api.accountID, // NOTE: no fallback in this case
		}
	}

	return api.buildAPIURL(
		pathTenant,
		params...,
	)
}

// GetAccountConfig yields the account configuration.
func (api *KSCloudAPI) GetAccountConfig(clusterName string) (*CustomerConfig, error) {
	if api.accountID == "" {
		return &CustomerConfig{}, nil
	}

	rdr, _, err := api.get(api.getAccountConfig(clusterName))
	if err != nil {
		return nil, err
	}
	defer rdr.Close()

	accountConfig, err := decode[CustomerConfig](rdr)
	if err != nil {
		// retry with default scope
		rdr, _, err = api.get(api.getAccountConfigDefault(clusterName))
		if err != nil {
			return nil, err
		}
		defer rdr.Close()

		accountConfig, err = decode[CustomerConfig](rdr)
		if err != nil {
			return nil, err
		}
	}

	return &accountConfig, nil
}

func (api *KSCloudAPI) getAccountConfig(clusterName string) string {
	params := api.paramsWithGUID()

	if clusterName != "" { // TODO - fix customer name support in Armo BE
		params = append(params, queryParamClusterName, clusterName)
	}

	return api.buildAPIURL(
		pathCustomerConfig,
		params...,
	)
}

func (api *KSCloudAPI) getAccountConfigDefault(clusterName string) string {
	params := append(
		api.paramsWithGUID(),
		queryParamScope, "customer",
	)

	if clusterName != "" { // TODO - fix customer name support in Armo BE
		params = append(params, queryParamClusterName, clusterName)
	}

	return api.buildAPIURL(
		pathCustomerConfig,
		params...,
	)
}

// GetControlsInputs returns the controls inputs configured in the account configuration.
func (api *KSCloudAPI) GetControlsInputs(clusterName string) (map[string][]string, error) {
	accountConfig, err := api.GetAccountConfig(clusterName)
	if err != nil {
		return nil, err
	}

	return accountConfig.Settings.PostureControlInputs, nil
}

// GetControl is currently not exposed as a public API endpoint.
func (api *KSCloudAPI) GetControl(ID string) (*Control, error) {
	return nil, ErrAPINotPublic
}

// ListControls is currently not exposed as a public API endpoint.
func (api *KSCloudAPI) ListControls() ([]string, error) {
	return nil, ErrAPINotPublic
}

// PostExceptions registers a list of exceptions.
func (api *KSCloudAPI) PostExceptions(exceptions []PostureExceptionPolicy) error {
	target := api.exceptionsURL("")

	for i := range exceptions {
		jazon, err := json.Marshal(exceptions[i])
		if err != nil {
			return err
		}

		_, _, err = api.post(target, jazon, withContentJSON(true))
		if err != nil {
			return err
		}
	}

	return nil
}

// Delete exception removes a registered exception rule.
func (api *KSCloudAPI) DeleteException(exceptionName string) error {
	_, _, err := api.delete(api.exceptionsURL(exceptionName))

	return err
}

func (api *KSCloudAPI) exceptionsURL(exceptionsPolicyName string) string {
	params := api.paramsWithGUID()
	if exceptionsPolicyName != "" { // for delete
		params = append(params, queryParamPolicyName, exceptionsPolicyName)
	}

	return api.buildAPIURL(
		pathExceptionPolicy,
		params...,
	)
}

// SubmitReport uploads a posture report.
func (api *KSCloudAPI) SubmitReport(report *PostureReport) error {
	jazon, err := json.Marshal(report)
	if err != nil {
		return err
	}

	_, _, err = api.post(api.postReportURL(report.ClusterName, report.ReportID), jazon, withContentJSON(true), withToken(api.invitationToken))

	return err
}

func (api *KSCloudAPI) postReportURL(cluster, reportID string) string {
	return api.buildReportURL(pathReport,
		append(
			api.paramsWithGUID(),
			queryParamContextName, cluster,
			queryParamClusterName, cluster, // deprecated
			queryParamReport, reportID,
		)...,
	)
}

// ViewReportURL yields the frontend URL to view a posture report (e.g. from a repository scan).
func (api *KSCloudAPI) ViewReportURL(reportID string) string {
	return api.buildUIURL(
		fmt.Sprintf(pathUIRepository, reportID),
	)
}

// ViewDashboardURL yields the frontend URL for the dashboard.
func (api *KSCloudAPI) ViewDashboardURL() string {
	return api.buildUIURL(
		pathUIDashboard,
	)
}

// ViewRBACURL yields the frontend URL to visualize RBAC.
func (api *KSCloudAPI) ViewRBACURL() string {
	return api.buildUIURL(
		pathUIRBAC,
	)
}

// ViewRBACURL yields the frontend URL to check the compliance of a scanned cluster.
func (api *KSCloudAPI) ViewScanURL(cluster string) string {
	return api.buildUIURL(
		fmt.Sprintf(pathUIScan, cluster),
	)
}

// ViewSignURL yields the frontend login page.
func (api *KSCloudAPI) ViewSignURL() string {
	params := api.paramsWithGUID()
	params = append(params, api.paramsWithUTM()...)
	params = append(params, queryParamInvitationToken, api.invitationToken)

	return api.buildUIURL(
		pathUISign,
		params...,
	)
}

// Login to the KS Cloud using the caller's accountID, clientID and secret key.
func (api *KSCloudAPI) Login() error {
	if err := api.loginRequirements(); err != nil {
		return err
	}

	// 1. acquire auth token
	body, err := json.Marshal(feLoginData{ClientId: api.clientID, Secret: api.secretKey})
	if err != nil {
		return err
	}

	rdr, _, err := api.post(api.authTokenURL(), body, withContentJSON(true))
	if err != nil {
		return err
	}
	defer rdr.Close()

	resp, err := decode[feLoginResponse](rdr)
	if err != nil {
		return err
	}

	api.feToken = resp

	// 2. acquire auth cookie
	// Now that we have the JWT token, acquire a cookie from the API
	api.authCookie, err = api.getAuthCookie()
	if err != nil {
		return err
	}

	api.loggedIn = true

	return nil
}

func (api *KSCloudAPI) authTokenURL() string {
	return api.buildAuthURL(pathLogin)
}

func (api *KSCloudAPI) getOpenidURL() string {
	return api.buildAPIURL(pathToken)
}

func (api *KSCloudAPI) getAuthCookie() (*http.Cookie, error) {
	selectCustomer := ksCloudSelectCustomer{SelectedCustomerGuid: api.accountID}
	body, err := json.Marshal(selectCustomer)
	if err != nil {
		return nil, err
	}

	target := api.getOpenidURL()
	o := api.defaultRequestOptions([]requestOption{withContentJSON(true), withCookie(nil)})
	req, err := http.NewRequestWithContext(o.reqContext, http.MethodPost, target, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	o.setHeaders(req)
	o.traceReq(req)
	resp, err := api.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	o.traceResp(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get cookie from %s: status %d", target, resp.StatusCode)
	}

	for _, cookie := range resp.Cookies() {
		if cookie.Name == authenticationCookie {
			return cookie, nil
		}
	}

	return nil, fmt.Errorf("no auth cookie in response from %s", target)
}

func (api *KSCloudAPI) loginRequirements() error {
	if api.accountID == "" {
		return ErrLoginMissingAccountID
	}

	if api.clientID == "" {
		return ErrLoginMissingClientID
	}

	if api.secretKey == "" {
		return ErrLoginMissingSecretKey
	}

	return nil
}

// defaultRequestOptions adds standard authentication headers to all requests
func (api *KSCloudAPI) defaultRequestOptions(opts []requestOption) *requestOptions {
	optionsWithDefaults := append(make([]requestOption, 0, 4),
		withToken(api.feToken.Token),
		withCookie(api.authCookie),
		withTrace(api.withTrace),
	)
	optionsWithDefaults = append(optionsWithDefaults, opts...)

	return requestOptionsWithDefaults(optionsWithDefaults)
}

func (api *KSCloudAPI) get(fullURL string, opts ...requestOption) (io.ReadCloser, int64, error) {
	o := api.defaultRequestOptions(opts)
	req, err := http.NewRequestWithContext(o.reqContext, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, 0, err
	}

	return api.do(req, o)
}

func (api *KSCloudAPI) post(fullURL string, body []byte, opts ...requestOption) (io.ReadCloser, int64, error) {
	o := api.defaultRequestOptions(opts)
	req, err := http.NewRequestWithContext(o.reqContext, http.MethodPost, fullURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, 0, err
	}

	return api.do(req, o)
}

func (api *KSCloudAPI) delete(fullURL string, opts ...requestOption) (io.ReadCloser, int64, error) {
	o := api.defaultRequestOptions(opts)
	req, err := http.NewRequestWithContext(o.reqContext, http.MethodDelete, fullURL, nil)
	if err != nil {
		return nil, 0, err
	}

	return api.do(req, o)
}

func (api *KSCloudAPI) do(req *http.Request, o *requestOptions) (io.ReadCloser, int64, error) {
	o.setHeaders(req)
	o.traceReq(req)

	resp, err := api.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	o.traceResp(resp)

	if resp.StatusCode >= 400 {
		if req.URL.Path == pathLogin {
			return nil, 0, errAuth(resp)

		}
		return nil, 0, errAPI(resp)
	}

	return resp.Body, resp.ContentLength, err
}

func (api *KSCloudAPI) paramsWithGUID() []string {
	return append(make([]string, 0, 6),
		queryParamGUID, api.getCustomerGUIDFallBack(),
	)
}

func (api *KSCloudAPI) paramsWithUTM() []string {
	return append(make([]string, 0, 6),
		queryParamUTMSource, "ARMOgithub",
		queryParamUTMMedium, "createaccount",
	)
}

func (api *KSCloudAPI) getCustomerGUIDFallBack() string {
	if api.accountID != "" {
		return api.accountID
	}
	return fallbackGUID
}
