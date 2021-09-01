package getter

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/armosec/kubescape/cautils/opapolicy"
)

const DefaultLocalStore = ".kubescape"

type IPolicyGetter interface {
	GetFramework(name string) (*opapolicy.Framework, error)
}

// =======================================================================================================================
// ======================================== DownloadReleasedPolicy =======================================================
// =======================================================================================================================

// Download released version
type DownloadReleasedPolicy struct {
	hostURL    string
	httpClient *http.Client
}

func NewDownloadReleasedPolicy() *DownloadReleasedPolicy {
	return &DownloadReleasedPolicy{
		hostURL:    "",
		httpClient: &http.Client{},
	}
}

func (drp *DownloadReleasedPolicy) GetFramework(name string) (*opapolicy.Framework, error) {
	drp.setURL(name)
	respStr, err := HttpGetter(drp.httpClient, drp.hostURL)
	if err != nil {
		return nil, err
	}

	framework := &opapolicy.Framework{}
	err = JSONDecoder(respStr).Decode(framework)
	return framework, err
}

func (drp *DownloadReleasedPolicy) setURL(frameworkName string) {
	// requestURI := "v1/armoFrameworks"

	// drp.hostURL = URLEncoder(fmt.Sprintf("%s/%s", drp.hostURL, requestURI))
}

// =======================================================================================================================
// ============================================== LoadPolicy =============================================================
// =======================================================================================================================

// Load policies from a local repository
type LoadPolicy struct {
	filePath string
}

func NewLoadPolicy(filePath string) *LoadPolicy {
	return &LoadPolicy{
		filePath: filePath,
	}
}

func (lp *LoadPolicy) GetFramework(filename string) (*opapolicy.Framework, error) {

	framework := &opapolicy.Framework{}
	f, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(f, framework)
	return framework, err
}

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

	framework := opapolicy.Framework{}
	err = JSONDecoder(respStr).Decode(&framework)
	return &framework, err
}

func (armoAPI *ArmoAPI) setURL(frameworkName string) {
	requestURI := "v1/armoFrameworks"
	requestURI += fmt.Sprintf("?customerGUID=%s", "11111111-1111-1111-1111-111111111111")
	requestURI += fmt.Sprintf("&frameworkName=%s", strings.ToUpper(frameworkName))
	requestURI += "&getRules=true"

	armoAPI.hostURL = urlEncoder(fmt.Sprintf("%s/%s", armoAPI.hostURL, requestURI))
}
