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
	if err = JSONDecoder(respStr).Decode(framework); err != nil {
		return framework, err
	}

	SaveFrameworkInFile(framework, GetDefaultPath(name))
	return framework, err
}

func (drp *DownloadReleasedPolicy) setURL(frameworkName string) error {

	latestReleases := "https://api.github.com/repos/armosec/regolibrary/releases/latest"
	resp, err := http.Get(latestReleases)
	if err != nil {
		return fmt.Errorf("failed to get latest releases from '%s', reason: %s", latestReleases, err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || 301 < resp.StatusCode {
		return fmt.Errorf("failed to download file, status code: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body from '%s', reason: %s", latestReleases, err.Error())
	}
	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response body from '%s', reason: %s", latestReleases, err.Error())
	}

	if assets, ok := data["assets"].([]interface{}); ok {
		for i := range assets {
			if asset, ok := assets[i].(map[string]interface{}); ok {
				if name, ok := asset["name"].(string); ok {
					if name == frameworkName {
						if url, ok := asset["browser_download_url"].(string); ok {
							drp.hostURL = url
						}
					}
				}
			}
		}
	}
	return nil

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

func (lp *LoadPolicy) GetFramework(frameworkName string) (*opapolicy.Framework, error) {

	framework := &opapolicy.Framework{}
	f, err := ioutil.ReadFile(lp.filePath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(f, framework)
	if frameworkName != "" && !strings.EqualFold(frameworkName, framework.Name) {
		return nil, fmt.Errorf("framework from file not matching")
	}
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
