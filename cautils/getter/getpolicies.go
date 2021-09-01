package getter

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils/opapolicy"
)

const DefaultLocalStore = ".kubescape"

var path string

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

func SaveFrameworkInFile(framework *opapolicy.Framework, path string) error {
	encodedData, _ := json.Marshal(framework)
	err := os.WriteFile(path, []byte(fmt.Sprintf("%v", string(encodedData))), 0644)
	if err != nil {
		return err
	}
	return nil
}

func (drp *DownloadReleasedPolicy) GetFramework(name string) (*opapolicy.Framework, error) {
	drp.setURL(name)
	respStr, err := HttpGetter(drp.httpClient, drp.hostURL)
	if err != nil {
		return nil, err
	}

	framework := &opapolicy.Framework{}
	err = JSONDecoder(respStr).Decode(framework)
	//	SaveFrameworkInFile(framework)
	// store in file
	//

	/*

		1. Public save framework function (framework, path) error
		2. Call the function from Download And GetFramework
		3. export to function: os.Join($HOME, getter.DefaultLocalStore, <name>.json)

	*/
	return framework, err
}

func (drp *DownloadReleasedPolicy) setURL(frameworkName string) error {

	resp, err := http.Get("https://api.github.com/repos/armosec/regolibrary/releases/latest")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || 301 < resp.StatusCode {
		return fmt.Errorf("failed to download file, status code: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return err
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
