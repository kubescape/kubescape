package getter

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/armosec/opa-utils/reporthandling"
)

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
		httpClient: &http.Client{Timeout: 61 * time.Second},
	}
}

func (drp *DownloadReleasedPolicy) GetFramework(name string) (*reporthandling.Framework, error) {
	if err := drp.setURL(name); err != nil {
		return nil, err
	}
	respStr, err := HttpGetter(drp.httpClient, drp.hostURL)
	if err != nil {
		return nil, err
	}

	framework := &reporthandling.Framework{}
	if err = JSONDecoder(respStr).Decode(framework); err != nil {
		return framework, err
	}

	SaveFrameworkInFile(framework, GetDefaultPath(name+".json"))
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

	body, err := io.ReadAll(resp.Body)
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
							return nil
						}
					}
				}
			}
		}
	}
	return fmt.Errorf("failed to download '%s' - not found", frameworkName)

}
