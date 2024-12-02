package getter

import (
	"bytes"
	"io"
	"net/http"

	v1 "github.com/kubescape/backend/pkg/client/v1"
	utils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

var (
	// globalKSCloudAPIConnector is a static global instance of the KS Cloud client,
	// to be initialized with SetKSCloudAPIConnector.
	globalKSCloudAPIConnector *v1.KSCloudAPI

	_ IPolicyGetter         = &v1.KSCloudAPI{}
	_ IExceptionsGetter     = &v1.KSCloudAPI{}
	_ IAttackTracksGetter   = &v1.KSCloudAPI{}
	_ IControlsInputsGetter = &v1.KSCloudAPI{}
)

// SetKSCloudAPIConnector registers a global instance of the KS Cloud client.
//
// NOTE: cannot be used concurrently.
func SetKSCloudAPIConnector(ksCloudAPI *v1.KSCloudAPI) {
	if ksCloudAPI != nil && ksCloudAPI.GetCloudAPIURL() != "" {
		logger.L().Debug("setting global KS Cloud API connector",
			helpers.String("accountID", ksCloudAPI.GetAccountID()),
			helpers.String("cloudAPIURL", ksCloudAPI.GetCloudAPIURL()),
			helpers.String("cloudReportURL", ksCloudAPI.GetCloudReportURL()))
	}
	globalKSCloudAPIConnector = ksCloudAPI
}

// GetKSCloudAPIConnector returns a shallow clone of the KS Cloud client registered for this package.
//
// NOTE: cannot be used concurrently with SetKSCloudAPIConnector.
func GetKSCloudAPIConnector() *v1.KSCloudAPI {
	if globalKSCloudAPIConnector == nil {
		SetKSCloudAPIConnector(v1.NewEmptyKSCloudAPI())
	}

	// we return a shallow clone that may be freely modified by the caller.
	client := *globalKSCloudAPIConnector
	options := *globalKSCloudAPIConnector.KsCloudOptions
	client.KsCloudOptions = &options

	return &client
}

// HTTPPost provides a low-level utility that sends a POST request to a given url
func HTTPPost(client *http.Client, fullURL string, body []byte, headers map[string]string) (io.ReadCloser, int64, error) {

	req, err := http.NewRequest(http.MethodPost, fullURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, 0, err
	}
	setHeaders(req, headers)

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, 0, utils.ErrAPI(resp)
	}

	return resp.Body, resp.ContentLength, err

}
