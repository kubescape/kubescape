package getter

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"

	"github.com/armosec/armoapi-go/armotypes"
	v1 "github.com/kubescape/backend/pkg/client/v1"
	utils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

var (
	// globalKSCloudAPIConnector is a static global instance of the KS Cloud client,
	// to be initialized with SetKSCloudAPIConnector.
	globalKSCloudAPIConnector      *v1.KSCloudAPI
	globalKSCloudAPIConnectorMutex sync.Mutex

	_ IPolicyGetter         = &v1.KSCloudAPI{}
	_ IExceptionsGetter     = &KSCloudAPIAdapter{}
	_ IAttackTracksGetter   = &v1.KSCloudAPI{}
	_ IControlsInputsGetter = &KSCloudAPIAdapter{}
)

// KSCloudAPIAdapter adapts v1.KSCloudAPI to the context-aware getter interfaces.
//
// NOTE: the supplied context is intentionally discarded. The upstream client in
// github.com/kubescape/backend/pkg/client/v1 does not yet expose context-aware
// methods, so cancellation and deadlines do not reach these HTTP calls. Remove
// this adapter once the backend client accepts a context.
type KSCloudAPIAdapter struct {
	*v1.KSCloudAPI
}

// GetKSCloudAPIAdapter returns an adapter wrapping the KS Cloud client registered for this package.
func GetKSCloudAPIAdapter() *KSCloudAPIAdapter {
	return &KSCloudAPIAdapter{
		KSCloudAPI: GetKSCloudAPIConnector(),
	}
}

func (a *KSCloudAPIAdapter) GetExceptions(_ context.Context, clusterName string) ([]armotypes.PostureExceptionPolicy, error) {
	return a.KSCloudAPI.GetExceptions(clusterName)
}

func (a *KSCloudAPIAdapter) GetControlsInputs(_ context.Context, clusterName string) (map[string][]string, error) {
	return a.KSCloudAPI.GetControlsInputs(clusterName)
}

// SetKSCloudAPIConnector registers a global instance of the KS Cloud client.
//
// Thread-safe.
func SetKSCloudAPIConnector(ksCloudAPI *v1.KSCloudAPI) {
	if ksCloudAPI != nil && ksCloudAPI.GetCloudAPIURL() != "" {
		logger.L().Debug("setting global KS Cloud API connector",
			helpers.String("accountID", ksCloudAPI.GetAccountID()),
			helpers.String("cloudAPIURL", ksCloudAPI.GetCloudAPIURL()),
			helpers.String("cloudReportURL", ksCloudAPI.GetCloudReportURL()))
	}
	globalKSCloudAPIConnectorMutex.Lock()
	globalKSCloudAPIConnector = ksCloudAPI
	globalKSCloudAPIConnectorMutex.Unlock()
}

// GetKSCloudAPIConnector returns a shallow clone of the KS Cloud client registered for this package.
//
// Thread-safe.
func GetKSCloudAPIConnector() *v1.KSCloudAPI {
	globalKSCloudAPIConnectorMutex.Lock()
	defer globalKSCloudAPIConnectorMutex.Unlock()

	if globalKSCloudAPIConnector == nil {
		globalKSCloudAPIConnector = v1.NewEmptyKSCloudAPI()
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
