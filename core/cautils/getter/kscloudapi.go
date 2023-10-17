package getter

import (
	v1 "github.com/kubescape/backend/pkg/client/v1"
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
	if ksCloudAPI != nil {
		logger.L().Debug("setting global KS Cloud API connector",
			helpers.String("accountID", ksCloudAPI.GetAccountID()),
			helpers.String("cloudAPIURL", ksCloudAPI.GetCloudAPIURL()),
			helpers.String("cloudReportURL", ksCloudAPI.GetCloudReportURL()))
	} else {
		logger.L().Debug("setting global KS Cloud API connector (nil)")
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
