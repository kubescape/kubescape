package getter

import (
	v1 "github.com/kubescape/backend/pkg/client/v1"
)

const (
	// Kubescape API endpoints

	// production
	ksCloudERURL = "report.armo.cloud" // API reports URL
	ksCloudBEURL = "api.armosec.io"    // API backend URL

	// staging
	ksCloudStageERURL = "report-ks.eustage2.cyberarmorsoft.com"
	ksCloudStageBEURL = "api-stage.armosec.io"

	// dev
	ksCloudDevERURL = "report.eudev3.cyberarmorsoft.com"
	ksCloudDevBEURL = "api-dev.armosec.io"
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
	globalKSCloudAPIConnector = ksCloudAPI
}

// GetKSCloudAPIConnector returns a shallow clone of the KS Cloud client registered for this package.
//
// NOTE: cannot be used concurrently with SetKSCloudAPIConnector.
func GetKSCloudAPIConnector() *v1.KSCloudAPI {
	if globalKSCloudAPIConnector == nil {
		SetKSCloudAPIConnector(NewKSCloudAPIProd())
	}

	// we return a shallow clone that may be freely modified by the caller.
	client := *globalKSCloudAPIConnector
	options := *globalKSCloudAPIConnector.KsCloudOptions
	client.KsCloudOptions = &options

	return &client
}

// NewKSCloudAPIDev returns a KS Cloud client pointing to a development environment.
func NewKSCloudAPIDev(opts ...v1.KSCloudOption) *v1.KSCloudAPI {
	devOpts := []v1.KSCloudOption{
		v1.WithReportURL(ksCloudDevERURL),
	}
	devOpts = append(devOpts, opts...)

	apiObj := v1.NewKSCloudAPI(
		ksCloudDevBEURL,
		devOpts...,
	)

	return apiObj
}

// NewKSCloudAPIDProd returns a KS Cloud client pointing to a production environment.
func NewKSCloudAPIProd(opts ...v1.KSCloudOption) *v1.KSCloudAPI {
	prodOpts := []v1.KSCloudOption{
		v1.WithReportURL(ksCloudERURL),
	}
	prodOpts = append(prodOpts, opts...)

	return v1.NewKSCloudAPI(
		ksCloudBEURL,
		prodOpts...,
	)
}

// NewKSCloudAPIStaging returns a KS Cloud client pointing to a testing environment.
func NewKSCloudAPIStaging(opts ...v1.KSCloudOption) *v1.KSCloudAPI {
	stagingOpts := []v1.KSCloudOption{
		v1.WithReportURL(ksCloudStageERURL),
	}
	stagingOpts = append(stagingOpts, opts...)

	return v1.NewKSCloudAPI(
		ksCloudStageBEURL,
		stagingOpts...,
	)
}
