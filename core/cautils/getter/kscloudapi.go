package getter

import (
	"github.com/armosec/armoapi-go/armotypes"
	v1 "github.com/kubescape/backend/pkg/client/v1"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
)

var (
	// globalKSCloudAPIConnector is a static global instance of the KS Cloud client,
	// to be initialized with SetKSCloudAPIConnector.
	globalKSCloudAPIConnector *v1.KSCloudAPI

	_ IPolicyGetter         = &KSCloudAPIWrapper{v1.KSCloudAPI{}, ""}
	_ IExceptionsGetter     = &KSCloudAPIWrapper{v1.KSCloudAPI{}, ""}
	_ IAttackTracksGetter   = &KSCloudAPIWrapper{v1.KSCloudAPI{}, ""}
	_ IControlsInputsGetter = &KSCloudAPIWrapper{v1.KSCloudAPI{}, ""}
)

type KSCloudAPIWrapper struct {
	v1.KSCloudAPI
	accessToken string
}

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
func GetKSCloudAPIConnector() *KSCloudAPIWrapper {
	if globalKSCloudAPIConnector == nil {
		SetKSCloudAPIConnector(v1.NewEmptyKSCloudAPI())
	}

	// we return a shallow clone that may be freely modified by the caller.
	client := KSCloudAPIWrapper{*globalKSCloudAPIConnector, ""}
	options := *globalKSCloudAPIConnector.KsCloudOptions
	client.KSCloudAPI.KsCloudOptions = &options

	return &client
}

func (ksc *KSCloudAPIWrapper) SetAccessToken(accessToken string) {
	ksc.accessToken = accessToken
}

func (ksc *KSCloudAPIWrapper) GetControl(ID string) (*reporthandling.Control, error) {
	var control *reporthandling.Control
	var err error

	control, err = ksc.KSCloudAPI.GetControl(ID)
	if err != nil {
		return nil, err
	}
	return control, nil
}

func (ksc *KSCloudAPIWrapper) setHeaders(accessToken string) map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + accessToken,
	}
}

func (ksc *KSCloudAPIWrapper) GetFramework(name string) (*reporthandling.Framework, error) {
	var reqOpts []v1.RequestOption
	reqOpts = append(reqOpts, v1.WithContentJSON(true))
	reqOpts = append(reqOpts, v1.WithHeaders(ksc.setHeaders(ksc.accessToken)))

	framework, err := ksc.KSCloudAPI.GetFramework(name, reqOpts...)
	if err != nil {
		return nil, err
	}
	return framework, err
}

func (ksc *KSCloudAPIWrapper) GetFrameworks() ([]reporthandling.Framework, error) {
	var reqOpts []v1.RequestOption
	reqOpts = append(reqOpts, v1.WithContentJSON(true))
	reqOpts = append(reqOpts, v1.WithHeaders(ksc.setHeaders(ksc.accessToken)))

	frameworks, err := ksc.KSCloudAPI.GetFrameworks(reqOpts...)
	if err != nil {
		return nil, err
	}
	return frameworks, err
}

func (ksc *KSCloudAPIWrapper) ListFrameworks() ([]string, error) {
	var frameworkNames []string
	var reqOpts []v1.RequestOption

	reqOpts = append(reqOpts, v1.WithContentJSON(true))
	reqOpts = append(reqOpts, v1.WithHeaders(ksc.setHeaders(ksc.accessToken)))

	frameworks, err := ksc.KSCloudAPI.GetFrameworks(reqOpts...)
	if err != nil {
		return nil, err
	}
	for i := range frameworks {
		frameworkNames = append(frameworkNames, frameworks[i].Name)
	}

	return frameworkNames, nil
}

func (ksc *KSCloudAPIWrapper) ListControls() ([]string, error) {
	controlsIDsList, err := ksc.KSCloudAPI.ListControls()
	if err != nil {
		return []string{}, err
	}
	return controlsIDsList, nil
}

func (ksc *KSCloudAPIWrapper) GetControlsInputs(clusterName string) (map[string][]string, error) {
	var reqOpts []v1.RequestOption

	reqOpts = append(reqOpts, v1.WithContentJSON(true))
	reqOpts = append(reqOpts, v1.WithHeaders(ksc.setHeaders(ksc.accessToken)))

	defaultConfigInputs, err := ksc.KSCloudAPI.GetControlsInputs(clusterName, reqOpts...)
	if err != nil {
		return nil, err
	}
	return defaultConfigInputs, err
}

func (ksc *KSCloudAPIWrapper) GetAttackTracks() ([]v1alpha1.AttackTrack, error) {
	var reqOpts []v1.RequestOption

	reqOpts = append(reqOpts, v1.WithContentJSON(true))
	reqOpts = append(reqOpts, v1.WithHeaders(ksc.setHeaders(ksc.accessToken)))

	attackTracks, err := ksc.KSCloudAPI.GetAttackTracks(reqOpts...)
	if err != nil {
		return nil, err
	}
	return attackTracks, err
}

func (ksc *KSCloudAPIWrapper) GetExceptions(clusterName string) ([]armotypes.PostureExceptionPolicy, error) {
	var reqOpts []v1.RequestOption

	reqOpts = append(reqOpts, v1.WithContentJSON(true))
	reqOpts = append(reqOpts, v1.WithHeaders(ksc.setHeaders(ksc.accessToken)))

	exceptions, err := ksc.KSCloudAPI.GetExceptions(clusterName, reqOpts...)
	if err != nil {
		return nil, err
	}
	return exceptions, nil
}
