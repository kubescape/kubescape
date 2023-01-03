package getter

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
)

type IPolicyGetter interface {
	GetFramework(name string) (*reporthandling.Framework, error)
	GetFrameworks() ([]reporthandling.Framework, error)
	GetControl(ID string) (*reporthandling.Control, error)

	ListFrameworks() ([]string, error)
	ListControls() ([]string, error)
}

type IExceptionsGetter interface {
	GetExceptions(clusterName string) ([]armotypes.PostureExceptionPolicy, error)
}
type IBackend interface {
	GetAccountID() string
	GetClientID() string
	GetSecretKey() string
	GetCloudReportURL() string
	GetCloudAPIURL() string
	GetCloudUIURL() string
	GetCloudAuthURL() string

	SetAccountID(accountID string)
	SetClientID(clientID string)
	SetSecretKey(secretKey string)
	SetCloudReportURL(cloudReportURL string)
	SetCloudAPIURL(cloudAPIURL string)
	SetCloudUIURL(cloudUIURL string)
	SetCloudAuthURL(cloudAuthURL string)

	GetTenant() (*TenantResponse, error)
}

type IControlsInputsGetter interface {
	GetControlsInputs(clusterName string) (map[string][]string, error)
}

type IAttackTracksGetter interface {
	GetAttackTracks() ([]v1alpha1.AttackTrack, error)
}
