package getter

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
)

// supported listing
type ListType string

const ListID ListType = "id"
const ListName ListType = "name"

type IPolicyGetter interface {
	GetFramework(name string) (*reporthandling.Framework, error)
	GetFrameworks() ([]reporthandling.Framework, error)
	GetControl(name string) (*reporthandling.Control, error)

	ListFrameworks() ([]string, error)
	ListControls(ListType) ([]string, error)
}

type IExceptionsGetter interface {
	GetExceptions(clusterName string) ([]armotypes.PostureExceptionPolicy, error)
}
type IBackend interface {
	GetAccountID() string
	GetClientID() string
	GetSecretKey() string
	GetCloudReport() string
	GetCloudAPI() string
	GetCloudUI() string
	GetCloudAuth() string

	SetAccountID(accountID string)
	SetClientID(clientID string)
	SetSecretKey(secretKey string)
	SetCloudReport(cloudReport string)
	SetCloudAPI(cloudAPI string)
	SetCloudUI(cloudUI string)
	SetCloudAuth(cloudAuth string)

	GetTenant() (*TenantResponse, error)
}

type IControlsInputsGetter interface {
	GetControlsInputs(clusterName string) (map[string][]string, error)
}

type IAttackTracksGetter interface {
	GetAttackTracks() ([]v1alpha1.AttackTrack, error)
}
