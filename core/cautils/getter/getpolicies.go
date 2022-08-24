package getter

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
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

	SetAccountID(accountID string)
	SetClientID(clientID string)
	SetSecretKey(secretKey string)

	GetTenant() (*TenantResponse, error)
}

type IControlsInputsGetter interface {
	GetControlsInputs(clusterName string) (map[string][]string, error)
}
