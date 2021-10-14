package getter

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/opa-utils/reporthandling"
)

type IPolicyGetter interface {
	GetFramework(name string) (*reporthandling.Framework, error)
}

type IExceptionsGetter interface {
	GetExceptions(customerGUID, clusterName string) ([]armotypes.PostureExceptionPolicy, error)
}
type IBackend interface {
	GetCustomerGUID(customerGUID string) (*TenantResponse, error)
}
