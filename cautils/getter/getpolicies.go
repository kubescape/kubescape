package getter

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/opapolicy"
)

type IPolicyGetter interface {
	GetFramework(name string) (*opapolicy.Framework, error)
}

type IExceptionsGetter interface {
	GetExceptions(customerGUID, clusterName string) ([]armotypes.PostureExceptionPolicy, error)
}
type IBackend interface {
	GetCustomerGUID(customerGUID string) (*TenantResponse, error)
}
