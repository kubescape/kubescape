package getter

import (
	"github.com/armosec/kubescape/cautils/armotypes"
	"github.com/armosec/kubescape/cautils/opapolicy"
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
