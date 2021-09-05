package getter

import (
	"github.com/armosec/kubescape/cautils/armotypes"
	"github.com/armosec/kubescape/cautils/opapolicy"
)

type IPolicyGetter interface {
	GetFramework(name string) (*opapolicy.Framework, error)
	GetExceptions(customerGUID, clusterName string) ([]armotypes.PostureExceptionPolicy, error)
	// GetScores(scope, customerName, namespace string) ([]armotypes.PostureExceptionPolicy, error)
}
