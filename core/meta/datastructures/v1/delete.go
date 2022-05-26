package v1

import "github.com/armosec/kubescape/v2/core/cautils"

type DeleteExceptions struct {
	Credentials cautils.Credentials
	Exceptions  []string
}
