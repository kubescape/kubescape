package v1

import "github.com/kubescape/kubescape/v2/core/cautils"

type DeleteExceptions struct {
	Credentials cautils.Credentials
	Exceptions  []string
}
