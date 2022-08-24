package v1

import "github.com/kubescape/kubescape/v2/core/cautils"

type Submit struct {
	Credentials cautils.Credentials
}

type Delete struct {
	Credentials cautils.Credentials
}
