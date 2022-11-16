package v1

import "github.com/kubescape/kubescape/v2/core/cautils"

type ListPolicies struct {
	Target      string
	Format      string
	Credentials cautils.Credentials
}

type ListResponse struct {
	Names []string
	IDs   []string
}
