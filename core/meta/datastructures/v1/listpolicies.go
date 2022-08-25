package v1

import "github.com/kubescape/kubescape/v2/core/cautils"

type ListPolicies struct {
	Target      string
	ListIDs     bool
	Format      string
	Credentials cautils.Credentials
}

type ListResponse struct {
	Names []string
	IDs   []string
}
