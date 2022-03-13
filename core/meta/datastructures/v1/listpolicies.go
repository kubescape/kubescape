package v1

type ListPolicies struct {
	Target  string
	ListIDs bool
	Account string
	Format  string
}

type ListResponse struct {
	Names []string
	IDs   []string
}
