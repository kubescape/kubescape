package v1

type ListPolicies struct {
	Target    string
	Format    string
	AccountID string
	AccessKey string
}

type ListResponse struct {
	Names []string
	IDs   []string
}
