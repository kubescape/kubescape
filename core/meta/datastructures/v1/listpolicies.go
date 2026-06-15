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

// ControlListEntry is a single row emitted by "kubescape list controls --format json".
type ControlListEntry struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Frameworks []string `json:"frameworks"`
}
