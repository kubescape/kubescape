package v1

type ListPolicies struct {
	Target         string
	Format         string
	AccountID      string
	AccessKey      string
	ControlsInputs string
}

type ListResponse struct {
	Names []string
	IDs   []string
}

type ListResult struct {
	Names          []string
	Controls       []ControlListEntry
	ControlsConfig []ControlConfigEntry
}

// ControlConfigEntry is a single configurable input a scan evaluates controls
// against, together with the value in effect and the controls that read it.
type ControlConfigEntry struct {
	// Name is the key as it appears in a controls-config file.
	Name string `json:"name"`
	// Title is the human readable label the controls declare it by.
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	Values      []string `json:"values"`
	Controls    []string `json:"controls"`
}

// ControlListEntry is a single row emitted by "kubescape list controls --format json".
type ControlListEntry struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Frameworks []string `json:"frameworks"`
}
