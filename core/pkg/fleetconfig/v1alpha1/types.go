package v1alpha1

const (
	APIVersion = "config.kubescape.io/v1alpha1"
	Kind       = "FleetConfig"
)

// Document is a v1alpha1 fleet config: which kube contexts a fleet scan covers and where its reports go.
// Pointer fields keep an omitted value apart from an explicit zero, so only what the file sets replaces a flag default.
type Document struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata,omitempty"`
	Spec       Spec     `yaml:"spec"`
}

type Metadata struct {
	Name string `yaml:"name,omitempty"`
}

// Spec holds the fleet flags: contexts is --kube-contexts, output is --output, and so on.
type Spec struct {
	Contexts         *[]string `yaml:"contexts,omitempty"`
	Output           *string   `yaml:"output,omitempty"`
	FleetReport      *string   `yaml:"fleetReport,omitempty"`
	ReferenceCluster *string   `yaml:"referenceCluster,omitempty"`
	Retries          *int      `yaml:"retries,omitempty"`
}
