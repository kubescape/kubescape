package v1alpha1

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

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
	Retries          *Count    `yaml:"retries,omitempty"`
}

// Count is a whole number; yaml.v3 would otherwise truncate a value like 1.5 into an int instead of rejecting it.
type Count int

func (c *Count) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode || value.ShortTag() != "!!int" {
		return fmt.Errorf("line %d: %q is not a whole number", value.Line, value.Value)
	}
	var whole int
	if err := value.Decode(&whole); err != nil {
		return err
	}
	*c = Count(whole)
	return nil
}
