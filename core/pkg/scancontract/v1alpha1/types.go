package v1alpha1

import (
	"encoding/json"
	"time"
)

const (
	APIVersion = "config.kubescape.io/v1alpha1"
	Kind       = "ScanContract"

	DigestSchema = "kubescape-scan-contract:v1"
)

// Document is the v1alpha1 repository scan-contract document.
// Pointer fields preserve the difference between omitted values and explicit
// zero or empty values for later precedence resolution.
type Document struct {
	APIVersion string   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string   `json:"kind" yaml:"kind"`
	Metadata   Metadata `json:"metadata" yaml:"metadata"`
	Spec       Spec     `json:"spec" yaml:"spec"`
}

type Metadata struct {
	Name string `json:"name" yaml:"name"`
}

type Spec struct {
	MinimumKubescapeVersion string              `json:"minimumKubescapeVersion" yaml:"minimumKubescapeVersion"`
	DefaultContract         string              `json:"defaultContract,omitempty" yaml:"defaultContract,omitempty"`
	Contracts               map[string]Contract `json:"contracts" yaml:"contracts"`
}

type Contract struct {
	Policy     *Policy     `json:"policy,omitempty" yaml:"policy,omitempty"`
	Scope      *Scope      `json:"scope,omitempty" yaml:"scope,omitempty"`
	Evaluation *Evaluation `json:"evaluation,omitempty" yaml:"evaluation,omitempty"`
	Failure    *Failure    `json:"failure,omitempty" yaml:"failure,omitempty"`
	Output     *Output     `json:"output,omitempty" yaml:"output,omitempty"`
}

type Policy struct {
	Frameworks      *[]string `json:"frameworks,omitempty" yaml:"frameworks,omitempty"`
	Controls        *[]string `json:"controls,omitempty" yaml:"controls,omitempty"`
	ControlsVersion *string   `json:"controlsVersion,omitempty" yaml:"controlsVersion,omitempty"`
}

type Scope struct {
	IncludeNamespaces *[]string `json:"includeNamespaces,omitempty" yaml:"includeNamespaces,omitempty"`
	ExcludeNamespaces *[]string `json:"excludeNamespaces,omitempty" yaml:"excludeNamespaces,omitempty"`
}

type Evaluation struct {
	ScanTimeout    *Duration `json:"scanTimeout,omitempty" yaml:"scanTimeout,omitempty"`
	ControlTimeout *Duration `json:"controlTimeout,omitempty" yaml:"controlTimeout,omitempty"`
}

type Failure struct {
	SeverityAtLeast     *string                  `json:"severityAtLeast,omitempty" yaml:"severityAtLeast,omitempty"`
	ComplianceBelow     *float64                 `json:"complianceBelow,omitempty" yaml:"complianceBelow,omitempty"`
	CoverageBelow       *float64                 `json:"coverageBelow,omitempty" yaml:"coverageBelow,omitempty"`
	DegradedPolicyInput *DegradedPolicyInputMode `json:"degradedPolicyInput,omitempty" yaml:"degradedPolicyInput,omitempty"`
}

type DegradedPolicyInputMode string

const (
	DegradedPolicyInputAllow DegradedPolicyInputMode = "allow"
	DegradedPolicyInputFail  DegradedPolicyInputMode = "fail"
)

type Output struct {
	Formats          *[]string `json:"formats,omitempty" yaml:"formats,omitempty"`
	OmitRawResources *bool     `json:"omitRawResources,omitempty" yaml:"omitRawResources,omitempty"`
}

// Duration retains the human-readable contract representation while exposing
// the parsed value to the eventual scan-option adapter.
type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

type SelectedContract struct {
	APIVersion              string   `json:"apiVersion"`
	Kind                    string   `json:"kind"`
	Metadata                Metadata `json:"metadata"`
	MinimumKubescapeVersion string   `json:"minimumKubescapeVersion"`
	ContractName            string   `json:"contractName"`
	Contract                Contract `json:"contract"`
	DigestSchema            string   `json:"digestSchema"`
	ContractDigest          string   `json:"contractDigest"`
}
