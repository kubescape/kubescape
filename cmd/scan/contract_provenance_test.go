package scan

import (
	"testing"

	contractv1alpha1 "github.com/kubescape/kubescape/v4/core/pkg/scancontract/v1alpha1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseContractAllowlist(t *testing.T) {
	tests := []struct {
		name        string
		input       []string
		want        map[string]bool
		wantErr     bool
		errContains string
	}{
		{
			name:  "empty slice returns nil map without error",
			input: nil,
			want:  nil,
		},
		{
			name:  "valid sections parsed and lowercased",
			input: []string{"policy,scope", "Evaluation", "FAILURE,output"},
			want: map[string]bool{
				"policy":     true,
				"scope":      true,
				"evaluation": true,
				"failure":    true,
				"output":     true,
			},
		},
		{
			name:  "trims whitespace around section tokens",
			input: []string{"  policy  ,   output  "},
			want: map[string]bool{
				"policy": true,
				"output": true,
			},
		},
		{
			name:        "rejects empty section token",
			input:       []string{"policy,,output"},
			wantErr:     true,
			errContains: `unsupported section "" in --contract-allow`,
		},
		{
			name:        "rejects unknown section name",
			input:       []string{"policy,invalidSection"},
			wantErr:     true,
			errContains: `unsupported section "invalidSection" in --contract-allow`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseContractAllowlist(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, got)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestPartitionContractSections(t *testing.T) {
	contract := contractv1alpha1.Contract{
		Policy:     &contractv1alpha1.Policy{},
		Scope:      &contractv1alpha1.Scope{},
		Evaluation: &contractv1alpha1.Evaluation{},
		Failure:    &contractv1alpha1.Failure{},
		Output:     &contractv1alpha1.Output{},
	}

	t.Run("nil allowlist returns all declared sections in canonical order as allowed", func(t *testing.T) {
		allowed, denied := partitionContractSections(contract, nil)
		assert.Equal(t, []string{"policy", "scope", "evaluation", "failure", "output"}, allowed)
		assert.Empty(t, denied)
	})

	t.Run("partitions declared sections into allowed and denied preserving canonical order", func(t *testing.T) {
		allowedMap := map[string]bool{
			"policy": true,
			"output": true,
		}
		allowed, denied := partitionContractSections(contract, allowedMap)
		assert.Equal(t, []string{"policy", "output"}, allowed)
		assert.Equal(t, []string{"scope", "evaluation", "failure"}, denied)
	})

	t.Run("skips absent sections", func(t *testing.T) {
		partial := contractv1alpha1.Contract{
			Policy: &contractv1alpha1.Policy{},
			Output: &contractv1alpha1.Output{},
		}
		allowedMap := map[string]bool{
			"policy": true,
		}
		allowed, denied := partitionContractSections(partial, allowedMap)
		assert.Equal(t, []string{"policy"}, allowed)
		assert.Equal(t, []string{"output"}, denied)
	})
}

func TestFilterContractSections(t *testing.T) {
	contract := contractv1alpha1.Contract{
		Policy:     &contractv1alpha1.Policy{},
		Scope:      &contractv1alpha1.Scope{},
		Evaluation: &contractv1alpha1.Evaluation{},
		Failure:    &contractv1alpha1.Failure{},
		Output:     &contractv1alpha1.Output{},
	}

	t.Run("nil allowedMap returns contract unmodified", func(t *testing.T) {
		filtered := filterContractSections(contract, nil)
		assert.NotNil(t, filtered.Policy)
		assert.NotNil(t, filtered.Scope)
		assert.NotNil(t, filtered.Evaluation)
		assert.NotNil(t, filtered.Failure)
		assert.NotNil(t, filtered.Output)
	})

	t.Run("nils out denied sections while keeping allowed sections", func(t *testing.T) {
		allowedMap := map[string]bool{
			"policy": true,
			"output": true,
		}
		filtered := filterContractSections(contract, allowedMap)
		assert.NotNil(t, filtered.Policy)
		assert.Nil(t, filtered.Scope)
		assert.Nil(t, filtered.Evaluation)
		assert.Nil(t, filtered.Failure)
		assert.NotNil(t, filtered.Output)
	})
}

func TestSplitContractNamespaces(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "empty string produces empty slice",
			input: "",
			want:  []string{},
		},
		{
			name:  "single namespace",
			input: "default",
			want:  []string{"default"},
		},
		{
			name:  "comma-separated with whitespace",
			input: " default , kube-system ,  prod ",
			want:  []string{"default", "kube-system", "prod"},
		},
		{
			name:  "ignores empty items from consecutive commas",
			input: "default,,prod,",
			want:  []string{"default", "prod"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitContractNamespaces(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestOmitUnenforcedComplianceGate(t *testing.T) {
	t.Run("nil metadata returns false", func(t *testing.T) {
		assert.False(t, omitUnenforcedComplianceGate(nil))
	})

	t.Run("clears effective compliance gate while preserving gate resolution contract and floor", func(t *testing.T) {
		requestedContract := 75.0
		runnerFloor := 60.0
		effectiveVal := 75.0

		metadata := &reporthandlingv2.ScanContractMetadata{
			GateResolution: &reporthandlingv2.ScanContractGateResolution{
				ComplianceBelow: reporthandlingv2.ScanContractNumberGateResolution{
					Contract:    &requestedContract,
					RunnerFloor: &runnerFloor,
					Effective:   &effectiveVal,
				},
			},
			Effective: &reporthandlingv2.ScanContractEffectiveSettings{
				Policy: &reporthandlingv2.ScanContractPolicy{
					ControlsVersion: "v1.0.0",
				},
				Failure: &reporthandlingv2.ScanContractFailure{
					ComplianceBelow: &effectiveVal,
				},
			},
		}

		omitted := omitUnenforcedComplianceGate(metadata)
		assert.True(t, omitted)
		assert.Nil(t, metadata.GateResolution.ComplianceBelow.Effective)
		assert.Equal(t, &requestedContract, metadata.GateResolution.ComplianceBelow.Contract)
		assert.Equal(t, &runnerFloor, metadata.GateResolution.ComplianceBelow.RunnerFloor)
		assert.Nil(t, metadata.Effective.Failure)
		assert.NotNil(t, metadata.Effective.Policy)
	})

	t.Run("cleans up effective settings when failure was the only configured section", func(t *testing.T) {
		effectiveVal := 80.0
		metadata := &reporthandlingv2.ScanContractMetadata{
			Effective: &reporthandlingv2.ScanContractEffectiveSettings{
				Failure: &reporthandlingv2.ScanContractFailure{
					ComplianceBelow: &effectiveVal,
				},
			},
		}

		omitted := omitUnenforcedComplianceGate(metadata)
		assert.True(t, omitted)
		assert.Nil(t, metadata.Effective, "Effective struct should be nilled out if empty")
	})

	t.Run("returns false when no effective compliance gate exists", func(t *testing.T) {
		metadata := &reporthandlingv2.ScanContractMetadata{
			Effective: &reporthandlingv2.ScanContractEffectiveSettings{
				Policy: &reporthandlingv2.ScanContractPolicy{ControlsVersion: "v1"},
			},
		}
		assert.False(t, omitUnenforcedComplianceGate(metadata))
	})
}
