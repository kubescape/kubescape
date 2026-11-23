package scan

import (
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	contractv1alpha1 "github.com/kubescape/kubescape/v4/core/pkg/scancontract/v1alpha1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/spf13/cobra"
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

func TestOrdinaryCLIOverrides(t *testing.T) {
	strPtr := func(s string) *string { return &s }
	boolPtr := func(b bool) *bool { return &b }
	strList := func(items ...string) *contractv1alpha1.StringList {
		l := contractv1alpha1.StringList(items)
		return &l
	}
	strSlicePtr := func(items ...string) *[]string {
		return &items
	}

	fullContract := contractv1alpha1.Contract{
		Policy: &contractv1alpha1.Policy{
			ControlsVersion: strPtr("v1.0.0"),
		},
		Scope: &contractv1alpha1.Scope{
			IncludeNamespaces: strList("kube-system"),
			ExcludeNamespaces: strList("default"),
		},
		Evaluation: &contractv1alpha1.Evaluation{
			ScanTimeout:    &contractv1alpha1.Duration{Duration: 5 * time.Minute},
			ControlTimeout: &contractv1alpha1.Duration{Duration: 30 * time.Second},
		},
		Output: &contractv1alpha1.Output{
			Formats:          strList("json"),
			OmitRawResources: boolPtr(false),
		},
	}

	fullScanInfo := &cautils.ScanInfo{
		ControlsVersion:    "v2.0.0",
		IncludeNamespaces:  "prod,staging",
		ExcludedNamespaces: "kube-system,test",
		ScanTimeout:        10 * time.Minute,
		ControlTimeout:     1 * time.Minute,
		Format:             "json,pdf",
		OmitRawResources:   true,
	}

	newCmdWithFlags := func(changedFlags map[string]string) *cobra.Command {
		cmd := &cobra.Command{Use: "scan"}
		cmd.Flags().String("controls-version", "", "")
		cmd.Flags().String("include-namespaces", "", "")
		cmd.Flags().String("exclude-namespaces", "", "")
		cmd.Flags().Duration("scan-timeout", 0, "")
		cmd.Flags().Duration("control-timeout", 0, "")
		cmd.Flags().String("format", "", "")
		cmd.Flags().Bool("omit-raw-resources", false, "")
		cmd.Flags().String("other-flag", "", "")

		for k, v := range changedFlags {
			if err := cmd.Flags().Set(k, v); err != nil {
				t.Fatalf("failed to set flag %q: %v", k, err)
			}
		}
		return cmd
	}

	allFlags := map[string]string{
		"controls-version":   "v2.0.0",
		"include-namespaces": "prod,staging",
		"exclude-namespaces": "kube-system,test",
		"scan-timeout":       "10m",
		"control-timeout":    "1m",
		"format":             "json,pdf",
		"omit-raw-resources": "true",
	}

	tests := []struct {
		name     string
		cmd      *cobra.Command
		contract contractv1alpha1.Contract
		scanInfo *cautils.ScanInfo
		want     *reporthandlingv2.ScanContractCLIOverrides
	}{
		{
			name:     "flags changed on command and present in contract are recorded",
			cmd:      newCmdWithFlags(allFlags),
			contract: fullContract,
			scanInfo: fullScanInfo,
			want: &reporthandlingv2.ScanContractCLIOverrides{
				Policy: &reporthandlingv2.ScanContractPolicyOverrides{
					ControlsVersion: strPtr("v2.0.0"),
				},
				Scope: &reporthandlingv2.ScanContractScopeOverrides{
					IncludeNamespaces: strSlicePtr("prod", "staging"),
					ExcludeNamespaces: strSlicePtr("kube-system", "test"),
				},
				Evaluation: &reporthandlingv2.ScanContractEvaluationOverrides{
					ScanTimeout:    strPtr("10m0s"),
					ControlTimeout: strPtr("1m0s"),
				},
				Output: &reporthandlingv2.ScanContractOutputOverrides{
					Formats:          strSlicePtr("json", "pdf"),
					OmitRawResources: boolPtr(true),
				},
			},
		},
		{
			name:     "flags changed but absent from contract are not recorded",
			cmd:      newCmdWithFlags(allFlags),
			contract: contractv1alpha1.Contract{},
			scanInfo: fullScanInfo,
			want:     nil,
		},
		{
			name: "flags changed but section present with nil target field in contract is not recorded",
			cmd:  newCmdWithFlags(allFlags),
			contract: contractv1alpha1.Contract{
				Policy:     &contractv1alpha1.Policy{},
				Scope:      &contractv1alpha1.Scope{},
				Evaluation: &contractv1alpha1.Evaluation{},
				Output:     &contractv1alpha1.Output{},
			},
			scanInfo: fullScanInfo,
			want:     nil,
		},
		{
			name:     "flags present in contract but not changed on CLI are not recorded",
			cmd:      newCmdWithFlags(nil),
			contract: fullContract,
			scanInfo: fullScanInfo,
			want:     nil,
		},
		{
			name:     "nil command returns nil",
			cmd:      nil,
			contract: fullContract,
			scanInfo: fullScanInfo,
			want:     nil,
		},
		{
			name: "unrelated flag changed on CLI is not recorded",
			cmd: newCmdWithFlags(map[string]string{
				"other-flag": "some-value",
			}),
			contract: fullContract,
			scanInfo: fullScanInfo,
			want:     nil,
		},
		{
			name: "selective overrides only records flags present in contract and changed on CLI",
			cmd: newCmdWithFlags(map[string]string{
				"controls-version": "v2.0.0",
				"format":           "json,pdf",
				"other-flag":       "custom",
			}),
			contract: contractv1alpha1.Contract{
				Policy: &contractv1alpha1.Policy{
					ControlsVersion: strPtr("v1.0.0"),
				},
				Scope: &contractv1alpha1.Scope{
					IncludeNamespaces: strList("kube-system"),
				},
				Output: &contractv1alpha1.Output{
					Formats: strList("yaml"),
				},
			},
			scanInfo: fullScanInfo,
			want: &reporthandlingv2.ScanContractCLIOverrides{
				Policy: &reporthandlingv2.ScanContractPolicyOverrides{
					ControlsVersion: strPtr("v2.0.0"),
				},
				Output: &reporthandlingv2.ScanContractOutputOverrides{
					Formats: strSlicePtr("json", "pdf"),
				},
			},
		},
		{
			name: "partial field overrides within sections",
			cmd: newCmdWithFlags(map[string]string{
				"include-namespaces": "prod,staging",
				"control-timeout":    "1m",
				"omit-raw-resources": "true",
			}),
			contract: fullContract,
			scanInfo: fullScanInfo,
			want: &reporthandlingv2.ScanContractCLIOverrides{
				Scope: &reporthandlingv2.ScanContractScopeOverrides{
					IncludeNamespaces: strSlicePtr("prod", "staging"),
				},
				Evaluation: &reporthandlingv2.ScanContractEvaluationOverrides{
					ControlTimeout: strPtr("1m0s"),
				},
				Output: &reporthandlingv2.ScanContractOutputOverrides{
					OmitRawResources: boolPtr(true),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ordinaryCLIOverrides(tt.cmd, tt.contract, tt.scanInfo)
			assert.Equal(t, tt.want, got)
		})
	}
}
