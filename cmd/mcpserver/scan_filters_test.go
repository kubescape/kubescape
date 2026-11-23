package mcpserver

import (
	"context"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExcludeControlsSchema(t *testing.T) {
	for name, options := range map[string][]mcp.ToolOption{
		"cluster": scanFilterOptions(), "iac": iacScanFilterOptions(), "workload": workloadScanFilterOptions(),
	} {
		t.Run(name, func(t *testing.T) {
			tool := mcp.NewTool("scan", options...)
			compiler := jsonschema.NewCompiler()
			require.NoError(t, compiler.AddResource("filter.json", tool.InputSchema.Properties["exclude_controls"]))
			schema, err := compiler.Compile("filter.json")
			require.NoError(t, err)
			assert.NotContains(t, tool.InputSchema.Required, "exclude_controls")
			for _, valid := range []any{nil, "C-0012,C-0017", []any{"C-0012"}} {
				assert.NoError(t, schema.Validate(valid), "exclude_controls=%v", valid)
			}
			for _, invalid := range []any{true, []any{nil}} {
				assert.Error(t, schema.Validate(invalid), "exclude_controls=%v", invalid)
			}
		})
	}
}

func TestParseScanFilterArgs_Severities(t *testing.T) {
	tests := []struct {
		name        string
		args        map[string]any
		wantMin     string
		wantMax     string
		wantErrCode ErrorCode
	}{
		{
			name:    "empty args",
			args:    map[string]any{},
			wantMin: "",
			wantMax: "",
		},
		{
			name: "valid lower-case severities",
			args: map[string]any{
				"min_severity": "high",
				"max_severity": "critical",
			},
			wantMin: "High",
			wantMax: "Critical",
		},
		{
			name: "valid mixed-case severities",
			args: map[string]any{
				"min_severity": "Medium",
				"max_severity": "HIGH",
			},
			wantMin: "Medium",
			wantMax: "High",
		},
		{
			name: "invalid min_severity",
			args: map[string]any{
				"min_severity": "extreme",
			},
			wantErrCode: ErrCodeInvalidArgument,
		},
		{
			name: "invalid max_severity",
			args: map[string]any{
				"max_severity": "moderate",
			},
			wantErrCode: ErrCodeInvalidArgument,
		},
		{
			name: "min_severity higher than max_severity",
			args: map[string]any{
				"min_severity": "Critical",
				"max_severity": "Low",
			},
			wantErrCode: ErrCodeInvalidArgument,
		},
		{
			name: "min_severity equal to max_severity is allowed",
			args: map[string]any{
				"min_severity": "High",
				"max_severity": "High",
			},
			wantMin: "High",
			wantMax: "High",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filters, errResult := parseScanFilterArgs(tt.args, "")
			if tt.wantErrCode != "" {
				require.NotNil(t, errResult)
				assert.True(t, errResult.IsError)
				errPayload := toolResultText(t, errResult)
				assert.Contains(t, errPayload, string(tt.wantErrCode))
			} else {
				require.Nil(t, errResult)
				assert.Equal(t, tt.wantMin, filters.minSeverity)
				assert.Equal(t, tt.wantMax, filters.maxSeverity)
			}
		})
	}
}

func TestParseScanFilterArgs_KindsAndLabels(t *testing.T) {
	tests := []struct {
		name          string
		args          map[string]any
		wantInclude   string
		wantExclude   string
		wantSelector  string
		wantErrCode   ErrorCode
		wantErrSubstr string
	}{
		{
			name: "valid kinds and label selector",
			args: map[string]any{
				"include_kinds":  "Deployment,DaemonSet",
				"exclude_kinds":  "Job,CronJob",
				"label_selector": "app=web,tier!=backend",
			},
			wantInclude:  "Deployment,DaemonSet",
			wantExclude:  "Job,CronJob",
			wantSelector: "app=web,tier!=backend",
		},
		{
			name: "invalid include_kinds only commas",
			args: map[string]any{
				"include_kinds": " , , ",
			},
			wantErrCode:   ErrCodeInvalidArgument,
			wantErrSubstr: "include_kinds",
		},
		{
			name: "invalid exclude_kinds only commas",
			args: map[string]any{
				"exclude_kinds": " , ",
			},
			wantErrCode:   ErrCodeInvalidArgument,
			wantErrSubstr: "exclude_kinds",
		},
		{
			name: "invalid label selector syntax",
			args: map[string]any{
				"label_selector": "app==web===bad",
			},
			wantErrCode:   ErrCodeInvalidArgument,
			wantErrSubstr: "label_selector",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filters, errResult := parseScanFilterArgs(tt.args, "")
			if tt.wantErrCode != "" {
				require.NotNil(t, errResult)
				assert.True(t, errResult.IsError)
				errPayload := toolResultText(t, errResult)
				assert.Contains(t, errPayload, string(tt.wantErrCode))
				if tt.wantErrSubstr != "" {
					assert.Contains(t, errPayload, tt.wantErrSubstr)
				}
			} else {
				require.Nil(t, errResult)
				assert.Equal(t, tt.wantInclude, filters.includeKinds)
				assert.Equal(t, tt.wantExclude, filters.excludeKinds)
				assert.Equal(t, tt.wantSelector, filters.labelSelector)
			}
		})
	}
}

func TestParseScanFilterArgs_ExcludedNamespaces(t *testing.T) {
	t.Run("exclude_namespaces allowed with empty namespace", func(t *testing.T) {
		args := map[string]any{"exclude_namespaces": "kube-system,kube-public"}
		filters, errResult := parseScanFilterArgs(args, "")
		require.Nil(t, errResult)
		assert.Equal(t, "kube-system,kube-public", filters.excludedNamespaces)
	})

	t.Run("exclude_namespaces allowed with star namespace", func(t *testing.T) {
		args := map[string]any{"exclude_namespaces": "kube-system"}
		filters, errResult := parseScanFilterArgs(args, "*")
		require.Nil(t, errResult)
		assert.Equal(t, "kube-system", filters.excludedNamespaces)
	})

	t.Run("exclude_namespaces rejected with specific namespace", func(t *testing.T) {
		args := map[string]any{"exclude_namespaces": "kube-system"}
		_, errResult := parseScanFilterArgs(args, "production")
		require.NotNil(t, errResult)
		assert.True(t, errResult.IsError)
		errPayload := toolResultText(t, errResult)
		assert.Contains(t, errPayload, "cannot be used together")
	})
}

func TestParseScanFilterArgs_ExcludeControls(t *testing.T) {
	t.Run("comma-separated string", func(t *testing.T) {
		args := map[string]any{"exclude_controls": "C-0012, C-0017"}
		filters, errResult := parseScanFilterArgs(args, "")
		require.Nil(t, errResult)
		assert.Equal(t, []string{"C-0012", "C-0017"}, filters.excludeControls)
	})

	t.Run("array of strings", func(t *testing.T) {
		args := map[string]any{"exclude_controls": []any{"C-0012", "C-0017"}}
		filters, errResult := parseScanFilterArgs(args, "")
		require.Nil(t, errResult)
		assert.Equal(t, []string{"C-0012", "C-0017"}, filters.excludeControls)
	})

	// Clients send null (or an empty value) for an optional argument they are
	// not setting; the filter stays off, as for the other optional filters.
	for name, value := range map[string]any{"null": nil, "empty string": "", "blank string": "  ", "empty array": []any{}} {
		t.Run(name+" leaves the filter off", func(t *testing.T) {
			filters, errResult := parseScanFilterArgs(map[string]any{"exclude_controls": value}, "")
			require.Nil(t, errResult)
			assert.Empty(t, filters.excludeControls)
		})
	}

	t.Run("only separators", func(t *testing.T) {
		_, errResult := parseScanFilterArgs(map[string]any{"exclude_controls": " , "}, "")
		require.NotNil(t, errResult)
		assert.Contains(t, toolResultText(t, errResult), "exclude_controls")
	})

	t.Run("invalid type", func(t *testing.T) {
		args := map[string]any{"exclude_controls": 12345}
		_, errResult := parseScanFilterArgs(args, "")
		require.NotNil(t, errResult)
		assert.True(t, errResult.IsError)
		errPayload := toolResultText(t, errResult)
		assert.Contains(t, errPayload, "exclude_controls")
		assert.NotContains(t, errPayload, "control_ids")
	})
}

func TestScanFilterArgs_KeySuffix(t *testing.T) {
	t.Run("empty filters produce empty key suffix", func(t *testing.T) {
		var f scanFilterArgs
		assert.Empty(t, f.keySuffix())
	})

	t.Run("all filters set produce deterministic escaped suffix", func(t *testing.T) {
		f := scanFilterArgs{
			minSeverity:        "High",
			maxSeverity:        "Critical",
			includeKinds:       "Deployment,DaemonSet",
			excludeKinds:       "Job",
			labelSelector:      "app=web,env!=dev",
			excludedNamespaces: "kube-system",
			excludeControls:    []string{"C-0017", "C-0012"}, // out of order
		}
		suffix := f.keySuffix()
		assert.NotEmpty(t, suffix)
		assert.True(t, strings.HasPrefix(suffix, ":"))
		// Exclude controls should be sorted deterministically
		assert.Contains(t, suffix, "excludeControls=C-0012%2CC-0017")
		assert.Contains(t, suffix, "minSev=High")
		assert.Contains(t, suffix, "maxSev=Critical")
		assert.Contains(t, suffix, "includeKinds=Deployment%2CDaemonSet")
		assert.Contains(t, suffix, "excludeKinds=Job")
		assert.Contains(t, suffix, "excludeNS=kube-system")
	})
}

func TestCallTool_ScanFilters_ForwardedAndValidated(t *testing.T) {
	origFramework := frameworkScanFn
	t.Cleanup(func() { frameworkScanFn = origFramework })

	var capturedFilters scanFilterArgs
	frameworkScanFn = func(_ *KubescapeMcpserver, _ context.Context, namespace, framework string, filters ...scanFilterArgs) ([]byte, error) {
		if len(filters) > 0 {
			capturedFilters = filters[0]
		}
		return []byte(`{"total_failed":0}`), nil
	}

	ksServer := &KubescapeMcpserver{}

	t.Run("filters forwarded to framework scan", func(t *testing.T) {
		capturedFilters = scanFilterArgs{}
		res, err := ksServer.CallTool(context.Background(), "run_framework_security_scan", map[string]any{
			"framework_name":   "nsa",
			"min_severity":     "high",
			"include_kinds":    "Deployment",
			"exclude_controls": "C-0012",
		})
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.False(t, res.IsError)
		assert.Equal(t, "High", capturedFilters.minSeverity)
		assert.Equal(t, "Deployment", capturedFilters.includeKinds)
		assert.Equal(t, []string{"C-0012"}, capturedFilters.excludeControls)
	})

	t.Run("invalid filter causes tool error", func(t *testing.T) {
		res, err := ksServer.CallTool(context.Background(), "run_framework_security_scan", map[string]any{
			"framework_name": "nsa",
			"min_severity":   "ultra_high",
		})
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.True(t, res.IsError)
		errPayload := toolResultText(t, res)
		assert.Contains(t, errPayload, string(ErrCodeInvalidArgument))
		assert.Contains(t, errPayload, "min_severity")
	})

	t.Run("scan_local_iac rejects label_selector", func(t *testing.T) {
		res, err := ksServer.CallTool(context.Background(), "scan_local_iac", map[string]any{
			"path":           "/valid/path",
			"label_selector": "app=web",
		})
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.True(t, res.IsError)
		errPayload := toolResultText(t, res)
		assert.Contains(t, errPayload, string(ErrCodeInvalidArgument))
		assert.Contains(t, errPayload, "label_selector is not supported for local IaC scans")
	})

	t.Run("scan_local_iac rejects exclude_namespaces", func(t *testing.T) {
		res, err := ksServer.CallTool(context.Background(), "scan_local_iac", map[string]any{
			"path":               "/valid/path",
			"exclude_namespaces": "kube-system",
		})
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.True(t, res.IsError)
		errPayload := toolResultText(t, res)
		assert.Contains(t, errPayload, string(ErrCodeInvalidArgument))
		assert.Contains(t, errPayload, "exclude_namespaces is not supported for local IaC scans")
	})
}
