package printer

import (
	"bytes"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// C-0012 (applications credentials in configuration files) is the case behind
// kubescape/kubescape#1737: the report named the failing Deployment and nothing
// more, so a reviewer could not tell which environment variable, or which
// ConfigMap key, matched. The control has two rules, and each reports delete
// paths that name the offending field:
//
//   - rule-credentials-in-env-var: <pod spec>.containers[i].env[j].name and
//     .value
//   - rule-credentials-configmap: data[<key>]
//
// These tests pin that the evidence reaches the reader down to that variable or
// key, that the literal never does, and that a variable which only references a
// Secret is not reported.

// c0012Control is a failed C-0012 whose rules report the given delete paths, one
// rule per entry.
func c0012Control(rules map[string][]string) *resourcesresults.ResourceAssociatedControl {
	control := &resourcesresults.ResourceAssociatedControl{
		ControlID: "C-0012",
		Name:      "Applications credentials in configuration files",
		Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
	}
	for name, paths := range rules {
		rule := resourcesresults.ResourceAssociatedRule{Name: name, Status: apis.StatusFailed}
		for _, p := range paths {
			rule.Paths = append(rule.Paths, armotypes.PosturePaths{DeletePath: p})
		}
		control.ResourceAssociatedRules = append(control.ResourceAssociatedRules, rule)
	}
	return control
}

// c0012Cell renders the evidence cell of the resource table for a file scan of
// manifest.yaml, with every path resolvable to the line in lines.
func c0012Cell(t *testing.T, control *resourcesresults.ResourceAssociatedControl, resource *mockResource, showSecrets bool, lines map[string]int) string {
	t.Helper()
	summary := &reportsummary.SummaryDetails{
		Controls: reportsummary.ControlSummaries{
			control.ControlID: {ControlID: control.ControlID, Name: control.Name, ScoreFactor: 8.0},
		},
	}
	rows := generateResourceRows([]resourcesresults.ResourceAssociatedControl{*control}, summary,
		resource, true, showSecrets, "manifest.yaml", stubLineFor(lines))
	require.Len(t, rows, 1)
	cell, ok := rows[0][resourceColumnPath].(string)
	require.True(t, ok)
	return cell
}

func TestC0012EvidenceNamesTheEnvVarNotJustTheDeployment(t *testing.T) {
	const (
		namePath  = "spec.template.spec.containers[0].env[1].name"
		valuePath = "spec.template.spec.containers[0].env[1].value"
	)
	// The scan overwrites every env value with the placeholder before output
	// is built, so the object the printer sees holds no literal at all.
	deployment := &mockResource{
		kind: "Deployment",
		obj: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]any{"name": "checkout-api"},
			"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
				"containers": []any{
					map[string]any{
						"name": "api",
						"env": []any{
							map[string]any{"name": "LOG_LEVEL", "value": scrubbedPlaceholder},
							map[string]any{"name": "DB_PASSWORD", "value": scrubbedPlaceholder},
						},
					},
					// Only references a Secret, so C-0012 does not report it.
					map[string]any{
						"name": "sidecar",
						"env": []any{
							map[string]any{"name": "API_TOKEN"},
						},
					},
				},
			}}},
		},
	}
	control := c0012Control(map[string][]string{
		"rule-credentials-in-env-var": {namePath, valuePath},
	})
	lines := map[string]int{namePath: 21, valuePath: 22}

	for _, showSecrets := range []bool{false, true} {
		name := "default"
		if showSecrets {
			name = "--show-secrets"
		}
		t.Run(name, func(t *testing.T) {
			cell := c0012Cell(t, control, deployment, showSecrets, lines)

			// The variable that matched, with its container and line.
			assert.Contains(t, cell, namePath+" (current: DB_PASSWORD) (api) (line 21)")
			// Its value is never the literal, with or without --show-secrets,
			// because the scan has already overwritten it.
			assert.Contains(t, cell, valuePath+" (current: "+redactedValue+") (api) (line 22)")
			assert.NotContains(t, cell, scrubbedPlaceholder)
			// The variables that did not match, and the Secret reference, are
			// not named.
			assert.NotContains(t, cell, "LOG_LEVEL")
			assert.NotContains(t, cell, "API_TOKEN")
			assert.NotContains(t, cell, "sidecar")
		})
	}

	t.Run("the JSON evidence array", func(t *testing.T) {
		assert.Equal(t, []PathValue{{Path: namePath, Value: "DB_PASSWORD"}}, failedPathValues(control, deployment))
	})
}

func TestC0012EvidenceNamesTheConfigMapKey(t *testing.T) {
	configMap := &mockResource{
		kind: "ConfigMap",
		obj: map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata":   map[string]any{"name": "app-config"},
			"data": map[string]any{
				"api_token": scrubbedPlaceholder,
				"log_level": scrubbedPlaceholder,
			},
		},
	}
	control := c0012Control(map[string][]string{
		"rule-credentials-configmap": {"data[api_token]"},
	})

	for _, showSecrets := range []bool{false, true} {
		name := "default"
		if showSecrets {
			name = "--show-secrets"
		}
		t.Run(name, func(t *testing.T) {
			cell := c0012Cell(t, control, configMap, showSecrets, map[string]int{"data[api_token]": 7})

			assert.Contains(t, cell, "data[api_token] (current: "+redactedValue+") (line 7)")
			assert.NotContains(t, cell, scrubbedPlaceholder)
			assert.NotContains(t, cell, "log_level", "a key the rule did not report is not named")
		})
	}
}

// A control that fails on a resource whose offending field is gone from the
// object must still render, must mark the path unresolved and must not invent a
// value or a line.
func TestC0012EvidenceWithoutTheFieldDoesNotPanic(t *testing.T) {
	deployment := &mockResource{
		kind: "Deployment",
		obj: map[string]any{
			"kind":     "Deployment",
			"metadata": map[string]any{"name": "checkout-api"},
			"spec":     map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{}}}},
		},
	}
	control := c0012Control(map[string][]string{
		"rule-credentials-in-env-var": {"spec.template.spec.containers[0].env[1].name"},
	})

	var cell string
	require.NotPanics(t, func() { cell = c0012Cell(t, control, deployment, false, nil) })
	assert.Contains(t, cell, "spec.template.spec.containers[0].env[1].name (current: <unresolved>)")
	assert.NotContains(t, cell, "(line")
}

func TestC0012EvidenceLiteralSecretRevealedWithShowSecrets(t *testing.T) {
	const (
		namePath  = "spec.template.spec.containers[0].env[0].name"
		valuePath = "spec.template.spec.containers[0].env[0].value"
	)
	deployment := &mockResource{
		kind: "Deployment",
		obj: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]any{"name": "checkout-api"},
			"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
				"containers": []any{
					map[string]any{
						"name": "api",
						"env": []any{
							map[string]any{"name": "DB_PASSWORD", "value": "mock-secret-val"},
						},
					},
				},
			}}},
		},
	}
	control := c0012Control(map[string][]string{
		"rule-credentials-in-env-var": {namePath, valuePath},
	})
	lines := map[string]int{namePath: 21, valuePath: 22}

	t.Run("default redacts secret value", func(t *testing.T) {
		cell := c0012Cell(t, control, deployment, false, lines)
		assert.Contains(t, cell, namePath+" (current: DB_PASSWORD) (api) (line 21)")
		assert.Contains(t, cell, valuePath+" (current: "+redactedValue+") (api) (line 22)")
		assert.NotContains(t, cell, "mock-secret-val")
	})

	t.Run("--show-secrets reveals literal secret value", func(t *testing.T) {
		cell := c0012Cell(t, control, deployment, true, lines)
		assert.Contains(t, cell, namePath+" (current: DB_PASSWORD) (api) (line 21)")
		assert.Contains(t, cell, valuePath+" (current: mock-secret-val) (api) (line 22)")
	})

	t.Run("--show-secrets reveals preserved value on scrubbed resource while JSON stays scrubbed", func(t *testing.T) {
		scrubbed := &mockResource{
			kind: "Deployment",
			obj: map[string]any{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata":   map[string]any{"name": "checkout-api"},
				"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name": "api",
							"env": []any{
								map[string]any{"name": "DB_PASSWORD", "value": scrubbedPlaceholder},
							},
						},
					},
				}}},
			},
		}
		resID := "apps/v1/Deployment/default/checkout-api"
		preserved := map[string]string{valuePath: "mock-secret-val"}
		summary := &reportsummary.SummaryDetails{
			Controls: reportsummary.ControlSummaries{
				control.ControlID: {ControlID: control.ControlID, Name: control.Name, ScoreFactor: 8.0},
			},
		}

		// With showSecrets=true, evidence resolves from preserved map even though resource has XXXXXX.
		rows := generateResourceRowsWithPreserved([]resourcesresults.ResourceAssociatedControl{*control}, summary,
			scrubbed, true, true, "manifest.yaml", stubLineFor(lines), preserved)
		require.Len(t, rows, 1)
		cell, ok := rows[0][resourceColumnPath].(string)
		require.True(t, ok)
		assert.Contains(t, cell, valuePath+" (current: mock-secret-val) (api) (line 22)")
		assert.NotContains(t, cell, scrubbedPlaceholder)

		// With showSecrets=false, preserved map is ignored and output stays redacted.
		rowsRedacted := generateResourceRowsWithPreserved([]resourcesresults.ResourceAssociatedControl{*control}, summary,
			scrubbed, true, false, "manifest.yaml", stubLineFor(lines), preserved)
		require.Len(t, rowsRedacted, 1)
		cellRedacted, ok := rowsRedacted[0][resourceColumnPath].(string)
		require.True(t, ok)
		assert.Contains(t, cellRedacted, valuePath+" (current: "+redactedValue+") (api) (line 22)")
		assert.NotContains(t, cellRedacted, "mock-secret-val")

		// JSON output must never carry the literal secret in raw resources or evidence.
		wl := workloadinterface.NewWorkloadObj(scrubbed.obj)
		session := &cautils.OPASessionObj{
			ShowSecrets:             true,
			PreservedEvidenceValues: map[string]map[string]string{resID: preserved},
			AllResources:            map[string]workloadinterface.IMetadata{resID: wl},
			ResourcesResult: map[string]resourcesresults.Result{
				resID: {ResourceID: resID, AssociatedControls: []resourcesresults.ResourceAssociatedControl{*control}},
			},
			Report: &reporthandlingv2.PostureReport{SummaryDetails: *summary},
		}
		var jsonBuf bytes.Buffer
		require.NoError(t, writeConfigurationJSON(&jsonBuf, session, nil))
		jsonOut := jsonBuf.String()
		assert.NotContains(t, jsonOut, "mock-secret-val")
		assert.Contains(t, jsonOut, scrubbedPlaceholder)
		assert.Contains(t, jsonOut, `"value":"DB_PASSWORD"`)
	})
}
