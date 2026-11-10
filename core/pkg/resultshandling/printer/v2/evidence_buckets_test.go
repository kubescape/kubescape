package printer

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover the shapes of evidence that regolibrary rules produce, one
// representative rule per shape. Each fixture carries what the report holds
// after a scan, not what the rule emits: only delete, review and fix paths
// reach the report, and a rule's failedPaths is not read (see
// docs/evidence-contract.md).
//
// A control that fails without any path must still render, and a path that
// does not resolve must never gain a value or a line it does not have.

// shapePod is a Pod as the scan hands it to the printer.
func shapePod(spec map[string]any) *mockResource {
	return &mockResource{
		kind: "Pod",
		obj: map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata":   map[string]any{"name": "demo"},
			"spec":       spec,
		},
	}
}

// shapeControl is a failed control whose one rule reports the given paths.
func shapeControl(paths ...armotypes.PosturePaths) *resourcesresults.ResourceAssociatedControl {
	return &resourcesresults.ResourceAssociatedControl{
		ControlID: "C-0001",
		Name:      "Control under test",
		Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{Name: "rule-under-test", Status: apis.StatusFailed, Paths: paths},
		},
	}
}

// shapeCell renders the evidence cell of the resource table for one failed
// control, the way `--show-evidence` does for a file scan of pod.yaml. lines
// stands in for the manifest: a path missing from it has no line.
func shapeCell(t *testing.T, control *resourcesresults.ResourceAssociatedControl, resource *mockResource, lines map[string]int) string {
	t.Helper()
	summary := &reportsummary.SummaryDetails{
		Controls: reportsummary.ControlSummaries{
			control.ControlID: {ControlID: control.ControlID, Name: control.Name, ScoreFactor: 5.0},
		},
	}
	rows := generateResourceRows([]resourcesresults.ResourceAssociatedControl{*control}, summary,
		resource, true, false, "pod.yaml", stubLineFor(lines))
	require.Len(t, rows, 1, "a failed control always gets a row")
	cell, ok := rows[0][resourceColumnPath].(string)
	require.True(t, ok)
	return cell
}

func TestEvidenceRuleShapes(t *testing.T) {
	const (
		hostNetwork = "spec.hostNetwork"
		readOnlyFS  = "spec.containers[0].securityContext.readOnlyRootFilesystem"
		envName     = "spec.containers[0].env[1].name"
		envValue    = "spec.containers[0].env[1].value"
	)

	tests := []struct {
		name     string
		resource *mockResource
		paths    []armotypes.PosturePaths
		lines    map[string]int
		wantCell string
		wantJSON []PathValue
	}{
		{
			// host-network-access (C-0041) emits deletePaths for the field that
			// makes the Pod fail, in every deny block.
			name:     "a rule that always emits a path",
			resource: shapePod(map[string]any{"hostNetwork": true, "containers": []any{map[string]any{"name": "app"}}}),
			paths:    []armotypes.PosturePaths{{DeletePath: hostNetwork}},
			lines:    map[string]int{hostNetwork: 6},
			wantCell: "@ pod.yaml\nspec.hostNetwork (current: true) (line 6)",
			wantJSON: []PathValue{{Path: hostNetwork, Value: "true"}},
		},
		{
			// immutable-container-filesystem (C-0017) emits a fix path in its Pod
			// and init-container blocks. The field is absent, so the line is the
			// enclosing block's, and there is no current value to show.
			name:     "a mixed rule, in a block that emits a path",
			resource: shapePod(map[string]any{"containers": []any{map[string]any{"name": "app"}}}),
			paths:    []armotypes.PosturePaths{{FixPath: armotypes.FixPath{Path: readOnlyFS, Value: "true"}}},
			lines:    map[string]int{readOnlyFS: 8},
			wantCell: "@ pod.yaml\nspec.containers[0].securityContext.readOnlyRootFilesystem=true (app) (line 8)",
		},
		{
			// The same rule's ephemeral-container block emits `"fixPaths": []`, so
			// the control fails and the report holds nothing to point at.
			name:     "a mixed rule, in a block that emits nothing",
			resource: shapePod(map[string]any{"ephemeralContainers": []any{map[string]any{"name": "debug"}}}),
			wantCell: "@ pod.yaml",
		},
		{
			// naked-pods (C-0073) emits `"failedPaths": [], "fixPaths": []`.
			name:     "a rule that emits no path at all",
			resource: shapePod(map[string]any{"containers": []any{map[string]any{"name": "app"}}}),
			wantCell: "@ pod.yaml",
		},
		{
			// duplicate-env-var builds its alert with `"failedPaths": [path]` and
			// `"fixPaths": []`. failedPaths is not read, so the report carries no
			// path for it and the control renders like any other without evidence.
			name: "a rule whose only path is in failedPaths",
			resource: shapePod(map[string]any{"containers": []any{map[string]any{
				"name": "app",
				"env": []any{
					map[string]any{"name": "DUP", "value": "a"},
					map[string]any{"name": "DUP", "value": "b"},
				},
			}}}),
			wantCell: "@ pod.yaml",
		},
		{
			// rule-credentials-in-env-var (C-0012) points at the variable's name and
			// at its value. The scan has already overwritten the value, and it is a
			// credential-shaped field besides, so only the name can be shown.
			name: "a credential rule on a scrubbed value",
			resource: shapePod(map[string]any{"containers": []any{map[string]any{
				"name": "app",
				"env": []any{
					map[string]any{"name": "LOG_LEVEL", "value": scrubbedPlaceholder},
					map[string]any{"name": "DB_PASSWORD", "value": scrubbedPlaceholder},
				},
			}}}),
			paths: []armotypes.PosturePaths{{DeletePath: envName}, {DeletePath: envValue}},
			lines: map[string]int{envName: 13, envValue: 14},
			wantCell: "@ pod.yaml\n" +
				"spec.containers[0].env[1].name (current: DB_PASSWORD) (app) (line 13)\n" +
				"spec.containers[0].env[1].value (current: " + redactedValue + ") (app) (line 14)",
			wantJSON: []PathValue{{Path: envName, Value: "DB_PASSWORD"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control := shapeControl(tt.paths...)

			assert.Equal(t, tt.wantCell, shapeCell(t, control, tt.resource, tt.lines))

			got := failedPathValues(control, tt.resource)
			if len(tt.wantJSON) == 0 {
				assert.Empty(t, got, "no value to put in the JSON evidence array")
			} else {
				assert.Equal(t, tt.wantJSON, got)
			}
		})
	}
}

// A path that cannot be resolved has to degrade to the bare path: no value
// invented for it, no line, and above all no panic, whatever the object holds.
func TestEvidenceDegradesGracefully(t *testing.T) {
	pod := shapePod(map[string]any{
		"hostNetwork": true,
		"containers":  []any{map[string]any{"name": "app", "image": "nginx:1.25"}},
	})

	tests := []struct {
		name     string
		resource *mockResource
		path     string
	}{
		{"a field the object does not have", pod, "spec.hostPID"},
		{"a path written for the wrong kind", pod, "spec.template.spec.hostNetwork"},
		{"a wildcard", pod, "spec.containers[*].image"},
		{"an unsubstituted index", pod, "spec.containers[container_ndx].image"},
		{"an index past the end of the list", pod, "spec.containers[5].image"},
		{"a scalar where a map is expected", pod, "spec.hostNetwork.enabled"},
		{"an empty object", &mockResource{kind: "Pod", obj: map[string]any{}}, "spec.hostNetwork"},
		{"a missing object", &mockResource{kind: "Pod"}, "spec.hostNetwork"},
	}

	kinds := []struct {
		name string
		path func(path string) armotypes.PosturePaths
	}{
		{"delete path", func(p string) armotypes.PosturePaths { return armotypes.PosturePaths{DeletePath: p} }},
		{"review path", func(p string) armotypes.PosturePaths { return armotypes.PosturePaths{ReviewPath: p} }},
	}

	for _, tt := range tests {
		for _, kind := range kinds {
			t.Run(tt.name+", as a "+kind.name, func(t *testing.T) {
				control := shapeControl(kind.path(tt.path))

				var cell string
				require.NotPanics(t, func() { cell = shapeCell(t, control, tt.resource, nil) })

				assert.Equal(t, "@ pod.yaml\n"+tt.path, cell, "the bare path, with nothing added")
				assert.Empty(t, failedPathValues(control, tt.resource))
			})
		}
	}

	t.Run("an empty path is skipped", func(t *testing.T) {
		control := shapeControl(armotypes.PosturePaths{DeletePath: ""}, armotypes.PosturePaths{ReviewPath: ""})
		assert.Equal(t, "@ pod.yaml", shapeCell(t, control, pod, nil))
		assert.Empty(t, failedPathValues(control, pod))
	})

	t.Run("a control with no rules at all", func(t *testing.T) {
		control := shapeControl()
		control.ResourceAssociatedRules = nil
		assert.Equal(t, "@ pod.yaml", shapeCell(t, control, pod, nil))
		assert.Empty(t, failedPathValues(control, pod))
	})
}
