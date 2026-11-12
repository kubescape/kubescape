package printer

import (
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deletePathControl builds a control whose rule names only the given delete
// paths.
func deletePathControl(deletePaths ...string) *resourcesresults.ResourceAssociatedControl {
	var paths []armotypes.PosturePaths
	for _, p := range deletePaths {
		paths = append(paths, armotypes.PosturePaths{DeletePath: p})
	}
	return &resourcesresults.ResourceAssociatedControl{
		ControlID: "C-0041",
		Name:      "HostNetwork access",
		Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{Name: "host-network-access", Status: apis.StatusFailed, Paths: paths},
		},
	}
}

// deleteValuesDeployment carries one plain field, one credential-shaped env
// value, and a container holding both a safe field and that credential.
func deleteValuesDeployment() *mockResource {
	return &mockResource{
		kind: "Deployment",
		obj: map[string]any{
			"spec": map[string]any{
				"template": map[string]any{
					"spec": map[string]any{
						"hostNetwork": true,
						"containers": []any{
							map[string]any{
								"name":  "api",
								"image": "nginx:1",
								"env": []any{
									map[string]any{"name": "DB_PASSWORD", "value": "hunter2-literal"},
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestEvidencePathsWithCurrentValues_DeletePath(t *testing.T) {
	const (
		hostNetwork = "spec.template.spec.hostNetwork"
		envValue    = "spec.template.spec.containers[0].env[0].value"
		container   = "spec.template.spec.containers[0]"
		absent      = "spec.template.spec.hostPID"
		sensitive   = "hunter2-literal"
	)
	resource := deleteValuesDeployment()

	tests := []struct {
		name        string
		path        string
		showSecrets bool
		want        string
		notContains string
	}{
		{
			name: "a plain field shows its current value",
			path: hostNetwork,
			want: hostNetwork + " (current: true)",
		},
		{
			name: "a field absent from the object stays bare",
			path: absent,
			want: absent,
		},
		{
			name:        "a credential-shaped path is redacted",
			path:        envValue,
			want:        envValue + " (current: " + redactedValue + ")",
			notContains: sensitive,
		},
		{
			name:        "--show-secrets reveals the credential-shaped path",
			path:        envValue,
			showSecrets: true,
			want:        envValue + " (current: hunter2-literal)",
		},
		{
			name:        "an object-valued path masks credential-shaped descendants",
			path:        container,
			notContains: sensitive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evidencePathsWithCurrentValues(deletePathControl(tt.path), resource, tt.showSecrets)
			require.Len(t, got, 1)
			if tt.want != "" {
				assert.Equal(t, tt.want, got[0])
			}
			if tt.notContains != "" {
				assert.NotContains(t, got[0], tt.notContains)
			}
		})
	}

	t.Run("an object-valued path still reports the safe fields", func(t *testing.T) {
		got := evidencePathsWithCurrentValues(deletePathControl(container), resource, false)
		require.Len(t, got, 1)
		assert.Contains(t, got[0], "nginx:1")
		assert.Contains(t, got[0], redactedValue)
	})

	t.Run("an absent credential-shaped path is not reported as redacted", func(t *testing.T) {
		// "[redacted]" claims there is a value to hide. A field the object
		// does not have has none.
		missing := "spec.template.spec.containers[0].env[5].value"
		got := evidencePathsWithCurrentValues(deletePathControl(missing), resource, false)
		assert.Equal(t, []string{missing}, got)
	})

	t.Run("a path both deleted and reviewed is listed once", func(t *testing.T) {
		ctrl := deletePathControl(hostNetwork)
		ctrl.ResourceAssociatedRules[0].Paths = append(ctrl.ResourceAssociatedRules[0].Paths,
			armotypes.PosturePaths{ReviewPath: hostNetwork})
		got := evidencePathsWithCurrentValues(ctrl, resource, false)
		assert.Equal(t, []string{hostNetwork + " (current: true)"}, got)
	})
}

// The exported function also feeds the HTML, SARIF, GitLab SAST and GitHub
// Actions printers. Delete-path values are a terminal-evidence change, so
// those outputs must be exactly what they were.
func TestAssistedRemediationPathsWithCurrentValuesFiltered_DeletePathStaysBare(t *testing.T) {
	const hostNetwork = "spec.template.spec.hostNetwork"
	got := AssistedRemediationPathsWithCurrentValuesFiltered(deletePathControl(hostNetwork), deleteValuesDeployment(), false)
	assert.Equal(t, []string{hostNetwork}, got)
}

// In the resource table the value comes first and the line last, so each
// annotation reads as a suffix on the path it describes.
func TestGenerateResourceRows_DeletePathShowsValueThenLine(t *testing.T) {
	const hostNetwork = "spec.template.spec.hostNetwork"
	ctrl := deletePathControl(hostNetwork)
	summary := &reportsummary.SummaryDetails{
		Controls: reportsummary.ControlSummaries{
			"C-0041": {ControlID: "C-0041", Name: "HostNetwork access", ScoreFactor: 7.0},
		},
	}

	rows := generateResourceRows([]resourcesresults.ResourceAssociatedControl{*ctrl}, summary,
		deleteValuesDeployment(), true, false, "", stubLineFor(map[string]int{hostNetwork: 8}))

	require.Len(t, rows, 1)
	cell, ok := rows[0][resourceColumnPath].(string)
	require.True(t, ok)
	assert.Equal(t, hostNetwork+" (current: true) (line 8)", cell)
}

func TestGenerateResourceRows_DeletePathCredentialNeverPrinted(t *testing.T) {
	const envValue = "spec.template.spec.containers[0].env[0].value"
	ctrl := deletePathControl(envValue)
	summary := &reportsummary.SummaryDetails{
		Controls: reportsummary.ControlSummaries{
			"C-0041": {ControlID: "C-0041", Name: "HostNetwork access", ScoreFactor: 7.0},
		},
	}

	rows := generateResourceRows([]resourcesresults.ResourceAssociatedControl{*ctrl}, summary,
		deleteValuesDeployment(), true, false, "", nil)

	require.Len(t, rows, 1)
	cell, ok := rows[0][resourceColumnPath].(string)
	require.True(t, ok)
	assert.Contains(t, cell, redactedValue)
	assert.NotContains(t, cell, "hunter2-literal")
}

// attachAssistedRemediation runs under --verbose too. Without --show-evidence
// it must print what it always has.
func TestAttachAssistedRemediation_DeleteValuesOnlyWithShowEvidence(t *testing.T) {
	const hostNetwork = "spec.template.spec.hostNetwork"
	resource := deleteValuesDeployment()
	resource.id = "deployment-1"
	ctrl := deletePathControl(hostNetwork)

	summary := &reportsummary.SummaryDetails{
		Controls: reportsummary.ControlSummaries{
			"C-0041": {ControlID: "C-0041", Name: "HostNetwork access", ScoreFactor: 7.0},
		},
	}
	results := map[string]resourcesresults.Result{
		resource.id: {ResourceID: resource.id, AssociatedControls: []resourcesresults.ResourceAssociatedControl{*ctrl}},
	}

	render := func(showEvidence bool) string {
		workloads := []WorkloadSummary{{resource: resource, status: apis.StatusFailed}}
		attachAssistedRemediation(summary, workloads, "C-0041", results, false, showEvidence)
		return workloads[0].assistedRemediation
	}

	assert.Equal(t, hostNetwork, render(false), "--verbose alone keeps the bare path")
	assert.True(t, strings.HasSuffix(render(true), "(current: true)"), "--show-evidence adds the value")
}
