package cautils

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReportV2ToV1(t *testing.T) {
	tests := []struct {
		name                string
		session             *OPASessionObj
		wantFrameworkNames  []string
		wantFrameworkScores []float32
	}{
		{
			name: "summary controls without frameworks create default framework",
			session: &OPASessionObj{
				Report: &reporthandlingv2.PostureReport{
					SummaryDetails: reportsummary.SummaryDetails{
						Score: 77,
						Controls: reportsummary.ControlSummaries{
							"C-001": reportsummary.ControlSummary{
								ControlID:   "C-001",
								Name:        "control one",
								Score:       88,
								ScoreFactor: 5,
								Description: "description",
								Remediation: "remediation",
							},
						},
					},
				},
			},
			wantFrameworkNames:  []string{""},
			wantFrameworkScores: []float32{77},
		},
		{
			name: "framework summaries preserve names and scores",
			session: &OPASessionObj{
				Report: &reporthandlingv2.PostureReport{
					SummaryDetails: reportsummary.SummaryDetails{
						Frameworks: []reportsummary.FrameworkSummary{
							{Name: "NSA", Score: 90},
							{Name: "MITRE", Score: 55},
						},
					},
				},
			},
			wantFrameworkNames:  []string{"NSA", "MITRE"},
			wantFrameworkScores: []float32{90, 55},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ReportV2ToV1(tt.session)

			require.NotNil(t, got)
			require.Len(t, got.FrameworkReports, len(tt.wantFrameworkNames))
			for i := range tt.wantFrameworkNames {
				assert.Equal(t, tt.wantFrameworkNames[i], got.FrameworkReports[i].Name)
				assert.Equal(t, tt.wantFrameworkScores[i], got.FrameworkReports[i].Score)
			}
		})
	}
}

func TestReportV2ToV1_DoesNotMutateAllResources(t *testing.T) {
	resourceID := "apps/v1/ns/Deployment/demo"
	controlID := "C-001"

	controlSummary := reportsummary.ControlSummary{ControlID: controlID, Name: "control demo", ScoreFactor: 5}
	controlSummary.Append(helpersv1.NewStatus(apis.StatusFailed), resourceID)

	session := &OPASessionObj{
		AllResources: map[string]workloadinterface.IMetadata{
			resourceID: workloadinterface.NewWorkloadObj(map[string]any{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata":   map[string]any{"name": "demo", "namespace": "ns"},
				"spec":       map[string]any{"replicas": float64(2)},
			}),
		},
		ResourcesResult: map[string]resourcesresults.Result{
			resourceID: {
				ResourceID: resourceID,
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{
					{
						ControlID: controlID,
						ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
							{
								Name:   "rule-demo",
								Status: apis.StatusFailed,
								Paths: []armotypes.PosturePaths{
									{FailedPath: "spec.replicas", FixPath: armotypes.FixPath{Path: "spec.replicas", Value: "3"}},
								},
							},
						},
					},
				},
			},
		},
		Report: &reporthandlingv2.PostureReport{
			SummaryDetails: reportsummary.SummaryDetails{
				Controls: reportsummary.ControlSummaries{controlID: controlSummary},
			},
		},
	}

	got := ReportV2ToV1(session)

	// The conversion must not mutate the caller's shared resource.
	assert.Contains(t, session.AllResources[resourceID].GetObject(), "spec")

	// The v1 alert object must still be trimmed, proving the failed-rule branch ran.
	require.Len(t, got.FrameworkReports, 1)
	require.Len(t, got.FrameworkReports[0].ControlReports, 1)
	require.Len(t, got.FrameworkReports[0].ControlReports[0].RuleReports, 1)
	alertObjects := got.FrameworkReports[0].ControlReports[0].RuleReports[0].RuleResponses[0].AlertObject.K8SApiObjects
	require.Len(t, alertObjects, 1)
	assert.NotContains(t, alertObjects[0], "spec")
}

func TestReportV2ToV1_PreservesAllRemediationPathTypes(t *testing.T) {
	resourceID := "apps/v1/ns/Deployment/remediation-test"
	controlID := "C-002"

	controlSummary := reportsummary.ControlSummary{
		ControlID:   controlID,
		Name:        "control remediation",
		ScoreFactor: 3,
		Description: "test description",
		Remediation: "test remediation",
	}
	controlSummary.Append(helpersv1.NewStatus(apis.StatusFailed), resourceID)

	session := &OPASessionObj{
		AllResources: map[string]workloadinterface.IMetadata{
			resourceID: workloadinterface.NewWorkloadObj(map[string]any{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata":   map[string]any{"name": "remediation-test", "namespace": "ns"},
				"spec":       map[string]any{"privileged": true},
			}),
		},
		ResourcesResult: map[string]resourcesresults.Result{
			resourceID: {
				ResourceID: resourceID,
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{
					{
						ControlID: controlID,
						ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
							{
								Name:   "rule-remediation",
								Status: apis.StatusFailed,
								Paths: []armotypes.PosturePaths{
									{
										FailedPath: "spec.containers[0].securityContext.privileged",
										DeletePath: "spec.containers[0].securityContext.privileged",
										ReviewPath: "spec.containers[0].securityContext",
										FixPath:    armotypes.FixPath{Path: "spec.containers[0].securityContext.allowPrivilegeEscalation", Value: "false"},
										FixCommand: "kubectl patch deployment remediation-test",
									},
									{
										FixCommand: "kubectl label deployment remediation-test env=prod",
									},
								},
							},
						},
					},
				},
			},
		},
		Report: &reporthandlingv2.PostureReport{
			SummaryDetails: reportsummary.SummaryDetails{
				Controls: reportsummary.ControlSummaries{controlID: controlSummary},
			},
		},
	}

	got := ReportV2ToV1(session)

	require.NotNil(t, got)
	require.Len(t, got.FrameworkReports, 1)
	require.Len(t, got.FrameworkReports[0].ControlReports, 1)

	cr := got.FrameworkReports[0].ControlReports[0]
	assert.Equal(t, "test description", cr.Description)
	assert.Equal(t, "test remediation", cr.Remediation)
	assert.Equal(t, controlID, cr.ControlID)

	require.Len(t, cr.RuleReports, 1)
	require.Len(t, cr.RuleReports[0].RuleResponses, 1)

	resp := cr.RuleReports[0].RuleResponses[0]
	assert.Equal(t, []string{"spec.containers[0].securityContext.privileged"}, resp.FailedPaths)
	assert.Equal(t, []string{"spec.containers[0].securityContext.privileged"}, resp.DeletePaths)
	assert.Equal(t, []string{"spec.containers[0].securityContext"}, resp.ReviewPaths)
	assert.Equal(t, []armotypes.FixPath{{Path: "spec.containers[0].securityContext.allowPrivilegeEscalation", Value: "false"}}, resp.FixPaths)
	assert.Equal(t, "kubectl patch deployment remediation-test\nkubectl label deployment remediation-test env=prod", resp.FixCommand)
}
