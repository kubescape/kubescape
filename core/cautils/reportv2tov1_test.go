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

func TestReportV2ToV1_StatusCounters(t *testing.T) {
	controlID := "C-001"
	controlSummary := reportsummary.ControlSummary{
		ControlID:   controlID,
		Name:        "control demo",
		ScoreFactor: 5,
		StatusCounters: reportsummary.StatusCounters{
			PassedResources:   1,
			FailedResources:   2,
			SkippedResources:  3,
			ExcludedResources: 4,
		},
	}

	session := &OPASessionObj{
		Report: &reporthandlingv2.PostureReport{
			SummaryDetails: reportsummary.SummaryDetails{
				Controls: reportsummary.ControlSummaries{controlID: controlSummary},
			},
		},
	}

	got := ReportV2ToV1(session)

	require.Len(t, got.FrameworkReports, 1)
	require.Len(t, got.FrameworkReports[0].ControlReports, 1)

	cr := got.FrameworkReports[0].ControlReports[0]
	assert.Equal(t, 10, cr.TotalResources)
	assert.Equal(t, 2, cr.FailedResources)
	assert.Equal(t, 7, cr.WarningResources)
}

func TestReportV2ToV1_DuplicateFrameworkNames(t *testing.T) {
	session := &OPASessionObj{
		Report: &reporthandlingv2.PostureReport{
			SummaryDetails: reportsummary.SummaryDetails{
				Frameworks: []reportsummary.FrameworkSummary{
					{
						Name: "custom-rules",
						Controls: reportsummary.ControlSummaries{
							"C-001": reportsummary.ControlSummary{
								ControlID: "C-001",
								StatusCounters: reportsummary.StatusCounters{
									PassedResources: 1,
									FailedResources: 1,
								},
							},
						},
					},
					{
						Name: "custom-rules",
						Controls: reportsummary.ControlSummaries{
							"C-002": reportsummary.ControlSummary{
								ControlID: "C-002",
								StatusCounters: reportsummary.StatusCounters{
									SkippedResources:  1,
									ExcludedResources: 1,
								},
							},
						},
					},
				},
			},
		},
	}

	got := ReportV2ToV1(session)

	require.Len(t, got.FrameworkReports, 2)
	assert.Equal(t, "custom-rules", got.FrameworkReports[0].Name)
	assert.Equal(t, "custom-rules", got.FrameworkReports[1].Name)

	require.Len(t, got.FrameworkReports[0].ControlReports, 1)
	assert.Equal(t, "C-001", got.FrameworkReports[0].ControlReports[0].ControlID)
	assert.Equal(t, 2, got.FrameworkReports[0].ControlReports[0].TotalResources)

	require.Len(t, got.FrameworkReports[1].ControlReports, 1)
	cr2 := got.FrameworkReports[1].ControlReports[0]
	assert.Equal(t, "C-002", cr2.ControlID)
	assert.Equal(t, 2, cr2.TotalResources)
	assert.Equal(t, 2, cr2.WarningResources)
}

func TestFrameworkScopedReportV2ToV1(t *testing.T) {
	control := reportsummary.ControlSummary{ControlID: "C-0034"}
	control.Append(helpersv1.NewStatus(apis.StatusFailed), "resource")
	session := &OPASessionObj{ResourcesResult: map[string]resourcesresults.Result{"resource": {ResourceID: "resource", AssociatedControls: []resourcesresults.ResourceAssociatedControl{{ControlID: "C-0034", ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Name: "R1", Status: apis.StatusFailed, Exception: []armotypes.PostureExceptionPolicy{{Actions: []armotypes.PostureExceptionPolicyActions{armotypes.Disable}, PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0034", RuleName: "R1"}}}}}}}}}}}
	for _, framework := range []string{"NSA", "MITRE"} {
		reports := controlReportV2ToV1(session, framework, reportsummary.ControlSummaries{"C-0034": control})
		require.Len(t, reports, 1)
		require.Len(t, reports[0].RuleReports, 1)
		assert.Equal(t, framework == "MITRE", len(reports[0].RuleReports[0].RuleResponses) > 0, framework)
	}
}
