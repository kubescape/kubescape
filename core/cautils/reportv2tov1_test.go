package cautils

import (
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/version"
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

// The OPA processor records a rule's paths as DeletePath / ReviewPath /
// FixCommand entries and no longer sets FailedPath (#3598); the v1 rule
// response has to carry them or every v1 finding loses its location.
func TestReportV2ToV1_MapsDeleteReviewPathsAndFixCommand(t *testing.T) {
	resourceID := "/v1/default/Pod/demo"
	controlID := "C-0038"

	controlSummary := reportsummary.ControlSummary{ControlID: controlID, Name: "host pid", ScoreFactor: 7}
	controlSummary.Append(helpersv1.NewStatus(apis.StatusFailed), resourceID)

	session := &OPASessionObj{
		AllResources: map[string]workloadinterface.IMetadata{
			resourceID: workloadinterface.NewWorkloadObj(map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata":   map[string]any{"name": "demo", "namespace": "default"},
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
								Name:   "host-pid-ipc-privileges",
								Status: apis.StatusFailed,
								Paths: []armotypes.PosturePaths{
									{ResourceID: resourceID, DeletePath: "spec.hostPID"},
									{ResourceID: resourceID, ReviewPath: "spec.containers[0].image"},
									{ResourceID: resourceID, FixPath: armotypes.FixPath{Path: "spec.hostIPC", Value: "false"}},
									{ResourceID: resourceID, FixCommand: "kubectl delete pod demo"},
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

	require.Len(t, got.FrameworkReports, 1)
	require.Len(t, got.FrameworkReports[0].ControlReports, 1)
	require.Len(t, got.FrameworkReports[0].ControlReports[0].RuleReports, 1)
	require.Len(t, got.FrameworkReports[0].ControlReports[0].RuleReports[0].RuleResponses, 1)
	response := got.FrameworkReports[0].ControlReports[0].RuleReports[0].RuleResponses[0]
	assert.Equal(t, []string{"spec.hostPID"}, response.DeletePaths)
	assert.Equal(t, []string{"spec.containers[0].image"}, response.ReviewPaths)
	assert.Equal(t, []armotypes.FixPath{{Path: "spec.hostIPC", Value: "false"}}, response.FixPaths)
	assert.Equal(t, "kubectl delete pod demo", response.FixCommand)
}

// A rule's paths can belong to a related resource: the processor records a
// RelatedObject's paths under that object's ResourceID (exposure-to-internet
// reports the exposing Service's spec.type against the failed Pod). The v1
// response must keep them on that related object, not move them onto the Pod.
func TestReportV2ToV1_KeepsRelatedResourcePathsOnRelatedObject(t *testing.T) {
	podID := "/v1/default/Pod/demo"
	serviceID := "/v1/default/Service/demo-svc"
	controlID := "C-0256"

	controlSummary := reportsummary.ControlSummary{ControlID: controlID, Name: "exposure to internet", ScoreFactor: 7}
	controlSummary.Append(helpersv1.NewStatus(apis.StatusFailed), podID)

	session := &OPASessionObj{
		AllResources: map[string]workloadinterface.IMetadata{
			podID: workloadinterface.NewWorkloadObj(map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata":   map[string]any{"name": "demo", "namespace": "default"},
				"spec":       map[string]any{"hostPID": true},
			}),
			serviceID: workloadinterface.NewWorkloadObj(map[string]any{
				"apiVersion": "v1",
				"kind":       "Service",
				"metadata":   map[string]any{"name": "demo-svc", "namespace": "default"},
				"spec":       map[string]any{"type": "LoadBalancer"},
			}),
		},
		ResourcesResult: map[string]resourcesresults.Result{
			podID: {
				ResourceID: podID,
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{
					{
						ControlID: controlID,
						ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
							{
								Name:                "exposure-to-internet",
								Status:              apis.StatusFailed,
								RelatedResourcesIDs: []string{serviceID},
								Paths: []armotypes.PosturePaths{
									{ResourceID: podID, DeletePath: "spec.hostPID"},
									{ResourceID: podID, FixCommand: "kubectl label pod demo exposed=false"},
									{ResourceID: serviceID, ReviewPath: "spec.type"},
									{ResourceID: serviceID, DeletePath: "spec.externalIPs"},
									{ResourceID: serviceID, FixCommand: "kubectl patch svc demo-svc -p '{\"spec\":{\"type\":\"ClusterIP\"}}'"},
									{ResourceID: serviceID, FixCommand: "kubectl annotate svc demo-svc reviewed=true"},
									{ResourceID: serviceID, FixCommand: "kubectl annotate svc demo-svc reviewed=true"},
									// legacy data without a ResourceID describes the failed resource
									{FailedPath: "spec.hostNetwork"},
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

	require.Len(t, got.FrameworkReports, 1)
	require.Len(t, got.FrameworkReports[0].ControlReports, 1)
	require.Len(t, got.FrameworkReports[0].ControlReports[0].RuleReports, 1)
	require.Len(t, got.FrameworkReports[0].ControlReports[0].RuleReports[0].RuleResponses, 1)
	response := got.FrameworkReports[0].ControlReports[0].RuleReports[0].RuleResponses[0]

	// the Pod keeps only its own remediation
	assert.Equal(t, []string{"spec.hostPID"}, response.DeletePaths)
	assert.Nil(t, response.ReviewPaths, "the Service's spec.type must not be reported against the Pod")
	assert.Equal(t, []string{"spec.hostNetwork"}, response.FailedPaths)
	assert.Equal(t, "kubectl label pod demo exposed=false", response.FixCommand)
	require.Len(t, response.AlertObject.K8SApiObjects, 1)
	assert.Equal(t, "Pod", response.AlertObject.K8SApiObjects[0]["kind"])

	// the Service's remediation stays attached to the Service
	require.Len(t, response.RelatedObjects, 1)
	related := response.RelatedObjects[0]
	assert.Equal(t, "Service", related.Object["kind"])
	assert.Equal(t, map[string]any{"name": "demo-svc", "namespace": "default"}, related.Object["metadata"])
	assert.Equal(t, []string{"spec.type"}, related.ReviewPaths)
	assert.Equal(t, []string{"spec.externalIPs"}, related.DeletePaths)
	assert.Equal(t, "kubectl patch svc demo-svc -p '{\"spec\":{\"type\":\"ClusterIP\"}}'\nkubectl annotate svc demo-svc reviewed=true", related.FixCommand)
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

	assert.Equal(t, 10, got.FrameworkReports[0].TotalResources)
	assert.Equal(t, 2, got.FrameworkReports[0].FailedResources)
	assert.Equal(t, 7, got.FrameworkReports[0].WarningResources)
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

	assert.Equal(t, 2, got.FrameworkReports[0].TotalResources)
	assert.Equal(t, 1, got.FrameworkReports[0].FailedResources)
	assert.Equal(t, 2, got.FrameworkReports[1].TotalResources)
	assert.Equal(t, 2, got.FrameworkReports[1].WarningResources)
}

func TestReportV2ToV1_Metadata(t *testing.T) {
	now := time.Now().UTC()
	apiServerInfo := &version.Info{GitVersion: "v1.30.0", Platform: "linux/amd64"}
	resources := []reporthandling.Resource{
		{
			ResourceID: "apps/v1/default/Deployment/demo-app",
		},
	}
	session := &OPASessionObj{
		Report: &reporthandlingv2.PostureReport{
			CustomerGUID:         "customer-123",
			ClusterName:          "prod-cluster",
			ClusterAPIServerInfo: apiServerInfo,
			ClusterCloudProvider: "gke",
			ReportID:             "report-456",
			JobID:                "job-789",
			ReportGenerationTime: now,
			Resources:            resources,
		},
	}

	got := ReportV2ToV1(session)

	assert.Equal(t, "customer-123", got.CustomerGUID)
	assert.Equal(t, "prod-cluster", got.ClusterName)
	assert.Equal(t, apiServerInfo, got.ClusterAPIServerInfo)
	assert.Equal(t, "gke", got.ClusterCloudProvider)
	assert.Equal(t, "report-456", got.ReportID)
	assert.Equal(t, "job-789", got.JobID)
	assert.Equal(t, now, got.ReportGenerationTime)
	assert.Equal(t, resources, got.Resources)
}

func TestReportV2ToV1_NilSafety(t *testing.T) {
	gotNil := ReportV2ToV1(nil)
	require.NotNil(t, gotNil)
	assert.Empty(t, gotNil.FrameworkReports)

	gotEmpty := ReportV2ToV1(&OPASessionObj{})
	require.NotNil(t, gotEmpty)
	assert.Empty(t, gotEmpty.FrameworkReports)
}

func TestReportV2ToV1_FrameworkStatusCounters_MultipleControls(t *testing.T) {
	// Framework counters aggregate unique resources across multiple controls
	// and therefore differ from any individual control's counters.
	session := &OPASessionObj{
		Report: &reporthandlingv2.PostureReport{
			SummaryDetails: reportsummary.SummaryDetails{
				Frameworks: []reportsummary.FrameworkSummary{
					{
						Name: "cis-v1.23",
						StatusCounters: reportsummary.StatusCounters{
							PassedResources:   5,
							FailedResources:   3,
							SkippedResources:  2,
							ExcludedResources: 1,
						},
						Controls: reportsummary.ControlSummaries{
							"C-001": reportsummary.ControlSummary{
								ControlID: "C-001",
								StatusCounters: reportsummary.StatusCounters{
									PassedResources: 3,
									FailedResources: 1,
								},
							},
							"C-002": reportsummary.ControlSummary{
								ControlID: "C-002",
								StatusCounters: reportsummary.StatusCounters{
									PassedResources:   3,
									FailedResources:   2,
									SkippedResources:  2,
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

	require.Len(t, got.FrameworkReports, 1)
	fw := got.FrameworkReports[0]
	assert.Equal(t, "cis-v1.23", fw.Name)

	// Framework totals: Passed(5) + Failed(3) + Skipped(2) + Excluded(1) = 11
	assert.Equal(t, 11, fw.TotalResources)
	assert.Equal(t, 3, fw.FailedResources)
	assert.Equal(t, 3, fw.WarningResources) // Skipped(2) + Excluded(1) = 3

	// Controls have their own individual totals
	require.Len(t, fw.ControlReports, 2)
	for _, cr := range fw.ControlReports {
		switch cr.ControlID {
		case "C-001":
			assert.Equal(t, 4, cr.TotalResources)
			assert.Equal(t, 1, cr.FailedResources)
		case "C-002":
			assert.Equal(t, 8, cr.TotalResources)
			assert.Equal(t, 2, cr.FailedResources)
			assert.Equal(t, 3, cr.WarningResources)
		}
	}
}
