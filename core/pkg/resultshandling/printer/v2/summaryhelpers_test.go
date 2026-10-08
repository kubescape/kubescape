package printer

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
)

func TestWorkfloadSummaryFailed(t *testing.T) {
	tests := []struct {
		name string
		ws   WorkloadSummary
		want bool
	}{
		{
			name: "Status Excluded",
			ws: WorkloadSummary{
				status: apis.StatusExcluded,
			},
			want: false,
		},
		{
			name: "Status Unknown",
			ws: WorkloadSummary{
				status: apis.StatusUnknown,
			},
			want: false,
		},
		{
			name: "Status Skipped",
			ws: WorkloadSummary{
				status: apis.StatusSkipped,
			},
			want: false,
		},
		{
			name: "Status Failed",
			ws: WorkloadSummary{
				status: apis.StatusFailed,
			},
			want: true,
		},
		{
			name: "Status passed",
			ws: WorkloadSummary{
				status: apis.StatusPassed,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, workloadSummaryFailed(&tt.ws))
		})
	}
}

func TestWorkloadSummaryPassed(t *testing.T) {
	tests := []struct {
		name string
		ws   WorkloadSummary
		want bool
	}{
		{
			name: "Status Excluded",
			ws: WorkloadSummary{
				status: apis.StatusExcluded,
			},
			want: false,
		},
		{
			name: "Status Unknown",
			ws: WorkloadSummary{
				status: apis.StatusUnknown,
			},
			want: false,
		},
		{
			name: "Status Skipped",
			ws: WorkloadSummary{
				status: apis.StatusSkipped,
			},
			want: false,
		},
		{
			name: "Status Failed",
			ws: WorkloadSummary{
				status: apis.StatusFailed,
			},
			want: false,
		},
		{
			name: "Status passed",
			ws: WorkloadSummary{
				status: apis.StatusPassed,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, workloadSummaryPassed(&tt.ws))
		})
	}
}

func TestWorkloadSummarySkipped(t *testing.T) {
	tests := []struct {
		name string
		ws   WorkloadSummary
		want bool
	}{
		{
			name: "Status Excluded",
			ws: WorkloadSummary{
				status: apis.StatusExcluded,
			},
			want: false,
		},
		{
			name: "Status Unknown",
			ws: WorkloadSummary{
				status: apis.StatusUnknown,
			},
			want: false,
		},
		{
			name: "Status Skipped",
			ws: WorkloadSummary{
				status: apis.StatusSkipped,
			},
			want: true,
		},
		{
			name: "Status Failed",
			ws: WorkloadSummary{
				status: apis.StatusFailed,
			},
			want: false,
		},
		{
			name: "Status passed",
			ws: WorkloadSummary{
				status: apis.StatusPassed,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, workloadSummarySkipped(&tt.ws))
		})
	}
}

func TestIsKindToBeGrouped(t *testing.T) {
	tests := []struct {
		name string
		kind string
		want bool
	}{
		{
			name: "Kind is Empty",
			kind: "",
			want: false,
		},
		{
			name: "Kind is User",
			kind: "User",
			want: true,
		},
		{
			name: "Kind is Group",
			kind: "Group",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isKindToBeGrouped(tt.kind))
		})
	}
}

func TestGroupByNamespaceOrKind(t *testing.T) {
	// Create mock workloads
	w1 := workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"namespace": "default",
			"name":      "pod1",
		},
	})

	w2 := workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"namespace": "kube-system",
			"name":      "pod2",
		},
	})

	w3 := workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata": map[string]interface{}{
			"name": "clusterrole1", // Empty namespace workload case
		},
	})

	// Create RegoResponseVectorObject
	r1 := objectsenvelopes.NewRegoResponseVectorObject(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "User",
		"metadata": map[string]interface{}{
			"name": "user1",
		},
	})

	// RegoResponseVectorObject not in the allowed Group/User to test fallthrough
	rFallthrough := objectsenvelopes.NewRegoResponseVectorObject(map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "RoleBinding",
		"metadata": map[string]interface{}{
			"name": "rolebinding1",
		},
	})

	// Non-workload envelope to test default apiGroup parsing branch
	lw := localworkload.NewLocalWorkload(map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      "d1",
			"namespace": "default",
		},
		"sourcePath":   "/tmp/a.yaml",
		"relativePath": "a.yaml",
	})

	tests := []struct {
		name            string
		resources       []WorkloadSummary
		filterFunc      func(*WorkloadSummary) bool
		expectedBuckets map[string][]workloadinterface.IMetadata
	}{
		{
			name: "StatusFailed filter with various resource types",
			resources: []WorkloadSummary{
				{resource: w1, status: apis.StatusFailed},
				{resource: w2, status: apis.StatusFailed},
				{resource: w3, status: apis.StatusFailed},
				{resource: r1, status: apis.StatusFailed},
				{resource: rFallthrough, status: apis.StatusFailed},
				{resource: lw, status: apis.StatusFailed},
			},
			filterFunc: workloadSummaryFailed,
			expectedBuckets: map[string][]workloadinterface.IMetadata{
				"Namespace default":     {w1},
				"Namespace kube-system": {w2},
				"":                      {w3, rFallthrough},
				"Users":                 {r1},
				"apps":                  {lw},
			},
		},
		{
			name: "StatusPassed filter ensures StatusFailed are skipped",
			resources: []WorkloadSummary{
				{resource: w1, status: apis.StatusFailed},
				{resource: w2, status: apis.StatusPassed},
			},
			filterFunc: workloadSummaryPassed,
			expectedBuckets: map[string][]workloadinterface.IMetadata{
				"Namespace kube-system": {w2},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := groupByNamespaceOrKind(tt.resources, tt.filterFunc)

			// Verify total cardinality to ensure nothing was grouped unexpectedly
			expectedCount := 0
			for _, expectedResList := range tt.expectedBuckets {
				expectedCount += len(expectedResList)
			}
			actualCount := 0
			for _, resList := range result {
				actualCount += len(resList)
			}
			assert.Equal(t, expectedCount, actualCount, "Total number of resources grouped does not match")

			// Verify identity and exact bucket lengths
			for group, expectedResList := range tt.expectedBuckets {
				assert.Contains(t, result, group)
				assert.Len(t, result[group], len(expectedResList))

				for _, expectedRes := range expectedResList {
					found := false
					for _, res := range result[group] {
						if res.resource == expectedRes {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected to find specific resource in group %s", group)
				}
			}
		})
	}
}

func TestCollectSkippedControls_FillMissingDescriptionAndRemediation(t *testing.T) {
	t.Run("Policy metadata has valid name and nonzero score but empty description and remediation", func(t *testing.T) {
		session := &cautils.OPASessionObj{
			AllPolicies: &cautils.Policies{
				Controls: map[string]reporthandling.Control{
					"C-0001": {
						PortalBase: armotypes.PortalBase{
							Name: "Policy Control Name",
						},
						ControlID: "C-0001",
						BaseScore: 5.0,
						// Description and Remediation left empty
					},
				},
			},
			Report: &reporthandlingv2.PostureReport{
				SummaryDetails: reportsummary.SummaryDetails{
					Controls: reportsummary.ControlSummaries{
						"C-0001": reportsummary.ControlSummary{
							ControlID:   "C-0001",
							Name:        "Summary Control Name",
							Description: "Summary Description",
							Remediation: "Summary Remediation",
							ScoreFactor: 7.0,
						},
					},
				},
			},
			ScanCoverage: cautils.ScanCoverage{
				NotEvaluatedControls: []cautils.NotEvaluatedControl{
					{
						ControlID:   "C-0001",
						MissingGVRs: []string{"apps/v1/daemonsets"},
					},
				},
			},
		}

		results := collectSkippedControls(session)
		assert.Len(t, results, 1)
		assert.Equal(t, "C-0001", results[0].controlID)
		assert.Equal(t, "Policy Control Name", results[0].name)
		assert.Equal(t, float32(5.0), results[0].scoreFactor)
		assert.Equal(t, "Summary Description", results[0].description)
		assert.Equal(t, "Summary Remediation", results[0].remediation)
		assert.Equal(t, "missing: apps/v1/daemonsets", results[0].reason)
	})

	t.Run("Policy metadata missing only description", func(t *testing.T) {
		session := &cautils.OPASessionObj{
			AllPolicies: &cautils.Policies{
				Controls: map[string]reporthandling.Control{
					"C-0002": {
						PortalBase: armotypes.PortalBase{
							Name: "Policy Control Name",
						},
						ControlID:   "C-0002",
						BaseScore:   6.0,
						Remediation: "Policy Remediation",
					},
				},
			},
			Report: &reporthandlingv2.PostureReport{
				SummaryDetails: reportsummary.SummaryDetails{
					Controls: reportsummary.ControlSummaries{
						"C-0002": reportsummary.ControlSummary{
							ControlID:   "C-0002",
							Description: "Summary Description",
							Remediation: "Summary Remediation",
						},
					},
				},
			},
			ScanCoverage: cautils.ScanCoverage{
				NotEvaluatedControls: []cautils.NotEvaluatedControl{
					{ControlID: "C-0002"},
				},
			},
		}

		results := collectSkippedControls(session)
		assert.Len(t, results, 1)
		assert.Equal(t, "Policy Control Name", results[0].name)
		assert.Equal(t, float32(6.0), results[0].scoreFactor)
		assert.Equal(t, "Summary Description", results[0].description)
		assert.Equal(t, "Policy Remediation", results[0].remediation)
	})

	t.Run("Policy metadata missing only remediation", func(t *testing.T) {
		session := &cautils.OPASessionObj{
			AllPolicies: &cautils.Policies{
				Controls: map[string]reporthandling.Control{
					"C-0003": {
						PortalBase: armotypes.PortalBase{
							Name: "Policy Control Name",
						},
						ControlID:   "C-0003",
						BaseScore:   6.0,
						Description: "Policy Description",
					},
				},
			},
			Report: &reporthandlingv2.PostureReport{
				SummaryDetails: reportsummary.SummaryDetails{
					Controls: reportsummary.ControlSummaries{
						"C-0003": reportsummary.ControlSummary{
							ControlID:   "C-0003",
							Description: "Summary Description",
							Remediation: "Summary Remediation",
						},
					},
				},
			},
			ScanCoverage: cautils.ScanCoverage{
				NotEvaluatedControls: []cautils.NotEvaluatedControl{
					{ControlID: "C-0003"},
				},
			},
		}

		results := collectSkippedControls(session)
		assert.Len(t, results, 1)
		assert.Equal(t, "Policy Control Name", results[0].name)
		assert.Equal(t, float32(6.0), results[0].scoreFactor)
		assert.Equal(t, "Policy Description", results[0].description)
		assert.Equal(t, "Summary Remediation", results[0].remediation)
	})

	t.Run("Policy metadata already has all fields populated", func(t *testing.T) {
		session := &cautils.OPASessionObj{
			AllPolicies: &cautils.Policies{
				Controls: map[string]reporthandling.Control{
					"C-0004": {
						PortalBase: armotypes.PortalBase{
							Name: "Policy Name",
						},
						ControlID:   "C-0004",
						BaseScore:   8.0,
						Description: "Policy Description",
						Remediation: "Policy Remediation",
					},
				},
			},
			Report: &reporthandlingv2.PostureReport{
				SummaryDetails: reportsummary.SummaryDetails{
					Controls: reportsummary.ControlSummaries{
						"C-0004": reportsummary.ControlSummary{
							ControlID:   "C-0004",
							Name:        "Summary Name",
							Description: "Summary Description",
							Remediation: "Summary Remediation",
							ScoreFactor: 3.0,
						},
					},
				},
			},
			ScanCoverage: cautils.ScanCoverage{
				NotEvaluatedControls: []cautils.NotEvaluatedControl{
					{ControlID: "C-0004"},
				},
			},
		}

		results := collectSkippedControls(session)
		assert.Len(t, results, 1)
		assert.Equal(t, "Policy Name", results[0].name)
		assert.Equal(t, float32(8.0), results[0].scoreFactor)
		assert.Equal(t, "Policy Description", results[0].description)
		assert.Equal(t, "Policy Remediation", results[0].remediation)
	})

	t.Run("Nil OPASessionObj and Nil Report do not panic", func(t *testing.T) {
		assert.Nil(t, collectSkippedControls(nil))

		sessionWithoutReport := &cautils.OPASessionObj{
			AllPolicies: &cautils.Policies{
				Controls: map[string]reporthandling.Control{
					"C-0005": {
						PortalBase: armotypes.PortalBase{
							Name: "Policy Name",
						},
						ControlID: "C-0005",
						BaseScore: 4.0,
					},
				},
			},
			ScanCoverage: cautils.ScanCoverage{
				NotEvaluatedControls: []cautils.NotEvaluatedControl{
					{ControlID: "C-0005"},
				},
			},
		}
		results := collectSkippedControls(sessionWithoutReport)
		assert.Len(t, results, 1)
		assert.Equal(t, "Policy Name", results[0].name)
		assert.Equal(t, float32(4.0), results[0].scoreFactor)
		assert.Equal(t, "", results[0].description)
		assert.Equal(t, "", results[0].remediation)
	})

	t.Run("Overlapping control in summary and ScanCoverage has status not evaluated", func(t *testing.T) {
		skippedStatus := &apis.StatusInfo{
			InnerStatus: apis.StatusSkipped,
			SubStatus:   apis.SubStatusConfiguration,
			InnerInfo:   "initial skip reason",
		}
		session := &cautils.OPASessionObj{
			Report: &reporthandlingv2.PostureReport{
				SummaryDetails: reportsummary.SummaryDetails{
					Controls: reportsummary.ControlSummaries{
						"C-0006": reportsummary.ControlSummary{
							ControlID:   "C-0006",
							Name:        "Overlapping Control",
							ScoreFactor: 5.0,
							StatusInfo:  *skippedStatus,
						},
					},
				},
			},
			ScanCoverage: cautils.ScanCoverage{
				NotEvaluatedControls: []cautils.NotEvaluatedControl{
					{
						ControlID: "C-0006",
						Reason:    "evaluation timed out",
					},
				},
			},
		}

		results := collectSkippedControls(session)
		assert.Len(t, results, 1)
		assert.Equal(t, "C-0006", results[0].controlID)
		assert.Equal(t, "Overlapping Control", results[0].name)
		assert.Equal(t, "not evaluated", results[0].status)
		assert.Equal(t, "configuration: initial skip reason", results[0].reason)
	})
}
