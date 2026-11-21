package mcpserver

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildScanResponse(t *testing.T) {
	floatPtr := func(v float32) *float32 { return &v }

	tests := []struct {
		name                 string
		numPassing           int
		numFailing           int
		complianceScore      *float32
		frameworkName        string
		degraded             bool
		notEvaluatedControls int
		totalControls        int
		wantTotal            int
		wantReturned         int
		wantTruncated        bool
	}{
		{
			name:            "No resources",
			numPassing:      0,
			numFailing:      0,
			complianceScore: nil,
			wantTotal:       0,
			wantReturned:    0,
			wantTruncated:   false,
		},
		{
			name:                 "With 0.0 score",
			numPassing:           0,
			numFailing:           5,
			complianceScore:      floatPtr(0.0),
			frameworkName:        "nsa",
			degraded:             true,
			notEvaluatedControls: 2,
			totalControls:        10,
			wantTotal:            5,
			wantReturned:         5,
			wantTruncated:        false,
		},
		{
			name:          "Only passing resources",
			numPassing:    10,
			numFailing:    0,
			wantTotal:     0,
			wantReturned:  0,
			wantTruncated: false,
		},
		{
			name:            "Exactly at cap (100 failing)",
			numPassing:      10,
			numFailing:      100,
			complianceScore: floatPtr(95.5),
			frameworkName:   "mitre",
			wantTotal:       100,
			wantReturned:    100,
			wantTruncated:   false,
		},
		{
			name:          "Over cap (105 failing)",
			numPassing:    10,
			numFailing:    105,
			wantTotal:     105,
			wantReturned:  100,
			wantTruncated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := make(map[string]resourcesresults.Result)

			for i := 0; i < tt.numPassing; i++ {
				results[fmt.Sprintf("pass-%d", i)] = resourcesresults.Result{
					ResourceID: fmt.Sprintf("pass-%d", i),
					AssociatedControls: []resourcesresults.ResourceAssociatedControl{
						{
							Status: apis.StatusInfo{
								InnerStatus: apis.StatusPassed,
							},
						},
					},
				}
			}
			for i := 0; i < tt.numFailing; i++ {
				results[fmt.Sprintf("fail-%d", i)] = resourcesresults.Result{
					ResourceID: fmt.Sprintf("fail-%d", i),
					AssociatedControls: []resourcesresults.ResourceAssociatedControl{
						{
							Status: apis.StatusInfo{
								InnerStatus: apis.StatusFailed,
							},
						},
					},
				}
			}
			resp := buildScanResponse(nil, results, tt.complianceScore, tt.frameworkName, tt.degraded, tt.notEvaluatedControls, tt.totalControls)

			if resp.TotalFailed != tt.wantTotal {
				t.Errorf("TotalFailed = %d, want %d", resp.TotalFailed, tt.wantTotal)
			}
			if resp.ReturnedFailed != tt.wantReturned {
				t.Errorf("ReturnedFailed = %d, want %d", resp.ReturnedFailed, tt.wantReturned)
			}
			if resp.Truncated != tt.wantTruncated {
				t.Errorf("Truncated = %v, want %v", resp.Truncated, tt.wantTruncated)
			}
			if len(resp.FailedResources) != tt.wantReturned {
				t.Errorf("len(FailedResources) = %d, want %d", len(resp.FailedResources), tt.wantReturned)
			}
			if tt.complianceScore != nil {
				if resp.ComplianceScore == nil {
					t.Fatalf("ComplianceScore = nil, want %f", *tt.complianceScore)
				}
				if *resp.ComplianceScore != *tt.complianceScore {
					t.Errorf("ComplianceScore = %f, want %f", *resp.ComplianceScore, *tt.complianceScore)
				}
			}

			if tt.wantTruncated {
				var expectedKeys []string
				for k := range results {
					expectedKeys = append(expectedKeys, k)
				}
				sort.Strings(expectedKeys)

				var expectedFailedKeys []string
				for _, k := range expectedKeys {
					res := results[k]
					if cautils.ResourceStatus(nil, &res).IsFailed() {
						expectedFailedKeys = append(expectedFailedKeys, k)
					}
				}

				for i, res := range resp.FailedResources {
					actualRes := res.(resourcesresults.Result)
					if actualRes.ResourceID != expectedFailedKeys[i] {
						t.Errorf("Deterministic sort failed at index %d: expected %s, got %s", i, expectedFailedKeys[i], actualRes.ResourceID)
					}
				}
			}

			jsonBytes, err := json.Marshal(resp)
			if err != nil {
				t.Fatalf("Failed to marshal scan response: %v", err)
			}

			var decodedResp scanResponse
			if err := json.Unmarshal(jsonBytes, &decodedResp); err != nil {
				t.Fatalf("Failed to unmarshal JSON back into scanResponse: %v", err)
			}

			if decodedResp.TotalFailed != resp.TotalFailed || decodedResp.Truncated != resp.Truncated {
				t.Errorf("Decoded fields do not match original struct")
			}

			if tt.wantReturned == 0 {
				jsonStr := string(jsonBytes)
				if !strings.Contains(jsonStr, `"failed_resources": []`) && !strings.Contains(jsonStr, `"failed_resources":[]`) {
					t.Errorf("Expected empty array for failed_resources, got JSON: %s", jsonStr)
				}
			}

			if tt.complianceScore != nil {
				jsonStr := string(jsonBytes)
				if !strings.Contains(jsonStr, `"compliance_score"`) {
					t.Errorf("Expected compliance_score to be marshaled, got JSON: %s", jsonStr)
				}
			} else {
				jsonStr := string(jsonBytes)
				if strings.Contains(jsonStr, `"compliance_score"`) {
					t.Errorf("Expected compliance_score to be omitted, got JSON: %s", jsonStr)
				}
			}
		})
	}
}

func TestBuildScanInfo(t *testing.T) {
	tests := []struct {
		name                string
		namespace           string
		wantComplianceScore bool
		expectedNamespace   string
		expectedTimeout     time.Duration
	}{
		{
			name:                "Cluster-wide scan (wildcard)",
			namespace:           "*",
			wantComplianceScore: false,
			expectedNamespace:   "",
			expectedTimeout:     60 * time.Second,
		},
		{
			name:                "Cluster-wide scan (empty string)",
			namespace:           "",
			wantComplianceScore: false,
			expectedNamespace:   "",
			expectedTimeout:     60 * time.Second,
		},
		{
			name:                "Specific namespace scan",
			namespace:           "default",
			wantComplianceScore: false,
			expectedNamespace:   "default",
			expectedTimeout:     10 * time.Second,
		},
		{
			name:                "Cluster-wide scan with compliance score (wildcard)",
			namespace:           "*",
			wantComplianceScore: true,
			expectedNamespace:   "",
			expectedTimeout:     120 * time.Second,
		},
		{
			name:                "Specific namespace scan with compliance score",
			namespace:           "default",
			wantComplianceScore: true,
			expectedNamespace:   "default",
			expectedTimeout:     30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanInfo := buildScanInfo(scanRequest{
				namespace:           tt.namespace,
				wantComplianceScore: tt.wantComplianceScore,
			})
			assert.Equal(t, tt.expectedNamespace, scanInfo.IncludeNamespaces, "IncludeNamespaces should match")
			assert.Equal(t, tt.expectedTimeout, scanInfo.ScanTimeout, "ScanTimeout should match")
		})
	}
}

func TestBuildScanResponse_FrameworkScopedExceptionKeepsWorkloadOutOfFailedResources(t *testing.T) {
	controlID := "C-0041"
	workloadID := "default/Pod/test-workload"

	exceptedRule := resourcesresults.ResourceAssociatedRule{
		Name:   "host-network-access",
		Status: apis.StatusFailed,
		Exception: []armotypes.PostureExceptionPolicy{
			{
				PortalBase:      armotypes.PortalBase{Name: "nsa-only-exception"},
				Actions:         []armotypes.PostureExceptionPolicyActions{armotypes.Disable},
				PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: controlID}},
			},
		},
	}

	result := resourcesresults.Result{
		ResourceID: workloadID,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{
				ControlID:               controlID,
				Status:                  apis.StatusInfo{InnerStatus: apis.StatusFailed},
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{exceptedRule},
			},
		},
	}

	results := map[string]resourcesresults.Result{
		workloadID: result,
	}

	// 1. Scanned in framework "NSA" where the exception applies:
	// cautils.ResourceStatus evaluates the workload as passed (with exception substatus),
	// keeping it out of failedResources and leaving totalFailed at 0.
	nsaSummary := &reportsummary.SummaryDetails{
		Frameworks: []reportsummary.FrameworkSummary{
			{
				Name: "NSA",
				Controls: reportsummary.ControlSummaries{
					controlID: reportsummary.ControlSummary{ControlID: controlID},
				},
			},
		},
	}

	nsaResp := buildScanResponse(nsaSummary, results, nil, "NSA", false, 0, 1)
	assert.Equal(t, 0, nsaResp.TotalFailed)
	assert.Equal(t, 0, nsaResp.ReturnedFailed)
	assert.Empty(t, nsaResp.FailedResources)

	// 2. Scanned in another framework (e.g., "MITRE") where the exception does not apply:
	// The workload remains failed and is returned in failedResources.
	mitreSummary := &reportsummary.SummaryDetails{
		Frameworks: []reportsummary.FrameworkSummary{
			{
				Name: "MITRE",
				Controls: reportsummary.ControlSummaries{
					controlID: reportsummary.ControlSummary{ControlID: controlID},
				},
			},
		},
	}

	mitreResp := buildScanResponse(mitreSummary, results, nil, "MITRE", false, 0, 1)
	assert.Equal(t, 1, mitreResp.TotalFailed)
	assert.Equal(t, 1, mitreResp.ReturnedFailed)
	require.Len(t, mitreResp.FailedResources, 1)
	assert.Equal(t, workloadID, mitreResp.FailedResources[0].(resourcesresults.Result).ResourceID)

	// 3. Without framework context (summary == nil), the framework-scoped exception
	// does not apply, and the workload remains failed.
	nilSummaryResp := buildScanResponse(nil, results, nil, "", false, 0, 1)
	assert.Equal(t, 1, nilSummaryResp.TotalFailed)
	assert.Equal(t, 1, nilSummaryResp.ReturnedFailed)
	require.Len(t, nilSummaryResp.FailedResources, 1)
}

func TestBuildScanResponse_SeveritySorting(t *testing.T) {
	summary := &reportsummary.SummaryDetails{
		Controls: reportsummary.ControlSummaries{
			"C-CRIT": reportsummary.ControlSummary{ControlID: "C-CRIT", ScoreFactor: 9.0},
			"C-HIGH": reportsummary.ControlSummary{ControlID: "C-HIGH", ScoreFactor: 7.0},
			"C-MED":  reportsummary.ControlSummary{ControlID: "C-MED", ScoreFactor: 4.0},
			"C-LOW":  reportsummary.ControlSummary{ControlID: "C-LOW", ScoreFactor: 1.0},
		},
	}

	makeFailingResource := func(id, controlID string) (string, resourcesresults.Result) {
		return id, resourcesresults.Result{
			ResourceID: id,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{
					ControlID: controlID,
					Status: apis.StatusInfo{
						InnerStatus: apis.StatusFailed,
					},
				},
			},
		}
	}

	results := make(map[string]resourcesresults.Result)
	id, res := makeFailingResource("res-low", "C-LOW")
	results[id] = res
	id, res = makeFailingResource("res-crit", "C-CRIT")
	results[id] = res
	id, res = makeFailingResource("res-med", "C-MED")
	results[id] = res
	id, res = makeFailingResource("res-high", "C-HIGH")
	results[id] = res

	resp := buildScanResponse(summary, results, nil, "test", false, 0, 4)
	require.Equal(t, 4, resp.TotalFailed)
	require.Equal(t, 4, resp.ReturnedFailed)
	require.Len(t, resp.FailedResources, 4)

	assert.Equal(t, "res-crit", resp.FailedResources[0].(resourcesresults.Result).ResourceID)
	assert.Equal(t, "res-high", resp.FailedResources[1].(resourcesresults.Result).ResourceID)
	assert.Equal(t, "res-med", resp.FailedResources[2].(resourcesresults.Result).ResourceID)
	assert.Equal(t, "res-low", resp.FailedResources[3].(resourcesresults.Result).ResourceID)
}

func TestBuildScanResponse_SeveritySortingTruncation(t *testing.T) {
	summary := &reportsummary.SummaryDetails{
		Controls: reportsummary.ControlSummaries{
			"C-CRIT": reportsummary.ControlSummary{ControlID: "C-CRIT", ScoreFactor: 9.0},
			"C-LOW":  reportsummary.ControlSummary{ControlID: "C-LOW", ScoreFactor: 1.0},
		},
	}

	makeFailingResource := func(id, controlID string) (string, resourcesresults.Result) {
		return id, resourcesresults.Result{
			ResourceID: id,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{
					ControlID: controlID,
					Status: apis.StatusInfo{
						InnerStatus: apis.StatusFailed,
					},
				},
			},
		}
	}

	results := make(map[string]resourcesresults.Result)
	// Low-resource keys sort lexically BEFORE critical-resource keys ("a-low-" < "z-crit-").
	// This enforces that severity ranking takes precedence over lexical ordering before truncation.
	for i := 0; i < 50; i++ {
		id, res := makeFailingResource(fmt.Sprintf("z-crit-%02d", i), "C-CRIT")
		results[id] = res
	}
	for i := 0; i < 70; i++ {
		id, res := makeFailingResource(fmt.Sprintf("a-low-%02d", i), "C-LOW")
		results[id] = res
	}

	resp := buildScanResponse(summary, results, nil, "test", false, 0, 2)
	assert.Equal(t, 120, resp.TotalFailed)
	assert.Equal(t, 100, resp.ReturnedFailed)
	assert.True(t, resp.Truncated)
	require.Len(t, resp.FailedResources, 100)

	// All 50 critical resources must be retained first, despite lexical disadvantage
	for i := 0; i < 50; i++ {
		assert.Equal(t, fmt.Sprintf("z-crit-%02d", i), resp.FailedResources[i].(resourcesresults.Result).ResourceID)
	}
	// The next 50 must be low resources
	for i := 50; i < 100; i++ {
		assert.Contains(t, resp.FailedResources[i].(resourcesresults.Result).ResourceID, "a-low-")
	}
}

func TestBuildScanInfo_Filters(t *testing.T) {
	req := scanRequest{
		namespace:          "prod",
		excludedNamespaces: "kube-system,kube-public",
		includeKinds:       "Deployment,DaemonSet",
		excludeKinds:       "Job",
		labelSelector:      "app=web",
		excludeControls:    []string{"C-0012", "C-0017"},
	}

	info := buildScanInfo(req)
	assert.Equal(t, "prod", info.IncludeNamespaces)
	assert.Equal(t, "kube-system,kube-public", info.ExcludedNamespaces)
	assert.Equal(t, "Deployment,DaemonSet", info.IncludeKinds)
	assert.Equal(t, "Job", info.ExcludeKinds)
	assert.Equal(t, "app=web", info.LabelSelector)
	assert.Equal(t, []string{"C-0012", "C-0017"}, info.ExcludeControls)
}
