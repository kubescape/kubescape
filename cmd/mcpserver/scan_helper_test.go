package mcpserver

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

func TestBuildScanResponse(t *testing.T) {
	tests := []struct {
		name          string
		numPassing    int
		numFailing    int
		wantTotal     int
		wantReturned  int
		wantTruncated bool
	}{
		{
			name:          "No resources",
			numPassing:    0,
			numFailing:    0,
			wantTotal:     0,
			wantReturned:  0,
			wantTruncated: false,
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
			name:          "Under cap (5 failing)",
			numPassing:    5,
			numFailing:    5,
			wantTotal:     5,
			wantReturned:  5,
			wantTruncated: false,
		},
		{
			name:          "Exactly at cap (100 failing)",
			numPassing:    10,
			numFailing:    100,
			wantTotal:     100,
			wantReturned:  100,
			wantTruncated: false,
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
			resp := buildScanResponse(results, nil)

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

			if tt.wantTruncated {
				var expectedKeys []string
				for k := range results {
					expectedKeys = append(expectedKeys, k)
				}
				sort.Strings(expectedKeys)

				var expectedFailedKeys []string
				for _, k := range expectedKeys {
					res := results[k]
					if res.GetStatus(nil).IsFailed() {
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
		})
	}
}
