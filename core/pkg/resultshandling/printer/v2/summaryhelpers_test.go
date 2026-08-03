package printer

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling/apis"
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
