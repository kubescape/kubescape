package printer

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes"
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
			"name": "clusterrole1",
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

	resources := []WorkloadSummary{
		{resource: w1, status: apis.StatusFailed},
		{resource: w2, status: apis.StatusFailed},
		{resource: w3, status: apis.StatusFailed},
		{resource: r1, status: apis.StatusFailed},
	}

	result := groupByNamespaceOrKind(resources, workloadSummaryFailed)

	assert.Len(t, result, 4)
	assert.Contains(t, result, "Namespace default")
	assert.Contains(t, result, "Namespace kube-system")
	assert.Contains(t, result, "")
	assert.Contains(t, result, "Users")

	assert.Len(t, result["Namespace default"], 1)
	assert.Len(t, result["Namespace kube-system"], 1)
	assert.Len(t, result[""], 1)
	assert.Len(t, result["Users"], 1)
}
