package printer

import (
	"testing"

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
