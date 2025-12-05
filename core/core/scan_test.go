package core

import (
	"context"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/stretchr/testify/assert"
)

func TestGetOutputPrinters(t *testing.T) {
	ctx := context.Background()
	scanInfo := &cautils.ScanInfo{
		ScanType: "control",
		Format:   "json,junit,html",
	}

	outputPrinters := GetOutputPrinters(scanInfo, ctx, "test-cluster")

	assert.NotNil(t, outputPrinters)
	assert.Equal(t, 3, len(outputPrinters))
}

func TestIsPrioritizationScanType(t *testing.T) {
	tests := []struct {
		name cautils.ScanTypes
		want bool
	}{
		{
			name: cautils.ScanTypeCluster,
			want: true,
		},
		{
			name: cautils.ScanTypeRepo,
			want: true,
		},
		{
			name: cautils.ScanTypeImage,
			want: false,
		},
		{
			name: cautils.ScanTypeWorkload,
			want: false,
		},
		{
			name: cautils.ScanTypeFramework,
			want: false,
		},
		{
			name: cautils.ScanTypeControl,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.name), func(t *testing.T) {
			assert.Equal(t, tt.want, isPrioritizationScanType(tt.name))
		})
	}
}

func TestIsAirGappedMode(t *testing.T) {
	tests := []struct {
		name     string
		scanInfo *cautils.ScanInfo
		want     bool
	}{
		{
			name: "air-gapped with Local flag",
			scanInfo: &cautils.ScanInfo{
				Local: true,
			},
			want: true,
		},
		{
			name: "air-gapped with UseFrom",
			scanInfo: &cautils.ScanInfo{
				UseFrom: []string{"/path/to/policy"},
			},
			want: true,
		},
		{
			name: "air-gapped with ControlsInputs",
			scanInfo: &cautils.ScanInfo{
				ControlsInputs: "/path/to/controls",
			},
			want: true,
		},
		{
			name: "air-gapped with UseExceptions",
			scanInfo: &cautils.ScanInfo{
				UseExceptions: "/path/to/exceptions",
			},
			want: true,
		},
		{
			name: "air-gapped with AttackTracks",
			scanInfo: &cautils.ScanInfo{
				AttackTracks: "/path/to/attack-tracks",
			},
			want: true,
		},
		{
			name:     "not air-gapped - all empty",
			scanInfo: &cautils.ScanInfo{},
			want:     false,
		},
		{
			name: "air-gapped with multiple flags",
			scanInfo: &cautils.ScanInfo{
				Local:   true,
				UseFrom: []string{"/path/to/policy"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isAirGappedMode(tt.scanInfo))
		})
	}
}
