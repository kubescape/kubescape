package printer

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
)

func TestIsPrintSeparatorType(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
		scanType cautils.ScanTypes
	}{
		{
			name:     "cluster scan",
			scanType: cautils.ScanTypeCluster,
			expected: false,
		},
		{
			name:     "repo scan",
			scanType: cautils.ScanTypeRepo,
			expected: false,
		},
		{
			name:     "workload scan",
			scanType: cautils.ScanTypeWorkload,
			expected: false,
		},
		{
			name:     "control scan",
			scanType: cautils.ScanTypeControl,
			expected: true,
		},
		{
			name:     "framework scan",
			scanType: cautils.ScanTypeFramework,
			expected: true,
		},
		{
			name:     "image scan",
			scanType: cautils.ScanTypeImage,
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := isPrintSeparatorType(test.scanType)
			if got != test.expected {
				t.Errorf("%s failed - expected %t, got %t", test.name, test.expected, got)
			}
		})
	}
}
