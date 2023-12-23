package shared

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/stretchr/testify/assert"
)

// Validate a scanInfo struct with a valid fail threshold severity
func TestValidateImageScanInfo(t *testing.T) {
	testCases := []struct {
		Description string
		ScanInfo    *cautils.ScanInfo
		Want        error
	}{
		{
			"Empty scanInfo is valid",
			&cautils.ScanInfo{},
			nil,
		},
		{
			"Empty severity is valid",
			&cautils.ScanInfo{FailThresholdSeverity: ""},
			nil,
		},
		{
			"High severity is valid",
			&cautils.ScanInfo{FailThresholdSeverity: "High"},
			nil,
		},
		{
			"HIGH severity is valid",
			&cautils.ScanInfo{FailThresholdSeverity: "HIGH"},
			nil,
		},
		{
			"high severity is valid",
			&cautils.ScanInfo{FailThresholdSeverity: "high"},
			nil,
		},
		{
			"Unknown severity is invalid",
			&cautils.ScanInfo{FailThresholdSeverity: "unknown"},
			ErrUnknownSeverity,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.Description,
			func(t *testing.T) {
				var want error = tc.Want

				got := ValidateImageScanInfo(tc.ScanInfo)

				assert.Equal(t, want, got)
			},
		)
	}
}
