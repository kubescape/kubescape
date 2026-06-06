package shared

import (
	"math"
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
		{
			"Fail threshold above 100 should be invalid",
			&cautils.ScanInfo{FailThreshold: 101},
			ErrBadThreshold,
		},
		{
			"Fail threshold below 0 should be invalid",
			&cautils.ScanInfo{FailThreshold: -1},
			ErrBadThreshold,
		},
		{
			"Compliance threshold above 100 should be invalid",
			&cautils.ScanInfo{ComplianceThreshold: 101},
			ErrBadThreshold,
		},
		{
			"Compliance threshold below 0 should be invalid",
			&cautils.ScanInfo{ComplianceThreshold: -1},
			ErrBadThreshold,
		},
		{
			"Coverage threshold above 100 should be invalid",
			&cautils.ScanInfo{FailCoverageThreshold: 150},
			ErrBadThreshold,
		},
		{
			"Valid thresholds should be accepted",
			&cautils.ScanInfo{FailThreshold: 80, ComplianceThreshold: 70},
			nil,
		},
		{
			"NaN fail threshold should be invalid",
			&cautils.ScanInfo{FailThreshold: float32(math.NaN())},
			ErrBadThreshold,
		},
		{
			"NaN compliance threshold should be invalid",
			&cautils.ScanInfo{ComplianceThreshold: float32(math.NaN())},
			ErrBadThreshold,
		},
		{
			"NaN fail coverage threshold should be invalid",
			&cautils.ScanInfo{FailCoverageThreshold: float32(math.NaN())},
			ErrBadThreshold,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.Description,
			func(t *testing.T) {
				var want = tc.Want

				got := ValidateImageScanInfo(tc.ScanInfo)

				assert.Equal(t, want, got)
			},
		)
	}
}
