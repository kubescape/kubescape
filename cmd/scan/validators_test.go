package scan

import (
	"testing"

	"github.com/kubescape/kubescape/v2/core/cautils"
)

// Test_validateControlScanInfo tests how scan info is validated for the `scan control` command
func Test_validateControlScanInfo(t *testing.T) {
	testCases := []struct {
		Description string
		ScanInfo    *cautils.ScanInfo
		Want        error
	}{
		{
			"Empty severity should be valid for scan info",
			&cautils.ScanInfo{FailThresholdSeverity: ""},
			nil,
		},
		{
			"High severity should be valid for scan info",
			&cautils.ScanInfo{FailThresholdSeverity: "High"},
			nil,
		},
		{
			"Unknown severity should be invalid for scan info",
			&cautils.ScanInfo{FailThresholdSeverity: "Unknown"},
			ErrUnknownSeverity,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.Description,
			func(t *testing.T) {
				var want error = tc.Want

				got := validateControlScanInfo(tc.ScanInfo)

				if got != want {
					t.Errorf("got: %v, want: %v", got, want)
				}
			},
		)
	}
}

// Test_validateFrameworkScanInfo tests how scan info is validated for the `scan framework` command
func Test_validateFrameworkScanInfo(t *testing.T) {
	testCases := []struct {
		Description string
		ScanInfo    *cautils.ScanInfo
		Want        error
	}{
		{
			"Empty severity should be valid for scan info",
			&cautils.ScanInfo{FailThresholdSeverity: ""},
			nil,
		},
		{
			"High severity should be valid for scan info",
			&cautils.ScanInfo{FailThresholdSeverity: "High"},
			nil,
		},
		{
			"Unknown severity should be invalid for scan info",
			&cautils.ScanInfo{FailThresholdSeverity: "Unknown"},
			ErrUnknownSeverity,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.Description,
			func(t *testing.T) {
				var want error = tc.Want

				got := validateFrameworkScanInfo(tc.ScanInfo)

				if got != want {
					t.Errorf("got: %v, want: %v", got, want)
				}
			},
		)
	}
}

func Test_validateSeverity(t *testing.T) {
	testCases := []struct {
		Description string
		Input       string
		Want        error
	}{
		{"low should be a valid severity", "low", nil},
		{"Low should be a valid severity", "Low", nil},
		{"medium should be a valid severity", "medium", nil},
		{"Medium should be a valid severity", "Medium", nil},
		{"high should be a valid severity", "high", nil},
		{"Critical should be a valid severity", "Critical", nil},
		{"critical should be a valid severity", "critical", nil},
		{"Unknown should be an invalid severity", "Unknown", ErrUnknownSeverity},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Description, func(t *testing.T) {
			input := testCase.Input
			want := testCase.Want
			got := validateSeverity(input)

			if got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
	}
}
