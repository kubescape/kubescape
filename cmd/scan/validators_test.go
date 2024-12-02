package scan

import (
	"testing"

	"github.com/kubescape/kubescape/v3/cmd/shared"
	"github.com/kubescape/kubescape/v3/core/cautils"
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
			shared.ErrUnknownSeverity,
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
			shared.ErrUnknownSeverity,
		},
		{
			"Security view should be invalid for scan info",
			&cautils.ScanInfo{View: string(cautils.SecurityViewType)},
			nil,
		},
		{
			"Empty view should be valid for scan info",
			&cautils.ScanInfo{},
			nil,
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

func Test_validateWorkloadIdentifier(t *testing.T) {
	testCases := []struct {
		Description string
		Input       string
		Want        error
	}{
		{"valid workload identifier should be valid", "deployment/test", nil},
		{"invalid workload identifier missing kind", "deployment", ErrInvalidWorkloadIdentifier},
		{"invalid workload identifier with namespace", "ns/deployment/name", ErrInvalidWorkloadIdentifier},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Description, func(t *testing.T) {
			input := testCase.Input
			want := testCase.Want
			got := validateWorkloadIdentifier(input)

			if got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
	}
}
