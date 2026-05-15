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
		{
			"Submit with omit-raw-resources should be invalid",
			&cautils.ScanInfo{Submit: true, OmitRawResources: true},
			ErrOmitRawResourcesOrSubmit,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.Description,
			func(t *testing.T) {
				var want = tc.Want

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
	const validAccountID = "22019933-feac-4012-a8eb-e81461ba6655"

	testCases := []struct {
		Description string
		ScanInfo    *cautils.ScanInfo
		Want        error
	}{
		{
			"Empty severity should be valid for scan info",
			&cautils.ScanInfo{FailThresholdSeverity: "", AccountID: validAccountID},
			nil,
		},
		{
			"High severity should be valid for scan info",
			&cautils.ScanInfo{FailThresholdSeverity: "High", AccountID: validAccountID},
			nil,
		},
		{
			"Unknown severity should be invalid for scan info",
			&cautils.ScanInfo{FailThresholdSeverity: "Unknown", AccountID: validAccountID},
			shared.ErrUnknownSeverity,
		},
		{
			"Security view should be invalid for scan info",
			&cautils.ScanInfo{View: string(cautils.SecurityViewType), AccountID: validAccountID},
			nil,
		},
		{
			"Empty view should be valid for scan info",
			&cautils.ScanInfo{AccountID: validAccountID},
			nil,
		},
		{
			"Submit with keep-local should be invalid",
			&cautils.ScanInfo{Submit: true, Local: true, AccountID: validAccountID},
			ErrKeepLocalOrSubmit,
		},
		{
			"Submit with omit-raw-resources should be invalid",
			&cautils.ScanInfo{Submit: true, OmitRawResources: true, AccountID: validAccountID},
			ErrOmitRawResourcesOrSubmit,
		},
		{
			"Fail threshold above 100 should be invalid",
			&cautils.ScanInfo{FailThreshold: 101, AccountID: validAccountID},
			ErrBadThreshold,
		},
		{
			"Compliance threshold below 0 should be invalid",
			&cautils.ScanInfo{ComplianceThreshold: -1, AccountID: validAccountID},
			ErrBadThreshold,
		},
		{
			"Coverage threshold above 100 should be invalid",
			&cautils.ScanInfo{FailCoverageThreshold: 150, AccountID: validAccountID},
			ErrBadThreshold,
		},
		{
			"Invalid account ID should be rejected",
			&cautils.ScanInfo{AccountID: "not-a-uuid"},
			nil,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.Description,
			func(t *testing.T) {
				var want = tc.Want

				got := validateFrameworkScanInfo(tc.ScanInfo)

				if tc.Description == "Invalid account ID should be rejected" {
					if got == nil {
						t.Errorf("got: %v, want: error", got)
					}
					return
				}

				if got != want {
					t.Errorf("got: %v, want: %v", got, want)
				}
			},
		)
	}
}

func Test_validateFrameworkScanInfo_SecurityViewMutatesToResourceView(t *testing.T) {
	const validAccountID = "22019933-feac-4012-a8eb-e81461ba6655"

	scanInfo := &cautils.ScanInfo{
		View:      string(cautils.SecurityViewType),
		AccountID: validAccountID,
	}

	err := validateFrameworkScanInfo(scanInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scanInfo.View != string(cautils.ResourceViewType) {
		t.Fatalf("got view: %v, want: %v", scanInfo.View, string(cautils.ResourceViewType))
	}
}

func Test_validateCoverageThreshold(t *testing.T) {
	testCases := []struct {
		Description string
		ScanInfo    *cautils.ScanInfo
		Want        error
	}{
		{"0 disables the check and is valid", &cautils.ScanInfo{FailCoverageThreshold: 0}, nil},
		{"50 is a valid threshold", &cautils.ScanInfo{FailCoverageThreshold: 50}, nil},
		{"100 is a valid threshold", &cautils.ScanInfo{FailCoverageThreshold: 100}, nil},
		{"101 is out of range", &cautils.ScanInfo{FailCoverageThreshold: 101}, ErrBadThreshold},
		{"negative value is out of range", &cautils.ScanInfo{FailCoverageThreshold: -1}, ErrBadThreshold},
	}

	for _, tc := range testCases {
		t.Run(tc.Description, func(t *testing.T) {
			got := validateThresholdsOnly(tc.ScanInfo)
			if got != tc.Want {
				t.Errorf("got: %v, want: %v", got, tc.Want)
			}
		})
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
