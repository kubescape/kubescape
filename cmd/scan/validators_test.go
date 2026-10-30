package scan

import (
	"errors"
	"math"
	"testing"

	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			"Compliance threshold below 0 should be invalid",
			&cautils.ScanInfo{ComplianceThreshold: -1},
			ErrBadThreshold,
		},
		{
			"Coverage threshold above 100 should be invalid",
			&cautils.ScanInfo{FailCoverageThreshold: 150},
			ErrBadThreshold,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.Description,
			func(t *testing.T) {
				var want = tc.Want

				got := validateControlScanInfo(tc.ScanInfo)

				if !errors.Is(got, want) {
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
			"NaN compliance threshold should be invalid",
			&cautils.ScanInfo{ComplianceThreshold: float32(math.NaN()), AccountID: validAccountID},
			ErrBadThreshold,
		},
		{
			"NaN coverage threshold should be invalid",
			&cautils.ScanInfo{FailCoverageThreshold: float32(math.NaN()), AccountID: validAccountID},
			ErrBadThreshold,
		},
		{
			"Invalid account ID should be rejected",
			&cautils.ScanInfo{AccountID: "not-a-uuid"},
			nil,
		},
		{
			"Invalid view should be rejected",
			&cautils.ScanInfo{View: "invalid", AccountID: validAccountID},
			nil,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.Description,
			func(t *testing.T) {
				var want = tc.Want

				got := validateFrameworkScanInfo(tc.ScanInfo)

				if tc.Description == "Invalid account ID should be rejected" || tc.Description == "Invalid view should be rejected" {
					if got == nil {
						t.Errorf("got: %v, want: error", got)
					}
					return
				}

				if !errors.Is(got, want) {
					t.Errorf("got: %v, want: %v", got, want)
				}
			},
		)
	}
}

func Test_validateFrameworkScanInfo_Views(t *testing.T) {
	const validAccountID = "22019933-feac-4012-a8eb-e81461ba6655"

	tests := []struct {
		name     string
		view     string
		wantErr  bool
		wantView string
	}{
		{"control view retained", "control", false, "control"},
		{"resource view retained", "resource", false, "resource"},
		{"namespace view retained", "namespace", false, "namespace"},
		{"security view mutates to resource", "security", false, "resource"},
		{"Security uppercase mutates to resource", "Security", false, "resource"},
		{"Resource mixed-case normalized", "Resource", false, "resource"},
		{"invalid view rejected", "invalid", true, ""},
		{"controls typo rejected", "controls", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanInfo := &cautils.ScanInfo{
				View:      tt.view,
				AccountID: validAccountID,
			}
			err := validateFrameworkScanInfo(scanInfo)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantView, scanInfo.View)
			}
		})
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
		{"NaN is out of range", &cautils.ScanInfo{FailCoverageThreshold: float32(math.NaN())}, ErrBadThreshold},
	}

	for _, tc := range testCases {
		t.Run(tc.Description, func(t *testing.T) {
			got := validateThresholdsOnly(tc.ScanInfo)
			if !errors.Is(got, tc.Want) {
				t.Errorf("got: %v, want: %v", got, tc.Want)
			}
		})
	}
}

func Test_validateThresholdsOnly_Compliance(t *testing.T) {
	testCases := []struct {
		Description string
		ScanInfo    *cautils.ScanInfo
		Want        error
	}{
		{"Compliance threshold above 100 is out of range", &cautils.ScanInfo{ComplianceThreshold: 101}, ErrBadThreshold},
		{"Compliance threshold below 0 is out of range", &cautils.ScanInfo{ComplianceThreshold: -1}, ErrBadThreshold},
		{"Compliance threshold at 0 is valid", &cautils.ScanInfo{ComplianceThreshold: 0}, nil},
		{"Compliance threshold at 100 is valid", &cautils.ScanInfo{ComplianceThreshold: 100}, nil},
		{"NaN compliance threshold is out of range", &cautils.ScanInfo{ComplianceThreshold: float32(math.NaN())}, ErrBadThreshold},
	}

	for _, tc := range testCases {
		t.Run(tc.Description, func(t *testing.T) {
			got := validateThresholdsOnly(tc.ScanInfo)
			if !errors.Is(got, tc.Want) {
				t.Errorf("got: %v, want: %v", got, tc.Want)
			}
		})
	}
}

func Test_validatePostureThresholds_NamesOffendingFlag(t *testing.T) {
	testCases := []struct {
		Description string
		ScanInfo    *cautils.ScanInfo
		WantErr     string
	}{
		{"compliance threshold", &cautils.ScanInfo{ComplianceThreshold: 150}, "bad argument: out of range threshold: --compliance-threshold must be between 0 and 100, got 150"},
		{"coverage threshold", &cautils.ScanInfo{FailCoverageThreshold: 101}, "bad argument: out of range threshold: --fail-coverage-below must be between 0 and 100, got 101"},
	}

	for _, tc := range testCases {
		t.Run(tc.Description, func(t *testing.T) {
			for name, validate := range map[string]func(*cautils.ScanInfo) error{
				"framework":       validateFrameworkScanInfo,
				"control":         validateControlScanInfo,
				"thresholds only": validateThresholdsOnly,
			} {
				err := validate(tc.ScanInfo)
				require.ErrorIs(t, err, ErrBadThreshold, name)
				assert.EqualError(t, err, tc.WantErr, name)
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
		{"valid workload identifier with namespace", "ns/deployment/name", nil},
		{"invalid workload identifier with too many segments", "cluster/ns/deployment/name", ErrInvalidWorkloadIdentifier},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Description, func(t *testing.T) {
			input := testCase.Input
			want := testCase.Want
			got := validateWorkloadIdentifier(input)

			if !errors.Is(got, want) {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
	}
}
