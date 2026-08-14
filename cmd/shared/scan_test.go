package shared

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestValidateScanFormat(t *testing.T) {
	testCases := []struct {
		Description string
		Format      string
		Supported   []string
		WantErr     bool
	}{
		{"valid single format", "json", ScanFormats, false},
		{"valid default format", "pretty-printer", ScanFormats, false},
		{"valid comma-separated formats", "json,html,junit", ScanFormats, false},
		{"comma-separated with whitespace and empty entry", "json, ,html", ScanFormats, false},
		{"empty string is not an invalid format", "", ScanFormats, false},
		{"separator-only input is rejected", ",", ScanFormats, true},
		{"whitespace-and-separator-only input is rejected", " , ", ScanFormats, true},
		{"invalid format", "xml", ScanFormats, true},
		{"mixed valid and invalid formats", "json,xml", ScanFormats, true},
		{"valid image format", "sarif", ScanFormats, false},
		{"junit format is now supported for image scanning", "junit", ScanFormats, false},
		{"junit is supported for image scanning", "junit", ImageScanFormats, false},
		{"csv is not supported for image scanning", "csv", ImageScanFormats, true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Description, func(t *testing.T) {
			err := ValidateScanFormat(testCase.Format, testCase.Supported)
			if testCase.WantErr {
				if err == nil {
					t.Errorf("expected an error for format %q, got nil", testCase.Format)
				}
			} else if err != nil {
				t.Errorf("expected no error for format %q, got: %v", testCase.Format, err)
			}
		})
	}
}

func TestValidateSeverity(t *testing.T) {
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
			got := ValidateSeverity(input)

			if got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
	}
}

func TestValidateCommonScanFlags(t *testing.T) {
	tests := []struct {
		name          string
		severity      string
		minSeverity   string
		format        string
		formatChanged bool
		expectedErr   string
	}{
		{
			name:          "Valid setup",
			severity:      "High",
			minSeverity:   "Medium",
			format:        "json",
			formatChanged: true,
			expectedErr:   "",
		},
		{
			name:          "Invalid severity",
			severity:      "Extreme",
			format:        "json",
			formatChanged: true,
			expectedErr:   "unknown severity",
		},
		{
			name:          "Invalid minimum severity",
			severity:      "High",
			minSeverity:   "Extreme",
			format:        "json",
			formatChanged: true,
			expectedErr:   "unknown severity",
		},
		{
			name:          "Empty format flag explicitly passed",
			severity:      "High",
			format:        "",
			formatChanged: true,
			expectedErr:   "format cannot be empty, supported formats",
		},
		{
			name:          "Invalid format",
			severity:      "High",
			format:        "fake-format",
			formatChanged: true,
			expectedErr:   "invalid format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanInfo := &cautils.ScanInfo{
				FailThresholdSeverity: tt.severity,
				MinSeverity:           tt.minSeverity,
				Format:                tt.format,
			}

			cmd := &cobra.Command{}
			cmd.Flags().String("format", "", "")
			if tt.formatChanged {
				cmd.Flags().Set("format", tt.format)
			}

			err := ValidateCommonScanFlags(cmd, scanInfo, ScanFormats)

			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
}
