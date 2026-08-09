package shared

import (
	"testing"
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
