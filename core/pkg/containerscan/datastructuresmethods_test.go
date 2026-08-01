package containerscan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScanResultReportValidate(t *testing.T) {
	tests := []struct {
		name     string
		in       ScanResultReport
		expected bool
	}{
		{
			name:     "empty report should return false",
			in:       ScanResultReport{},
			expected: false,
		},
		{
			name: "report with empty CustomerGUID should return false",
			in: ScanResultReport{
				CustomerGUID: "",
				ImgHash:      "aaa",
				ImgTag:       "bbb",
				Timestamp:    1,
			},
			expected: false,
		},
		{
			name: "report with empty ImgHash and ImgTag should return false",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "",
				ImgTag:       "",
				Timestamp:    1,
			},
			expected: false,
		},
		{
			name: "report with empty ImageHash and non-empty ImgTag should return true",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "",
				ImgTag:       "bbb",
				Timestamp:    1,
			},
			expected: true,
		},
		{
			name: "report with non-empty ImageHash and empty ImgTag should return true",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "bbb",
				ImgTag:       "",
				Timestamp:    1,
			},
			expected: true,
		},
		{
			name: "report with non-empty ImageHash and non-empty ImgTag should return true",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "bbb",
				ImgTag:       "ccc",
				Timestamp:    1,
			},
			expected: true,
		},
		{
			name: "report with Timestamp <= 0 should return false",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "bbb",
				ImgTag:       "ccc",
				Timestamp:    0,
			},
			expected: false,
		},
		{
			name: "report with negative Timestamp should return false",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "bbb",
				ImgTag:       "ccc",
				Timestamp:    -1,
			},
			expected: false,
		},
		{
			name: "report with whitespace-only CustomerGUID should return true",
			in: ScanResultReport{
				CustomerGUID: "   ",
				ImgHash:      "bbb",
				ImgTag:       "ccc",
				Timestamp:    1,
			},
			expected: true,
		},
		{
			name: "report with layer missing LayerHash should return true (layers not validated yet)",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "bbb",
				ImgTag:       "ccc",
				Timestamp:    1,
				Layers: LayersList{
					{LayerHash: ""},
				},
			},
			expected: true,
		},
		{
			name: "report with vulnerability missing Name and Severity should return true (vulnerabilities not validated yet)",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "bbb",
				ImgTag:       "ccc",
				Timestamp:    1,
				Layers: LayersList{
					{
						LayerHash: "ddd",
						Vulnerabilities: VulnerabilitiesList{
							{Name: "", Severity: ""},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "fully populated report should return true",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "bbb",
				ImgTag:       "ccc",
				Timestamp:    1,
				Layers: LayersList{
					{
						LayerHash: "ddd",
						Vulnerabilities: VulnerabilitiesList{
							{Name: "CVE-2024-1234", Severity: HighSeverity},
						},
						Packages: LinuxPkgs{
							{PackageName: "coreutils", PackageVersion: "1.0.0"},
						},
					},
				},
			},
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := test.in.Validate()
			assert.Equal(t, test.expected, res)
		})
	}
}
