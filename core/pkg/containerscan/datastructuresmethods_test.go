package containerscan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScanResultReportValidate(t *testing.T) {
	validLayers := LayersList{
		{
			LayerHash: "ddd",
			Vulnerabilities: VulnerabilitiesList{
				{Name: "CVE-2024-1234", Severity: HighSeverity},
			},
			Packages: LinuxPkgs{
				{PackageName: "coreutils", PackageVersion: "1.0.0"},
			},
		},
	}

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
				Layers:       validLayers,
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
				Layers:       validLayers,
			},
			expected: false,
		},
		{
			name: "report with empty ImgHash and non-empty ImgTag should return true",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "",
				ImgTag:       "bbb",
				Timestamp:    1,
				Layers:       validLayers,
			},
			expected: true,
		},
		{
			name: "report with non-empty ImgHash and empty ImgTag should return true",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "bbb",
				ImgTag:       "",
				Timestamp:    1,
				Layers:       validLayers,
			},
			expected: true,
		},
		{
			name: "report with non-empty ImgHash and non-empty ImgTag should return true",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "bbb",
				ImgTag:       "ccc",
				Timestamp:    1,
				Layers:       validLayers,
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
				Layers:       validLayers,
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
				Layers:       validLayers,
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
				Layers:       validLayers,
			},
			expected: true,
		},
		{
			name: "report with nil layers should return false",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "bbb",
				ImgTag:       "ccc",
				Timestamp:    1,
				Layers:       nil,
			},
			expected: false,
		},
		{
			name: "report with empty but non-nil layers should return true",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "bbb",
				ImgTag:       "ccc",
				Timestamp:    1,
				Layers:       LayersList{},
			},
			expected: true,
		},
		{
			name: "report with duplicate layer hashes should return false",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "bbb",
				ImgTag:       "ccc",
				Timestamp:    1,
				Layers: LayersList{
					{LayerHash: "duplicate-hash"},
					{LayerHash: "duplicate-hash"},
				},
			},
			expected: false,
		},
		{
			name: "report with vulnerability missing Name should return false",
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
			expected: false,
		},
		{
			name: "report with duplicate vulnerability should return false",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "bbb",
				ImgTag:       "ccc",
				Timestamp:    1,
				Layers: LayersList{
					{
						LayerHash: "ddd",
						Vulnerabilities: VulnerabilitiesList{
							{Name: "CVE-2024-1234", RelatedPackageName: "pkgA", PackageVersion: "1.0"},
							{Name: "CVE-2024-1234", RelatedPackageName: "pkgA", PackageVersion: "1.0"},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "same vulnerability and package with different versions should return true",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "bbb",
				ImgTag:       "ccc",
				Timestamp:    1,
				Layers: LayersList{
					{
						LayerHash: "ddd",
						Vulnerabilities: VulnerabilitiesList{
							{
								Name:               "CVE-2024-1234",
								RelatedPackageName: "pkgA",
								PackageVersion:     "1.0",
							},
							{
								Name:               "CVE-2024-1234",
								RelatedPackageName: "pkgA",
								PackageVersion:     "2.0",
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "same vulnerability and version in different packages should return true",
			in: ScanResultReport{
				CustomerGUID: "aaa",
				ImgHash:      "bbb",
				ImgTag:       "ccc",
				Timestamp:    1,
				Layers: LayersList{
					{
						LayerHash: "ddd",
						Vulnerabilities: VulnerabilitiesList{
							{
								Name:               "CVE-2024-1234",
								RelatedPackageName: "pkgA",
								PackageVersion:     "1.0",
							},
							{
								Name:               "CVE-2024-1234",
								RelatedPackageName: "pkgB",
								PackageVersion:     "1.0",
							},
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
				Layers:       validLayers,
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
