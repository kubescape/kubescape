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

func TestVulnerabilityIsRCE(t *testing.T) {
	tests := []struct {
		name        string
		description string
		expected    bool
	}{
		{
			name:        "uppercase acronym",
			description: "a flaw allows an attacker to achieve RCE",
			expected:    true,
		},
		{
			name:        "lowercase acronym",
			description: "a flaw allows an attacker to achieve rce",
			expected:    true,
		},
		{
			name:        "mixed-case acronym",
			description: "a flaw allows an attacker to achieve Rce",
			expected:    true,
		},
		{
			name:        "acronym adjacent to punctuation",
			description: "this is an RCE-vulnerability affecting the product",
			expected:    true,
		},
		{
			name:        "expanded phrase is still detected",
			description: "allows arbitrary code execution in the context of the host",
			expected:    true,
		},
		{
			name:        "command injection phrase is still detected",
			description: "allows command injection via crafted arguments",
			expected:    true,
		},
		{
			name:        "source substring is not a false positive",
			description: "the source code of the affected component is available",
			expected:    false,
		},
		{
			name:        "resource substring is not a false positive",
			description: "an unauthenticated user may access the affected resource",
			expected:    false,
		},
		{
			name:        "force substring is not a false positive",
			description: "the update may force a restart of the service",
			expected:    false,
		},
		{
			name:        "commerce substring is not a false positive",
			description: "information disclosure in the commerce component",
			expected:    false,
		},
		{
			name:        "no RCE keywords",
			description: "a denial of service vulnerability exists in the parser",
			expected:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vul := Vulnerability{Description: test.description}
			assert.Equal(t, test.expected, vul.IsRCE())
		})
	}
}
