package core

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetImageExceptionsFromFile(t *testing.T) {
	tests := []struct {
		filePath         string
		expectedPolicies []VulnerabilitiesIgnorePolicy
		expectedErr      error
	}{
		{
			filePath: "./testdata/exceptions.json",
			expectedPolicies: []VulnerabilitiesIgnorePolicy{
				{
					Metadata: Metadata{
						Name: "medium-severity-vulnerabilites-exceptions",
					},
					Kind: "VulnerabilitiesIgnorePolicy",
					Targets: []Target{
						{
							DesignatorType: "Attributes",
							Attributes: Attributes{
								Registry:     "docker.io",
								Organization: "",
								ImageName:    "",
								ImageTag:     "",
							},
						},
					},
					Vulnerabilities: []string{},
					Severities:      []string{"medium"},
				},
				{
					Metadata: Metadata{
						Name: "exclude-allowed-hostPath-control",
					},
					Kind: "VulnerabilitiesIgnorePolicy",
					Targets: []Target{
						{
							DesignatorType: "Attributes",
							Attributes: Attributes{
								Registry:     "",
								Organization: "",
								ImageName:    "",
								ImageTag:     "",
							},
						},
					},
					Vulnerabilities: []string{"CVE-2023-42366", "CVE-2023-42365"},
					Severities:      []string{"critical", "low"},
				},
				{
					Metadata: Metadata{
						Name: "regex-example",
					},
					Kind: "VulnerabilitiesIgnorePolicy",
					Targets: []Target{
						{
							DesignatorType: "Attributes",
							Attributes: Attributes{
								Registry:     "quay.*",
								Organization: "kube*",
								ImageName:    "kubescape*",
								ImageTag:     "v2*",
							},
						},
						{
							DesignatorType: "Attributes",
							Attributes: Attributes{
								Registry:     "docker.io",
								Organization: ".*",
								ImageName:    "kube*",
								ImageTag:     "v3*",
							},
						},
					},
					Vulnerabilities: []string{"CVE-2023-6879", "CVE-2023-44487"},
					Severities:      []string{"critical", "low"},
				},
			},
			expectedErr: nil,
		},
		{
			filePath:         "./testdata/empty_exceptions.json",
			expectedPolicies: []VulnerabilitiesIgnorePolicy{},
			expectedErr:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.filePath, func(t *testing.T) {
			policies, err := GetImageExceptionsFromFile(tt.filePath)
			assert.Equal(t, tt.expectedPolicies, policies)
			assert.Equal(t, tt.expectedErr, err)
		})
	}
}

func TestGetAttributesFromImage(t *testing.T) {
	tests := []struct {
		imageName          string
		expectedAttributes Attributes
		expectedErr        error
	}{
		{
			imageName: "quay.io/kubescape/kubescape-cli:v3.0.0",
			expectedAttributes: Attributes{
				Registry:     "quay.io",
				Organization: "kubescape",
				ImageName:    "kubescape-cli",
				ImageTag:     "v3.0.0",
			},
			expectedErr: nil,
		},
		{
			imageName: "alpine",
			expectedAttributes: Attributes{
				Registry:     "docker.io",
				Organization: "library",
				ImageName:    "alpine",
				ImageTag:     "latest",
			},
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.imageName, func(t *testing.T) {
			attributes, err := getAttributesFromImage(tt.imageName)
			assert.Equal(t, tt.expectedErr, err)
			assert.Equal(t, tt.expectedAttributes, attributes)
		})
	}
}

func TestRegexStringMatch(t *testing.T) {
	tests := []struct {
		pattern  string
		target   string
		expected bool
	}{
		{
			pattern:  ".*",
			target:   "quay.io",
			expected: true,
		},
		{
			pattern:  "kubescape",
			target:   "kubescape",
			expected: true,
		},
		{
			pattern:  "kubescape*",
			target:   "kubescape-cli",
			expected: true,
		},
		{
			pattern:  "",
			target:   "v3.0.0",
			expected: true,
		},
		{
			pattern:  "docker.io",
			target:   "quay.io",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.target+"/"+tt.pattern, func(t *testing.T) {
			assert.Equal(t, tt.expected, regexStringMatch(tt.pattern, tt.target))
		})
	}
}

func TestIsTargetImage(t *testing.T) {
	tests := []struct {
		targets    []Target
		attributes Attributes
		expected   bool
	}{
		{
			targets: []Target{
				{
					Attributes: Attributes{
						Registry:     "docker.io",
						Organization: ".*",
						ImageName:    ".*",
						ImageTag:     "",
					},
				},
			},
			attributes: Attributes{
				Registry:     "quay.io",
				Organization: "kubescape",
				ImageName:    "kubescape-cli",
				ImageTag:     "v3.0.0",
			},
			expected: false,
		},
		{
			targets: []Target{
				{
					Attributes: Attributes{
						Registry:     "quay.io",
						Organization: "kubescape",
						ImageName:    "kubescape*",
						ImageTag:     "",
					},
				},
			},
			attributes: Attributes{
				Registry:     "quay.io",
				Organization: "kubescape",
				ImageName:    "kubescape-cli",
				ImageTag:     "v3.0.0",
			},
			expected: true,
		},
		{
			targets: []Target{
				{
					Attributes: Attributes{
						Registry:     "docker.io",
						Organization: "library",
						ImageName:    "alpine",
						ImageTag:     "",
					},
				},
			},
			attributes: Attributes{
				Registry:     "docker.io",
				Organization: "library",
				ImageName:    "alpine",
				ImageTag:     "latest",
			},
			expected: true,
		},
		{
			targets: []Target{
				{
					Attributes: Attributes{
						Registry:     "quay.io",
						Organization: "kubescape",
						ImageName:    "kubescape*",
						ImageTag:     "",
					},
				},
				{
					Attributes: Attributes{
						Registry:     "docker.io",
						Organization: "library",
						ImageName:    "alpine",
						ImageTag:     "",
					},
				},
			},
			attributes: Attributes{
				Registry:     "docker.io",
				Organization: "library",
				ImageName:    "alpine",
				ImageTag:     "latest",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.attributes.Registry+"/"+tt.attributes.ImageName, func(t *testing.T) {
			assert.Equal(t, tt.expected, isTargetImage(tt.targets, tt.attributes))
		})
	}
}

func TestGetVulnerabilitiesAndSeverities(t *testing.T) {
	tests := []struct {
		policies                []VulnerabilitiesIgnorePolicy
		image                   string
		expectedVulnerabilities []string
		expectedSeverities      []string
	}{
		{
			policies: []VulnerabilitiesIgnorePolicy{
				{
					Metadata: Metadata{
						Name: "vulnerabilites-exceptions",
					},
					Kind: "VulnerabilitiesIgnorePolicy",
					Targets: []Target{
						{
							DesignatorType: "Attributes",
							Attributes: Attributes{
								Registry:     "",
								Organization: "kubescape*",
								ImageName:    "",
								ImageTag:     "",
							},
						},
					},
					Vulnerabilities: []string{"CVE-2023-42365"},
					Severities:      []string{},
				},
				{
					Metadata: Metadata{
						Name: "exclude-allowed-hostPath-control",
					},
					Kind: "VulnerabilitiesIgnorePolicy",
					Targets: []Target{
						{
							DesignatorType: "Attributes",
							Attributes: Attributes{
								Registry:     "docker.io",
								Organization: "",
								ImageName:    "",
								ImageTag:     "",
							},
						},
					},
					Vulnerabilities: []string{"CVE-2023-42366", "CVE-2023-42365"},
					Severities:      []string{"critical", "low"},
				},
			},
			image:                   "quay.io/kubescape/kubescape-cli:v3.0.0",
			expectedVulnerabilities: []string{"CVE-2023-42365"},
			expectedSeverities:      []string{},
		},
		{
			policies: []VulnerabilitiesIgnorePolicy{
				{
					Metadata: Metadata{
						Name: "medium-severity-vulnerabilites-exceptions",
					},
					Kind: "VulnerabilitiesIgnorePolicy",
					Targets: []Target{
						{
							DesignatorType: "Attributes",
							Attributes: Attributes{
								Registry:     "",
								Organization: "",
								ImageName:    "",
								ImageTag:     "",
							},
						},
					},
					Vulnerabilities: []string{},
					Severities:      []string{"medium"},
				},
				{
					Metadata: Metadata{
						Name: "exclude-allowed-hostPath-control",
					},
					Kind: "VulnerabilitiesIgnorePolicy",
					Targets: []Target{
						{
							DesignatorType: "Attributes",
							Attributes: Attributes{
								Registry:     "quay.io",
								Organization: "",
								ImageName:    "",
								ImageTag:     "",
							},
						},
					},
					Vulnerabilities: []string{"CVE-2023-42366", "CVE-2023-42365"},
					Severities:      []string{},
				},
			},
			image:                   "alpine",
			expectedVulnerabilities: []string{},
			expectedSeverities:      []string{"MEDIUM"},
		},
		{
			policies: []VulnerabilitiesIgnorePolicy{
				{
					Metadata: Metadata{
						Name: "regex-example",
					},
					Kind: "VulnerabilitiesIgnorePolicy",
					Targets: []Target{
						{
							DesignatorType: "Attributes",
							Attributes: Attributes{
								Registry:     "quay.io",
								Organization: "kube*",
								ImageName:    "kubescape*",
								ImageTag:     ".*",
							},
						},
					},
					Vulnerabilities: []string{},
					Severities:      []string{"critical"},
				},
				{
					Metadata: Metadata{
						Name: "only-for-docker-registry",
					},
					Kind: "VulnerabilitiesIgnorePolicy",
					Targets: []Target{
						{
							DesignatorType: "Attributes",
							Attributes: Attributes{
								Registry: "docker.io",
								ImageTag: "v3*",
							},
						},
					},
					Vulnerabilities: []string{"CVE-2023-42366", "CVE-2022-28391"},
					Severities:      []string{"high"},
				},
				{
					Metadata: Metadata{
						Name: "exclude-allowed-hostPath-control",
					},
					Kind: "VulnerabilitiesIgnorePolicy",
					Targets: []Target{
						{
							DesignatorType: "Attributes",
							Attributes: Attributes{
								ImageTag: "v3*",
							},
						},
					},
					Vulnerabilities: []string{"CVE-2022-30065", "CVE-2022-28391"},
					Severities:      []string{},
				},
			},
			image:                   "quay.io/kubescape/kubescape-cli:v3.0.0",
			expectedVulnerabilities: []string{"CVE-2022-30065", "CVE-2022-28391"},
			expectedSeverities:      []string{"CRITICAL"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			vulnerabilities, severities := getUniqueVulnerabilitiesAndSeverities(tt.policies, tt.image)
			sort.Strings(tt.expectedVulnerabilities)
			sort.Strings(vulnerabilities)
			assert.Equal(t, tt.expectedVulnerabilities, vulnerabilities)
			assert.Equal(t, tt.expectedSeverities, severities)
		})
	}
}
