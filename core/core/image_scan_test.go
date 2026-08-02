package core

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"syscall"
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
		{
			// registry image with no organization path (previously panicked)
			imageName: "myregistry.io/myimage:v1",
			expectedAttributes: Attributes{
				Registry:     "myregistry.io",
				Organization: "",
				ImageName:    "myimage",
				ImageTag:     "v1",
			},
			expectedErr: nil,
		},
		{
			// registry with a port, no organization, default tag
			imageName: "localhost:5000/myimage",
			expectedAttributes: Attributes{
				Registry:     "localhost:5000",
				Organization: "",
				ImageName:    "myimage",
				ImageTag:     "latest",
			},
			expectedErr: nil,
		},
		{
			// multi-segment organization path
			imageName: "gcr.io/team/sub/myimage:v2",
			expectedAttributes: Attributes{
				Registry:     "gcr.io",
				Organization: "team/sub",
				ImageName:    "myimage",
				ImageTag:     "v2",
			},
			expectedErr: nil,
		},
		{
			// Regression: a digest-pinned reference's digest ("sha256:...")
			// contains a colon. Splitting the name:tag segment on ":" without
			// accounting for the digest used to leave "@sha256" stuck onto
			// ImageName and the raw hash treated as ImageTag, which silently
			// broke isTargetImage's exception-policy matching for these images.
			imageName: "myregistry.io/myimage@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			expectedAttributes: Attributes{
				Registry:     "myregistry.io",
				Organization: "",
				ImageName:    "myimage",
				ImageTag:     "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			},
			expectedErr: nil,
		},
		{
			// Both an explicit tag and a digest: the explicit tag must win
			// over the digest for ImageTag, and ImageName must still exclude
			// both suffixes.
			imageName: "myregistry.io/myimage:v1@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			expectedAttributes: Attributes{
				Registry:     "myregistry.io",
				Organization: "",
				ImageName:    "myimage",
				ImageTag:     "v1",
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
			expectedVulnerabilities: []string{"CVE-2023-42365", "cve-2023-42365"},
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
			expectedVulnerabilities: []string{"CVE-2022-28391", "CVE-2022-30065", "cve-2022-28391", "cve-2022-30065"},
			expectedSeverities:      []string{"CRITICAL"},
		},
		{
			// A lowercase-suffix GHSA ID on its own must reach grype in
			// original, uppercase, and lowercase form, because grype's
			// IgnoreRule matching is case-sensitive and the advisory is
			// reported with a mixed casing (see issue #1870).
			policies: []VulnerabilitiesIgnorePolicy{
				{
					Metadata: Metadata{
						Name: "ghsa-lowercase-only",
					},
					Kind: "VulnerabilitiesIgnorePolicy",
					Targets: []Target{
						{
							DesignatorType: "Attributes",
							Attributes: Attributes{
								Registry: "quay.io",
							},
						},
					},
					Vulnerabilities: []string{"GHSA-jc7w-c686-c4v9"},
					Severities:      []string{},
				},
			},
			image:                   "quay.io/kubescape/kubescape-cli:v3.0.0",
			expectedVulnerabilities: []string{"GHSA-JC7W-C686-C4V9", "GHSA-jc7w-c686-c4v9", "ghsa-jc7w-c686-c4v9"},
			expectedSeverities:      []string{},
		},
		{
			// When users list the same GHSA ID in both cases, each variant
			// is preserved so the filter still works regardless of how the
			// advisory is reported.
			policies: []VulnerabilitiesIgnorePolicy{
				{
					Metadata: Metadata{
						Name: "ghsa-mixed-and-upper",
					},
					Kind: "VulnerabilitiesIgnorePolicy",
					Targets: []Target{
						{
							DesignatorType: "Attributes",
							Attributes: Attributes{
								Registry: "quay.io",
							},
						},
					},
					Vulnerabilities: []string{"GHSA-jc7w-c686-c4v9", "GHSA-JC7W-C686-C4V9"},
					Severities:      []string{},
				},
			},
			image:                   "quay.io/kubescape/kubescape-cli:v3.0.0",
			expectedVulnerabilities: []string{"GHSA-JC7W-C686-C4V9", "GHSA-jc7w-c686-c4v9", "ghsa-jc7w-c686-c4v9"},
			expectedSeverities:      []string{},
		},
		{
			// Empty or whitespace-only entries are skipped so they cannot
			// produce an empty IgnoreRule that grype would treat as a
			// match-everything wildcard, and surrounding whitespace from a
			// hand-edited exceptions file is tolerated.
			policies: []VulnerabilitiesIgnorePolicy{
				{
					Metadata: Metadata{
						Name: "edge-empty-whitespace",
					},
					Kind: "VulnerabilitiesIgnorePolicy",
					Targets: []Target{
						{
							DesignatorType: "Attributes",
							Attributes: Attributes{
								Registry: "quay.io",
							},
						},
					},
					Vulnerabilities: []string{"", "   ", "  CVE-2024-1234  "},
					Severities:      []string{},
				},
			},
			image:                   "quay.io/kubescape/kubescape-cli:v3.0.0",
			expectedVulnerabilities: []string{"CVE-2024-1234", "cve-2024-1234"},
			expectedSeverities:      []string{},
		},
		{
			// An all-lowercase CVE ID must produce exactly two forms (original
			// + uppercase), not three — the lowercase variant equals the
			// original so it must not be re-added as a duplicate key.
			policies: []VulnerabilitiesIgnorePolicy{
				{
					Metadata: Metadata{
						Name: "lowercase-cve",
					},
					Kind: "VulnerabilitiesIgnorePolicy",
					Targets: []Target{
						{
							DesignatorType: "Attributes",
							Attributes: Attributes{
								Registry: "quay.io",
							},
						},
					},
					Vulnerabilities: []string{"cve-2023-1234"},
					Severities:      []string{},
				},
			},
			image:                   "quay.io/kubescape/kubescape-cli:v3.0.0",
			expectedVulnerabilities: []string{"CVE-2023-1234", "cve-2023-1234"},
			expectedSeverities:      []string{},
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

func TestApplyRegistryMapping(t *testing.T) {
	tests := []struct {
		name            string
		image           string
		registryMapping map[string]string
		expected        string
		expectMatched   bool
		expectErr       bool
	}{
		{
			name:            "OpenShift internal to external",
			image:           "image-registry.openshift-image-registry.svc:5000/namespace/image:tag",
			registryMapping: map[string]string{"image-registry.openshift-image-registry.svc:5000": "registry.company.com"},
			expected:        "registry.company.com/namespace/image:tag",
			expectMatched:   true,
		},
		{
			name:            "Docker Hub short to alternative",
			image:           "nginx",
			registryMapping: map[string]string{"docker.io": "my.registry.local:8080"},
			expected:        "my.registry.local:8080/library/nginx",
			expectMatched:   true,
		},
		{
			name:            "Quay to alternative",
			image:           "quay.io/kubescape/kubescape:latest",
			registryMapping: map[string]string{"quay.io": "internal.quay.mirror"},
			expected:        "internal.quay.mirror/kubescape/kubescape:latest",
			expectMatched:   true,
		},
		{
			name:            "No mapping matched — fully qualified",
			image:           "quay.io/kubescape/kubescape:latest",
			registryMapping: map[string]string{"docker.io": "internal.quay.mirror"},
			expected:        "quay.io/kubescape/kubescape:latest",
			expectMatched:   false,
		},
		{
			name:            "No mapping matched — short name returns original",
			image:           "nginx",
			registryMapping: map[string]string{"quay.io": "mirror.local"},
			expected:        "nginx",
			expectMatched:   false,
		},
		{
			name:            "Empty mapping returns original",
			image:           "nginx",
			registryMapping: map[string]string{},
			expected:        "nginx",
			expectMatched:   false,
		},
		{
			name:            "Invalid fallback registry with scheme",
			image:           "image-registry.openshift-image-registry.svc:5000/namespace/image:tag",
			registryMapping: map[string]string{"image-registry.openshift-image-registry.svc:5000": "https://registry.company.com"},
			expectErr:       true,
		},
		{
			name:            "Invalid fallback registry with trailing slash",
			image:           "image-registry.openshift-image-registry.svc:5000/namespace/image:tag",
			registryMapping: map[string]string{"image-registry.openshift-image-registry.svc:5000": "registry.company.com/"},
			expectErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, matched, err := applyRegistryMapping(tt.image, tt.registryMapping)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
				assert.Equal(t, tt.expectMatched, matched)
			}
		})
	}
}

func TestIsResolutionError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "DNS error (typed)",
			err:      fmt.Errorf("get descriptor: %w", &net.DNSError{Err: "no such host", Name: "registry.svc", IsNotFound: true}),
			expected: true,
		},
		{
			name:     "connection refused (typed)",
			err:      fmt.Errorf("dial tcp 10.0.0.1:5000: %w", syscall.ECONNREFUSED),
			expected: true,
		},
		{
			name:     "host unreachable (typed)",
			err:      fmt.Errorf("dial tcp: %w", syscall.EHOSTUNREACH),
			expected: true,
		},
		{
			name:     "timeout (net.Error interface)",
			err:      fmt.Errorf("connect: %w", &net.DNSError{Err: "i/o timeout", IsTimeout: true}),
			expected: true,
		},
		{
			name:     "string fallback — no such host",
			err:      errors.New("Get https://registry.svc:5000/v2/: dial tcp: lookup registry.svc: no such host"),
			expected: true,
		},
		{
			name:     "string fallback — connection refused",
			err:      errors.New("Get https://registry.svc:5000/v2/: dial tcp 10.0.0.1:5000: connect: connection refused"),
			expected: true,
		},
		{
			name:     "string fallback — i/o timeout",
			err:      errors.New("Get https://registry.svc:5000/v2/: dial tcp 10.0.0.1:5000: i/o timeout"),
			expected: true,
		},
		{
			name:     "auth failure — should NOT match",
			err:      errors.New("UNAUTHORIZED: authentication required"),
			expected: false,
		},
		{
			name:     "manifest not found — should NOT match",
			err:      errors.New("name unknown: manifest unknown"),
			expected: false,
		},
		{
			name:     "bad certificate — should NOT match",
			err:      errors.New("x509: certificate signed by unknown authority"),
			expected: false,
		},
		{
			name:     "rate limited — should NOT match",
			err:      errors.New("TOOMANYREQUESTS: retry later"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isResolutionError(tt.err))
		})
	}
}
