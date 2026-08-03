package cautils

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsScanningScopeMatchToControlScope(t *testing.T) {
	tests := []struct {
		scanScope    reporthandling.ScanningScopeType
		controlScope reporthandling.ScanningScopeType
		expected     bool
	}{
		{
			scanScope:    reporthandling.ScopeFile,
			controlScope: reporthandling.ScopeFile,
			expected:     true,
		},
		{
			scanScope:    ScopeCluster,
			controlScope: ScopeCluster,
			expected:     true,
		},
		{
			scanScope:    reporthandling.ScopeCloud,
			controlScope: reporthandling.ScopeCloud,
			expected:     true,
		},
		{
			scanScope:    reporthandling.ScopeCloudAKS,
			controlScope: reporthandling.ScopeCloudAKS,
			expected:     true,
		},
		{
			scanScope:    reporthandling.ScopeCloudEKS,
			controlScope: reporthandling.ScopeCloudEKS,
			expected:     true,
		},
		{
			scanScope:    reporthandling.ScopeCloudGKE,
			controlScope: reporthandling.ScopeCloudGKE,
			expected:     true,
		},
		{
			scanScope:    ScopeCluster,
			controlScope: reporthandling.ScopeCloud,
			expected:     false,
		},
		{
			scanScope:    reporthandling.ScopeCloud,
			controlScope: ScopeCluster,
			expected:     true,
		},
		{
			scanScope:    reporthandling.ScopeCloudAKS,
			controlScope: ScopeCluster,
			expected:     true,
		},
		{
			scanScope:    reporthandling.ScopeCloudEKS,
			controlScope: ScopeCluster,
			expected:     true,
		},
		{
			scanScope:    reporthandling.ScopeCloudGKE,
			controlScope: ScopeCluster,
			expected:     true,
		},
		{
			scanScope:    reporthandling.ScopeCloud,
			controlScope: reporthandling.ScopeCloudAKS,
			expected:     false,
		},
		{
			scanScope:    reporthandling.ScopeCloudAKS,
			controlScope: reporthandling.ScopeCloud,
			expected:     true,
		},
		{
			scanScope:    reporthandling.ScopeCloudEKS,
			controlScope: reporthandling.ScopeCloud,
			expected:     true,
		},
		{
			scanScope:    reporthandling.ScopeCloudGKE,
			controlScope: reporthandling.ScopeCloud,
			expected:     true,
		},
		{
			scanScope:    ScopeCluster,
			controlScope: reporthandling.ScopeCloudAKS,
			expected:     false,
		},
		{
			scanScope:    ScopeCluster,
			controlScope: reporthandling.ScopeCloudEKS,
			expected:     false,
		},
		{
			scanScope:    ScopeCluster,
			controlScope: reporthandling.ScopeCloudGKE,
			expected:     false,
		},
		{
			scanScope:    reporthandling.ScopeFile,
			controlScope: ScopeCluster,
			expected:     false,
		},
		{
			scanScope:    reporthandling.ScopeFile,
			controlScope: reporthandling.ScopeCloud,
			expected:     false,
		},
		{
			scanScope:    reporthandling.ScopeFile,
			controlScope: reporthandling.ScopeCloudAKS,
			expected:     false,
		},
		{
			scanScope:    reporthandling.ScopeFile,
			controlScope: reporthandling.ScopeCloudEKS,
			expected:     false,
		},
		{
			scanScope:    reporthandling.ScopeFile,
			controlScope: reporthandling.ScopeCloudGKE,
			expected:     false,
		},
		{
			scanScope:    reporthandling.ScopeCloud,
			controlScope: reporthandling.ScopeCloudEKS,
			expected:     false,
		},
		{
			scanScope:    reporthandling.ScopeCloud,
			controlScope: reporthandling.ScopeCloudGKE,
			expected:     false,
		},
		{
			scanScope:    reporthandling.ScopeCloudAKS,
			controlScope: reporthandling.ScopeCloudEKS,
			expected:     false,
		},
		{
			scanScope:    reporthandling.ScopeCloudAKS,
			controlScope: reporthandling.ScopeCloudGKE,
			expected:     false,
		},
		{
			scanScope:    reporthandling.ScopeCloudEKS,
			controlScope: reporthandling.ScopeCloudAKS,
			expected:     false,
		},
		{
			scanScope:    reporthandling.ScopeCloudEKS,
			controlScope: reporthandling.ScopeCloudGKE,
			expected:     false,
		},
		{
			scanScope:    reporthandling.ScopeCloudGKE,
			controlScope: reporthandling.ScopeCloudAKS,
			expected:     false,
		},
		{
			scanScope:    reporthandling.ScopeCloudGKE,
			controlScope: reporthandling.ScopeCloudEKS,
			expected:     false,
		},
	}

	for _, test := range tests {
		result := isScanningScopeMatchToControlScope(test.scanScope, test.controlScope)
		assert.Equal(t, test.expected, result, fmt.Sprintf("scanScope: %v, controlScope: %v", test.scanScope, test.controlScope))
	}
}

func TestIsFrameworkFitToScanScope(t *testing.T) {
	tests := []struct {
		name           string
		framework      reporthandling.Framework
		scanScopeMatch reporthandling.ScanningScopeType
		want           bool
	}{
		{
			name: "Framework with nil ScanningScope should return true",
			framework: reporthandling.Framework{
				PortalBase: armotypes.PortalBase{
					Name: "test-framework",
				},
			},
			scanScopeMatch: reporthandling.ScopeFile,
			want:           true,
		},
		{
			name: "Framework with empty ScanningScope.Matches should return true",
			framework: reporthandling.Framework{
				PortalBase: armotypes.PortalBase{
					Name: "test-framework",
				}, ScanningScope: &reporthandling.ScanningScope{},
			},
			scanScopeMatch: reporthandling.ScopeFile,
			want:           true,
		},
		{
			name: "Framework with matching ScanningScope.Matches should return true",
			framework: reporthandling.Framework{
				PortalBase: armotypes.PortalBase{
					Name: "test-framework",
				}, ScanningScope: &reporthandling.ScanningScope{
					Matches: []reporthandling.ScanningScopeType{reporthandling.ScopeFile},
				},
			},
			scanScopeMatch: reporthandling.ScopeFile,
			want:           true,
		},
		{
			name: "Framework with non-matching ScanningScope.Matches should return false",
			framework: reporthandling.Framework{
				PortalBase: armotypes.PortalBase{
					Name: "test-framework",
				}, ScanningScope: &reporthandling.ScanningScope{
					Matches: []reporthandling.ScanningScopeType{reporthandling.ScopeCluster},
				},
			},
			scanScopeMatch: reporthandling.ScopeFile,
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isFrameworkFitToScanScope(tt.framework, tt.scanScopeMatch); got != tt.want {
				t.Errorf("isFrameworkFitToScanScope() = %v, want %v", got, tt.want)
			}
		})
	}
}

var rule_v1_0_131 = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]any{"useUntilKubescapeVersion": "v1.0.132"}}}
var rule_v1_0_132 = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]any{"useFromKubescapeVersion": "v1.0.132", "useUntilKubescapeVersion": "v1.0.133"}}}
var rule_v1_0_133 = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]any{"useFromKubescapeVersion": "v1.0.133", "useUntilKubescapeVersion": "v1.0.134"}}}
var rule_v1_0_134 = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]any{"useFromKubescapeVersion": "v1.0.134"}}}
var rule_invalid_from = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]any{"useFromKubescapeVersion": 1.0135, "useUntilKubescapeVersion": "v1.0.135"}}}
var rule_invalid_until = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]any{"useFromKubescapeVersion": "v1.0.135", "useUntilKubescapeVersion": 1.0135}}}

func TestIsRuleKubescapeVersionCompatible(t *testing.T) {
	// local build- no build number

	// should not crash when the value of useUntilKubescapeVersion is not a string
	buildNumberMock := "v1.0.135"
	assert.False(t, isRuleKubescapeVersionCompatible("test-rule", rule_invalid_from.Attributes, buildNumberMock, make(map[string]struct{})))
	assert.False(t, isRuleKubescapeVersionCompatible("test-rule", rule_invalid_until.Attributes, buildNumberMock, make(map[string]struct{})))
	// should use only rules that don't have "until"
	buildNumberMock = ""
	assert.False(t, isRuleKubescapeVersionCompatible("test-rule", rule_v1_0_131.Attributes, buildNumberMock, make(map[string]struct{})))
	assert.False(t, isRuleKubescapeVersionCompatible("test-rule", rule_v1_0_132.Attributes, buildNumberMock, make(map[string]struct{})))
	assert.False(t, isRuleKubescapeVersionCompatible("test-rule", rule_v1_0_133.Attributes, buildNumberMock, make(map[string]struct{})))
	assert.True(t, isRuleKubescapeVersionCompatible("test-rule", rule_v1_0_134.Attributes, buildNumberMock, make(map[string]struct{})))

	// should only use rules that version is in range of use
	buildNumberMock = "v1.0.130"
	assert.True(t, isRuleKubescapeVersionCompatible("test-rule", rule_v1_0_131.Attributes, buildNumberMock, make(map[string]struct{})))
	assert.False(t, isRuleKubescapeVersionCompatible("test-rule", rule_v1_0_132.Attributes, buildNumberMock, make(map[string]struct{})))
	assert.False(t, isRuleKubescapeVersionCompatible("test-rule", rule_v1_0_133.Attributes, buildNumberMock, make(map[string]struct{})))
	assert.False(t, isRuleKubescapeVersionCompatible("test-rule", rule_v1_0_134.Attributes, buildNumberMock, make(map[string]struct{})))

	// should only use rules that version is in range of use
	buildNumberMock = "v1.0.132"
	assert.False(t, isRuleKubescapeVersionCompatible("test-rule", rule_v1_0_131.Attributes, buildNumberMock, make(map[string]struct{})))
	assert.True(t, isRuleKubescapeVersionCompatible("test-rule", rule_v1_0_132.Attributes, buildNumberMock, make(map[string]struct{})))
	assert.False(t, isRuleKubescapeVersionCompatible("test-rule", rule_v1_0_133.Attributes, buildNumberMock, make(map[string]struct{})))
	assert.False(t, isRuleKubescapeVersionCompatible("test-rule", rule_v1_0_134.Attributes, buildNumberMock, make(map[string]struct{})))

	// should only use rules that version is in range of use
	buildNumberMock = "v1.0.133"
	assert.False(t, isRuleKubescapeVersionCompatible("test-rule", rule_v1_0_131.Attributes, buildNumberMock, make(map[string]struct{})))
	assert.False(t, isRuleKubescapeVersionCompatible("test-rule", rule_v1_0_132.Attributes, buildNumberMock, make(map[string]struct{})))
	assert.True(t, isRuleKubescapeVersionCompatible("test-rule", rule_v1_0_133.Attributes, buildNumberMock, make(map[string]struct{})))
	assert.False(t, isRuleKubescapeVersionCompatible("test-rule", rule_v1_0_134.Attributes, buildNumberMock, make(map[string]struct{})))

	// should only use rules that version is in range of use
	buildNumberMock = "v1.0.135"
	assert.False(t, isRuleKubescapeVersionCompatible("test-rule", rule_v1_0_131.Attributes, buildNumberMock, make(map[string]struct{})))
	assert.False(t, isRuleKubescapeVersionCompatible("test-rule", rule_v1_0_132.Attributes, buildNumberMock, make(map[string]struct{})))
	assert.False(t, isRuleKubescapeVersionCompatible("test-rule", rule_v1_0_133.Attributes, buildNumberMock, make(map[string]struct{})))
	assert.True(t, isRuleKubescapeVersionCompatible("test-rule", rule_v1_0_134.Attributes, buildNumberMock, make(map[string]struct{})))
}

// TestPoliciesSetDoesNotMutateCallerFrameworks guards against a regression where Set
// filtered a control's rules into a new slice but wrote it back through the caller's
// slice header, permanently deleting excluded rules from the caller's data (e.g.
// PolicyHandler's cached frameworks, reused across scans while POLICIES_CACHE_TTL is set).
func TestPoliciesSetDoesNotMutateCallerFrameworks(t *testing.T) {
	buildFrameworks := func() []reporthandling.Framework {
		return []reporthandling.Framework{
			{
				PortalBase: armotypes.PortalBase{Name: "test-framework"},
				Controls: []reporthandling.Control{
					{
						ControlID: "control-1",
						Rules: []reporthandling.PolicyRule{
							{PortalBase: armotypes.PortalBase{Name: "rule-a"}},
							{PortalBase: armotypes.PortalBase{Name: "rule-b"}},
						},
					},
				},
			},
		}
	}

	frameworks := buildFrameworks()
	originalRuleCount := len(frameworks[0].Controls[0].Rules)

	// first scan excludes "rule-a"
	firstScanPolicies := NewPolicies()
	firstScanPolicies.Set(frameworks, map[string]bool{"rule-a": true}, "")
	assert.Len(t, firstScanPolicies.Controls["control-1"].Rules, 1)

	// the caller's original slice must be untouched by the first Set call
	assert.Len(t, frameworks[0].Controls[0].Rules, originalRuleCount,
		"Set must not mutate the caller's frameworks slice")

	// a second scan reusing the same frameworks slice (e.g. a cache hit) with no
	// exclusions must see all rules, not the previous scan's filtered-down set
	secondScanPolicies := NewPolicies()
	secondScanPolicies.Set(frameworks, nil, "")
	assert.Len(t, secondScanPolicies.Controls["control-1"].Rules, originalRuleCount)
}

func TestGetScanningScope(t *testing.T) {
	tests := []struct {
		name     string
		metadata reporthandlingv2.ContextMetadata
		expected reporthandling.ScanningScopeType
	}{
		{
			name: "ScopeFile without cluster context",
			metadata: reporthandlingv2.ContextMetadata{
				ClusterContextMetadata: nil,
			},
			expected: reporthandling.ScopeFile,
		},
		{
			name: "ScopeCluster with cluster context but no cloud metadata",
			metadata: reporthandlingv2.ContextMetadata{
				ClusterContextMetadata: &reporthandlingv2.ClusterMetadata{
					CloudMetadata: nil,
				},
			},
			expected: reporthandling.ScopeCluster,
		},
		{
			name: "CloudProvider matching provider string",
			metadata: reporthandlingv2.ContextMetadata{
				ClusterContextMetadata: &reporthandlingv2.ClusterMetadata{
					CloudMetadata: &reporthandlingv2.CloudMetadata{
						CloudProvider: "gke",
					},
				},
			},
			expected: reporthandling.ScanningScopeType("gke"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, GetScanningScope(tt.metadata))
		})
	}
}

func TestIsRuleKubescapeVersionCompatible_BadSemverBounds(t *testing.T) {
	tests := []struct {
		name        string
		attributes  map[string]interface{}
		buildNumber string
		want        bool
	}{
		{
			name:        "invalid useUntilKubescapeVersion excludes the rule (fail-closed)",
			attributes:  map[string]interface{}{"useUntilKubescapeVersion": "not-a-version"},
			buildNumber: "v1.0.133",
			want:        false,
		},
		{
			name: "valid from, invalid until excludes the rule (mixed case)",
			attributes: map[string]interface{}{
				"useFromKubescapeVersion":  "v1.0.130",
				"useUntilKubescapeVersion": "not-a-version",
			},
			buildNumber: "v1.0.133",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRuleKubescapeVersionCompatible("test-rule", tt.attributes, tt.buildNumber, make(map[string]struct{}))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsRuleKubescapeVersionCompatible_WarnsOnInvalidUntil(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "log"))
	require.NoError(t, err)
	defer f.Close()
	prev := logger.L().GetWriter()
	logger.L().SetWriter(f)
	defer logger.L().SetWriter(prev)

	assert.False(t, isRuleKubescapeVersionCompatible("c-0001", map[string]any{"useUntilKubescapeVersion": "not-a-version"}, "v1.0.133", make(map[string]struct{})))

	require.NoError(t, f.Sync())
	b, err := os.ReadFile(f.Name())
	require.NoError(t, err)
	assert.Contains(t, string(b), "invalid useUntilKubescapeVersion")
	assert.Contains(t, string(b), "c-0001")
}

func TestIsRuleKubescapeVersionCompatible_WarnsOnInvalidFrom(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "log"))
	require.NoError(t, err)
	defer f.Close()
	prev := logger.L().GetWriter()
	logger.L().SetWriter(f)
	defer logger.L().SetWriter(prev)

	assert.True(t, isRuleKubescapeVersionCompatible("c-0002", map[string]any{"useFromKubescapeVersion": "not-a-version"}, "v1.0.133", make(map[string]struct{})))

	require.NoError(t, f.Sync())
	b, err := os.ReadFile(f.Name())
	require.NoError(t, err)
	assert.Contains(t, string(b), "invalid useFromKubescapeVersion")
	assert.Contains(t, string(b), "c-0002")
}

func TestIsRuleKubescapeVersionCompatible_DedupWarnings(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "log"))
	require.NoError(t, err)
	defer f.Close()
	prev := logger.L().GetWriter()
	logger.L().SetWriter(f)
	defer logger.L().SetWriter(prev)

	warned := make(map[string]struct{})
	for range 3 {
		isRuleKubescapeVersionCompatible("dedup-rule", map[string]any{"useUntilKubescapeVersion": "bad-semver"}, "v1.0.133", warned)
	}

	require.NoError(t, f.Sync())
	b, err := os.ReadFile(f.Name())
	require.NoError(t, err)
	assert.Equal(t, 1, bytes.Count(b, []byte("invalid useUntilKubescapeVersion")), "expected exactly one warning, got duplicates")
}
