package cautils

import (
	"fmt"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
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
	Attributes: map[string]interface{}{"useUntilKubescapeVersion": "v1.0.132"}}}
var rule_v1_0_132 = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]interface{}{"useFromKubescapeVersion": "v1.0.132", "useUntilKubescapeVersion": "v1.0.133"}}}
var rule_v1_0_133 = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]interface{}{"useFromKubescapeVersion": "v1.0.133", "useUntilKubescapeVersion": "v1.0.134"}}}
var rule_v1_0_134 = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]interface{}{"useFromKubescapeVersion": "v1.0.134"}}}
var rule_invalid_from = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]interface{}{"useFromKubescapeVersion": 1.0135, "useUntilKubescapeVersion": "v1.0.135"}}}
var rule_invalid_until = &reporthandling.PolicyRule{PortalBase: armotypes.PortalBase{
	Attributes: map[string]interface{}{"useFromKubescapeVersion": "v1.0.135", "useUntilKubescapeVersion": 1.0135}}}

func TestIsRuleKubescapeVersionCompatible(t *testing.T) {
	// local build- no build number

	// should not crash when the value of useUntilKubescapeVersion is not a string
	buildNumberMock := "v1.0.135"
	assert.False(t, isRuleKubescapeVersionCompatible(rule_invalid_from.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_invalid_until.Attributes, buildNumberMock))
	// should use only rules that don't have "until"
	buildNumberMock = ""
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_131.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_132.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_133.Attributes, buildNumberMock))
	assert.True(t, isRuleKubescapeVersionCompatible(rule_v1_0_134.Attributes, buildNumberMock))

	// should only use rules that version is in range of use
	buildNumberMock = "v1.0.130"
	assert.True(t, isRuleKubescapeVersionCompatible(rule_v1_0_131.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_132.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_133.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_134.Attributes, buildNumberMock))

	// should only use rules that version is in range of use
	buildNumberMock = "v1.0.132"
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_131.Attributes, buildNumberMock))
	assert.True(t, isRuleKubescapeVersionCompatible(rule_v1_0_132.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_133.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_134.Attributes, buildNumberMock))

	// should only use rules that version is in range of use
	buildNumberMock = "v1.0.133"
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_131.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_132.Attributes, buildNumberMock))
	assert.True(t, isRuleKubescapeVersionCompatible(rule_v1_0_133.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_134.Attributes, buildNumberMock))

	// should only use rules that version is in range of use
	buildNumberMock = "v1.0.135"
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_131.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_132.Attributes, buildNumberMock))
	assert.False(t, isRuleKubescapeVersionCompatible(rule_v1_0_133.Attributes, buildNumberMock))
	assert.True(t, isRuleKubescapeVersionCompatible(rule_v1_0_134.Attributes, buildNumberMock))
}
