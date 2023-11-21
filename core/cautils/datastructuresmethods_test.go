package cautils

import (
	"fmt"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
)

func TestRuleWithKSOpaDependency(t *testing.T) {
	t.Run("return false when attributes is nil", func(t *testing.T) {
		result := ruleWithKSOpaDependency(nil)
		assert.False(t, result)
	})

	t.Run("returns false when attributes does not contain armoOpa key", func(t *testing.T) {
		attributes := map[string]interface{}{
			"key": "value",
		}
		result := ruleWithKSOpaDependency(attributes)
		assert.False(t, result)
	})

	t.Run("returns false when attributes contain armoOpa key with non bool value", func(t *testing.T) {
		attributes := map[string]interface{}{
			"armoOpa": true,
		}
		result := ruleWithKSOpaDependency(attributes)
		assert.False(t, result)
	})

	t.Run("returns true when attributes contain armoOpa key with value true", func(t *testing.T) {
		attributes := map[string]interface{}{
			"armoOpa": "true",
		}
		result := ruleWithKSOpaDependency(attributes)
		assert.True(t, result)
	})
}

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
