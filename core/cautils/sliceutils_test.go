package cautils

import (
	"fmt"
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
)

func TestIsSubSliceScanningScopeType(t *testing.T) {
	tests_true := []struct {
		haystack []reporthandling.ScanningScopeType
		needle   []reporthandling.ScanningScopeType
	}{
		{
			haystack: []reporthandling.ScanningScopeType{
				reporthandling.ScopeFile,
			},
			needle: []reporthandling.ScanningScopeType{
				reporthandling.ScopeFile,
			},
		},
		{
			haystack: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
			},
			needle: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
			},
		},
		{
			haystack: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
				reporthandling.ScopeCloud,
			},
			needle: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
			},
		},
		{
			haystack: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
				reporthandling.ScopeCloud,
				reporthandling.ScopeCloudAKS,
			},
			needle: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
			},
		},
		{
			haystack: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
				reporthandling.ScopeCloud,
				reporthandling.ScopeCloudEKS,
			},
			needle: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
			},
		},
		{
			haystack: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
				reporthandling.ScopeCloud,
				reporthandling.ScopeCloudGKE,
			},
			needle: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
			},
		},
		{
			haystack: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
				reporthandling.ScopeCloud,
				reporthandling.ScopeCloudAKS,
			},
			needle: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
				reporthandling.ScopeCloud,
			},
		},
		{
			haystack: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
				reporthandling.ScopeCloud,
				reporthandling.ScopeCloudEKS,
			},
			needle: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
				reporthandling.ScopeCloud,
			},
		},
		{
			haystack: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
				reporthandling.ScopeCloud,
				reporthandling.ScopeCloudGKE,
			},
			needle: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
				reporthandling.ScopeCloud,
			},
		},
		{
			haystack: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
				reporthandling.ScopeCloud,
				reporthandling.ScopeCloudAKS,
			},
			needle: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
				reporthandling.ScopeCloud,
				reporthandling.ScopeCloudAKS,
			},
		},
		{
			haystack: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
				reporthandling.ScopeCloud,
				reporthandling.ScopeCloudEKS,
			},
			needle: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
				reporthandling.ScopeCloud,
				reporthandling.ScopeCloudEKS,
			},
		},
		{
			haystack: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
				reporthandling.ScopeCloud,
				reporthandling.ScopeCloudGKE,
			},
			needle: []reporthandling.ScanningScopeType{
				reporthandling.ScopeCluster,
				reporthandling.ScopeCloud,
				reporthandling.ScopeCloudGKE,
			},
		},
	}

	for i := range tests_true {
		assert.Equal(t, IsSubSliceScanningScopeType(tests_true[i].haystack, tests_true[i].needle), true, fmt.Sprintf("tests_true index %d", i))
	}

	tests_false := []struct {
		haystack []reporthandling.ScanningScopeType
		needle   []reporthandling.ScanningScopeType
	}{
		{
			haystack: []reporthandling.ScanningScopeType{reporthandling.ScopeFile},
			needle:   []reporthandling.ScanningScopeType{reporthandling.ScopeCluster},
		},
		{
			haystack: []reporthandling.ScanningScopeType{reporthandling.ScopeCluster},
			needle:   []reporthandling.ScanningScopeType{reporthandling.ScopeCluster, reporthandling.ScopeCloud},
		},
		{
			haystack: []reporthandling.ScanningScopeType{reporthandling.ScopeCluster},
			needle:   []reporthandling.ScanningScopeType{reporthandling.ScopeCluster, reporthandling.ScopeCloud, reporthandling.ScopeCloudAKS},
		},
		{
			haystack: []reporthandling.ScanningScopeType{reporthandling.ScopeCluster},
			needle:   []reporthandling.ScanningScopeType{reporthandling.ScopeCluster, reporthandling.ScopeCloud, reporthandling.ScopeCloudEKS},
		},
		{
			haystack: []reporthandling.ScanningScopeType{reporthandling.ScopeCluster, reporthandling.ScopeCloud, reporthandling.ScopeCloudAKS},
			needle:   []reporthandling.ScanningScopeType{reporthandling.ScopeCluster, reporthandling.ScopeCloud, reporthandling.ScopeCloudGKE},
		},
		{
			haystack: []reporthandling.ScanningScopeType{reporthandling.ScopeCluster, reporthandling.ScopeCloud, reporthandling.ScopeCloudGKE},
			needle:   []reporthandling.ScanningScopeType{reporthandling.ScopeCluster, reporthandling.ScopeCloud, reporthandling.ScopeCloudAKS},
		},
		{
			haystack: []reporthandling.ScanningScopeType{reporthandling.ScopeCluster},
			needle:   []reporthandling.ScanningScopeType{reporthandling.ScopeCluster, reporthandling.ScopeCloud, reporthandling.ScopeCloudEKS},
		},
		{
			haystack: []reporthandling.ScanningScopeType{reporthandling.ScopeCluster, reporthandling.ScopeCloud, reporthandling.ScopeCloudEKS},
			needle:   []reporthandling.ScanningScopeType{reporthandling.ScopeCluster, reporthandling.ScopeCloud, reporthandling.ScopeCloudGKE},
		},
	}

	for i := range tests_false {
		assert.Equal(t, IsSubSliceScanningScopeType(tests_false[i].haystack, tests_false[i].needle), false, fmt.Sprintf("tests_false index %d", i))
	}
}
