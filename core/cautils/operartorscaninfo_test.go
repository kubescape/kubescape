package cautils

import (
	"errors"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/stretchr/testify/assert"
)

func newFalse() *bool {
	f := false
	return &f
}

func Test_GetRequestPayload(t *testing.T) {
	testCases := []struct {
		name        string
		clusterName string
		OperatorScanInfo
		result *apis.Commands
	}{
		{
			name: "scan kubescape config",
			OperatorScanInfo: &ConfigScanInfo{
				ExcludedNamespaces: []string{"1111"},
				IncludedNamespaces: []string{"2222"},
				HostScanner:        false,
				Frameworks:         []string{"any", "many"},
			},
			result: &apis.Commands{
				Commands: []apis.Command{
					{
						CommandName: apis.TypeRunKubescape,
						Args: map[string]interface{}{
							KubescapeScanV1: utilsmetav1.PostScanRequest{
								ExcludedNamespaces: []string{"1111"},
								IncludeNamespaces:  []string{"2222"},
								TargetType:         apisv1.KindFramework,
								TargetNames:        []string{"any", "many"},
								HostScanner:        newFalse(),
							},
						},
					},
				},
			},
		},
		{
			name: "scan kubescape vulns",
			OperatorScanInfo: &VulnerabilitiesScanInfo{
				ClusterName:       "any",
				IncludeNamespaces: []string{""},
			},
			result: &apis.Commands{
				Commands: []apis.Command{
					{
						CommandName: apis.TypeScanImages,
						WildWlid:    "wlid://cluster-any/namespace-",
					},
				},
			},
		},
		{
			name: "scan kubescape vulns with namespace",
			OperatorScanInfo: &VulnerabilitiesScanInfo{
				ClusterName:       "any",
				IncludeNamespaces: []string{"123"},
			},
			result: &apis.Commands{
				Commands: []apis.Command{
					{
						CommandName: apis.TypeScanImages,
						WildWlid:    "wlid://cluster-any/namespace-123",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.OperatorScanInfo.GetRequestPayload()
			assert.Equal(t, tc.result, result)
		})
	}
}

func Test_ValidatePayload(t *testing.T) {
	testCases := []struct {
		name        string
		clusterName string
		OperatorScanInfo
		result error
	}{
		{
			name: "ConfigScanInfo first happy case",
			OperatorScanInfo: &ConfigScanInfo{
				ExcludedNamespaces: []string{"1111"},
				IncludedNamespaces: []string{},
				HostScanner:        false,
				Frameworks:         []string{"any", "many"},
			},
			result: nil,
		},
		{
			name: "ConfigScanInfo second happy case",
			OperatorScanInfo: &ConfigScanInfo{
				ExcludedNamespaces: []string{},
				IncludedNamespaces: []string{"1111"},
				HostScanner:        false,
				Frameworks:         []string{"any", "many"},
			},
			result: nil,
		},
		{
			name: "ConfigScanInfo returned error",
			OperatorScanInfo: &ConfigScanInfo{
				ExcludedNamespaces: []string{"1111"},
				IncludedNamespaces: []string{"2222"},
				HostScanner:        false,
				Frameworks:         []string{"any", "many"},
			},
			result: errors.New("invalid arguments: include-namespaces and exclude-namespaces can't pass together to the CLI"),
		},
		{
			name: "VulnerabilitiesScanInfo happy case",
			OperatorScanInfo: &VulnerabilitiesScanInfo{
				ClusterName:       "any",
				IncludeNamespaces: []string{""},
			},
			result: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payload := tc.OperatorScanInfo.GetRequestPayload()
			result := tc.OperatorScanInfo.ValidatePayload(payload)
			assert.Equal(t, tc.result, result)
		})
	}
}
