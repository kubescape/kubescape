package cautils

import (
	"testing"

	"github.com/armosec/armoapi-go/apis"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/stretchr/testify/assert"
)

func newTrue() *bool {
	t := true
	return &t
}

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
				Submit:             false,
				ExcludedNamespaces: []string{"1111"},
				IncludedNamespaces: []string{"2222"},
				HostScanner:        false,
				Frameworks:         []string{"any", "many"},
			},
			result: &apis.Commands{
				Commands: []apis.Command{
					apis.Command{
						CommandName: apis.TypeRunKubescape,
						Args: map[string]interface{}{
							KubescapeScanV1: utilsmetav1.PostScanRequest{
								Submit:             newFalse(),
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
					apis.Command{
						CommandName: apis.TypeScanImages,
						WildWlid:    "wlid://cluster-any",
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
					apis.Command{
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
