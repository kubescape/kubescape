package cautils

import (
	"testing"

	"github.com/armosec/armoapi-go/apis"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func requireConfigScanRequest(t *testing.T, payload *apis.Commands) utilsmetav1.PostScanRequest {
	t.Helper()

	require.NotNil(t, payload)
	require.Len(t, payload.Commands, 1)
	assert.Equal(t, apis.TypeRunKubescape, payload.Commands[0].CommandName)
	require.Contains(t, payload.Commands[0].Args, KubescapeScanV1)

	request, ok := payload.Commands[0].Args[KubescapeScanV1].(utilsmetav1.PostScanRequest)
	require.True(t, ok)
	return request
}

func TestConfigScanInfo_ValidatePayload(t *testing.T) {
	tests := []struct {
		name      string
		info      ConfigScanInfo
		expectErr bool
	}{
		{
			name:      "no namespaces set",
			info:      ConfigScanInfo{},
			expectErr: false,
		},
		{
			name: "only included namespaces",
			info: ConfigScanInfo{
				IncludedNamespaces: []string{"ns-a"},
			},
			expectErr: false,
		},
		{
			name: "only excluded namespaces",
			info: ConfigScanInfo{
				ExcludedNamespaces: []string{"ns-b"},
			},
			expectErr: false,
		},
		{
			name: "both included and excluded namespaces",
			info: ConfigScanInfo{
				IncludedNamespaces: []string{"ns-a"},
				ExcludedNamespaces: []string{"ns-b"},
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.info.ValidatePayload(&apis.Commands{})
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigScanInfo_GetRequestPayload(t *testing.T) {
	t.Run("default frameworks when none specified", func(t *testing.T) {
		info := &ConfigScanInfo{}
		payload := info.GetRequestPayload()
		request := requireConfigScanRequest(t, payload)

		assert.Equal(t, apisv1.KindFramework, request.TargetType)
		assert.Equal(t, []string{"all"}, request.TargetNames)
		assert.Empty(t, request.IncludeNamespaces)
		assert.Empty(t, request.ExcludedNamespaces)
		require.NotNil(t, request.HostScanner)
		assert.False(t, *request.HostScanner)
	})

	t.Run("uses provided frameworks", func(t *testing.T) {
		info := &ConfigScanInfo{
			Frameworks: []string{"nsa", "mitre"},
		}
		payload := info.GetRequestPayload()
		request := requireConfigScanRequest(t, payload)

		assert.Equal(t, apisv1.KindFramework, request.TargetType)
		assert.Equal(t, []string{"nsa", "mitre"}, request.TargetNames)
	})

	t.Run("includes excluded namespaces in payload", func(t *testing.T) {
		info := &ConfigScanInfo{
			ExcludedNamespaces: []string{"kube-system"},
			Frameworks:         []string{"nsa"},
		}
		payload := info.GetRequestPayload()
		request := requireConfigScanRequest(t, payload)

		assert.Equal(t, []string{"kube-system"}, request.ExcludedNamespaces)
		assert.Empty(t, request.IncludeNamespaces)
		assert.Equal(t, []string{"nsa"}, request.TargetNames)
	})

	t.Run("includes included namespaces in payload", func(t *testing.T) {
		info := &ConfigScanInfo{
			IncludedNamespaces: []string{"prod"},
			Frameworks:         []string{"mitre"},
			HostScanner:        true,
		}
		payload := info.GetRequestPayload()
		request := requireConfigScanRequest(t, payload)

		assert.Equal(t, []string{"prod"}, request.IncludeNamespaces)
		assert.Empty(t, request.ExcludedNamespaces)
		assert.Equal(t, []string{"mitre"}, request.TargetNames)
		require.NotNil(t, request.HostScanner)
		assert.True(t, *request.HostScanner)
	})
}

func TestVulnerabilitiesScanInfo_ValidatePayload(t *testing.T) {
	info := &VulnerabilitiesScanInfo{}
	err := info.ValidatePayload(&apis.Commands{})
	assert.NoError(t, err, "ValidatePayload should always return nil")
}

func TestVulnerabilitiesScanInfo_GetRequestPayload(t *testing.T) {
	t.Run("no namespaces produces single wildcard command", func(t *testing.T) {
		info := &VulnerabilitiesScanInfo{
			ClusterName: "test-cluster",
		}
		payload := info.GetRequestPayload()

		require.NotNil(t, payload)
		require.Len(t, payload.Commands, 1)
		assert.Equal(t, apis.TypeScanImages, payload.Commands[0].CommandName)
		assert.Equal(t, "wlid://cluster-test-cluster/namespace-", payload.Commands[0].WildWlid)
	})

	t.Run("multiple namespaces produce one command per namespace", func(t *testing.T) {
		info := &VulnerabilitiesScanInfo{
			ClusterName:       "test-cluster",
			IncludeNamespaces: []string{"ns-a", "ns-b", "ns-c"},
		}
		payload := info.GetRequestPayload()

		require.NotNil(t, payload)
		require.Len(t, payload.Commands, 3)
		expectedWildWlids := []string{
			"wlid://cluster-test-cluster/namespace-ns-a",
			"wlid://cluster-test-cluster/namespace-ns-b",
			"wlid://cluster-test-cluster/namespace-ns-c",
		}
		for i, cmd := range payload.Commands {
			assert.Equal(t, apis.TypeScanImages, cmd.CommandName)
			assert.Equal(t, expectedWildWlids[i], cmd.WildWlid)
		}
	})
}
