package cautils

import (
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

		require.NotNil(t, payload)
		require.Len(t, payload.Commands, 1)
		assert.Equal(t, apis.TypeRunKubescape, payload.Commands[0].CommandName)
		// When no frameworks are set, "all" should be the default
		assert.Contains(t, info.Frameworks, "all")
	})

	t.Run("uses provided frameworks", func(t *testing.T) {
		info := &ConfigScanInfo{
			Frameworks: []string{"nsa", "mitre"},
		}
		payload := info.GetRequestPayload()

		require.NotNil(t, payload)
		require.Len(t, payload.Commands, 1)
		assert.Equal(t, []string{"nsa", "mitre"}, info.Frameworks)
	})

	t.Run("includes excluded namespaces in payload", func(t *testing.T) {
		info := &ConfigScanInfo{
			ExcludedNamespaces: []string{"kube-system"},
		}
		payload := info.GetRequestPayload()

		require.NotNil(t, payload)
		require.Len(t, payload.Commands, 1)
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
	})

	t.Run("multiple namespaces produce one command per namespace", func(t *testing.T) {
		info := &VulnerabilitiesScanInfo{
			ClusterName:       "test-cluster",
			IncludeNamespaces: []string{"ns-a", "ns-b", "ns-c"},
		}
		payload := info.GetRequestPayload()

		require.NotNil(t, payload)
		require.Len(t, payload.Commands, 3)
		for _, cmd := range payload.Commands {
			assert.Equal(t, apis.TypeScanImages, cmd.CommandName)
		}
	})
}
