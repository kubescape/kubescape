package core

import (
	"bytes"
	"context"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestViewCachedConfig_KeyedLookup(t *testing.T) {
	// Setup temporary config store
	originalStore := getter.DefaultLocalStore
	getter.DefaultLocalStore = t.TempDir()
	t.Cleanup(func() { getter.DefaultLocalStore = originalStore })

	ks := NewKubescape(context.Background())

	// Set cached config values
	setConfig := &metav1.SetConfig{
		Account:   "test-account-id",
		AccessKey: "test-secret-key-123", // length > 8, should mask everything except last 4
	}
	require.NoError(t, ks.SetCachedConfig(setConfig))

	tests := []struct {
		name       string
		key        string
		format     string
		want       string
		wantErr    string
	}{
		{
			name:   "Found key",
			key:    "accountID",
			format: "text", // default
			want:   "test-account-id\n",
		},
		{
			name:   "Key normalization",
			key:    "Account",
			format: "",
			want:   "test-account-id\n",
		},
		{
			name:   "Masked access key",
			key:    "accessKey",
			format: "",
			want:   "****-123\n", // Length > 8, masks last 4. 'test-secret-key-123' is 19 chars. last 4 is '-123'
		},
		{
			name:    "Unsupported key",
			key:     "unknownKey",
			format:  "",
			wantErr: `key "unknownKey" is not supported`,
		},
		{
			name:    "Unset key",
			key:     "clusterName",
			format:  "",
			wantErr: `key "clusterName" is not set`,
		},
		{
			name:   "Format JSON",
			key:    "accountID",
			format: "json",
			want:   "{\n  \"accountID\": \"test-account-id\"\n}",
		},
		{
			name:   "Format YAML",
			key:    "accountID",
			format: "yaml",
			want:   "accountID: test-account-id\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			viewConfig := &metav1.ViewConfig{
				Key:          tt.key,
				OutputFormat: tt.format,
				Writer:       &buf,
			}

			err := ks.ViewCachedConfig(viewConfig)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, buf.String())
			}
		})
	}
}
