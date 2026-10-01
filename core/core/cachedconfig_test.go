package core

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func isolateCachedConfigTest(t *testing.T) {
	t.Helper()

	originalStore := getter.DefaultLocalStore
	getter.DefaultLocalStore = t.TempDir()
	t.Cleanup(func() { getter.DefaultLocalStore = originalStore })

	originalConnector := getter.GetKSCloudAPIConnector()
	getter.SetKSCloudAPIConnector(nil)
	t.Cleanup(func() { getter.SetKSCloudAPIConnector(originalConnector) })

	for _, envVar := range []string{
		"KS_ACCOUNT_ID",
		"KS_ACCESS_KEY",
		"KS_CLOUD_API_URL",
		"KS_CLOUD_REPORT_URL",
	} {
		t.Setenv(envVar, "")
	}
}

func readPersistedConfig(t *testing.T) cautils.ConfigObj {
	t.Helper()

	data, err := os.ReadFile(cautils.ConfigFileFullPath())
	require.NoError(t, err)

	var config cautils.ConfigObj
	require.NoError(t, json.Unmarshal(data, &config))
	return config
}

func TestViewCachedConfig_KeyedLookup(t *testing.T) {
	isolateCachedConfigTest(t)

	// Force the LocalConfig path so the test never reads the host's cluster
	// ConfigMap/Secret/kube-context.
	originalConnected := k8sinterface.IsConnectedToCluster()
	k8sinterface.SetConnectedToCluster(false)
	t.Cleanup(func() { k8sinterface.SetConnectedToCluster(originalConnected) })

	// stub k8s API to prevent flaky tests in cluster-connected environments
	origK8s := kubernetesAPIFunc
	kubernetesAPIFunc = func() *k8sinterface.KubernetesApi { return nil }
	t.Cleanup(func() { kubernetesAPIFunc = origK8s })

	ks := NewKubescape(context.Background())

	// Set cached config values
	setConfig := &metav1.SetConfig{
		Account:   "test-account-id",
		AccessKey: "test-secret-key-123", // length > 8, should mask everything except last 4
	}
	require.NoError(t, ks.SetCachedConfig(setConfig))

	tests := []struct {
		name    string
		key     string
		format  string
		want    string
		wantErr string
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
			key:     "cloudReportURL",
			format:  "",
			wantErr: `key "cloudReportURL" is not set`,
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

func TestSetCachedConfig_AllFieldsPersisted(t *testing.T) {
	isolateCachedConfigTest(t)

	ks := NewKubescape(context.Background())
	setConfig := &metav1.SetConfig{
		Account:        "test-account",
		AccessKey:      "test-access-key",
		CloudAPIURL:    "https://api.example.test",
		CloudReportURL: "https://report.example.test",
	}

	require.NoError(t, ks.SetCachedConfig(setConfig))

	persisted := readPersistedConfig(t)
	assert.Equal(t, setConfig.Account, persisted.AccountID)
	assert.Equal(t, setConfig.AccessKey, persisted.AccessKey)
	assert.Equal(t, setConfig.CloudAPIURL, persisted.CloudAPIURL)
	assert.Equal(t, setConfig.CloudReportURL, persisted.CloudReportURL)
}

func TestSetCachedConfig_EmptyFieldsDoNotOverride(t *testing.T) {
	isolateCachedConfigTest(t)

	ks := NewKubescape(context.Background())
	require.NoError(t, ks.SetCachedConfig(&metav1.SetConfig{
		Account:        "original-account",
		AccessKey:      "original-access-key",
		CloudAPIURL:    "https://original-api.example.test",
		CloudReportURL: "https://original-report.example.test",
	}))

	before := readPersistedConfig(t)
	require.NoError(t, ks.SetCachedConfig(&metav1.SetConfig{}))
	after := readPersistedConfig(t)

	assert.Equal(t, before, after)
}

func TestViewCachedConfig_FullJSON(t *testing.T) {
	isolateCachedConfigTest(t)

	// Force the LocalConfig path so the test never reads the host's cluster
	// ConfigMap, Secret, or kube-context.
	originalConnected := k8sinterface.IsConnectedToCluster()
	k8sinterface.SetConnectedToCluster(false)
	t.Cleanup(func() { k8sinterface.SetConnectedToCluster(originalConnected) })

	originalKubernetesAPIFunc := kubernetesAPIFunc
	kubernetesAPIFunc = func() *k8sinterface.KubernetesApi { return nil }
	t.Cleanup(func() { kubernetesAPIFunc = originalKubernetesAPIFunc })

	ks := NewKubescape(context.Background())
	const accessKey = "test-access-key-123"
	require.NoError(t, ks.SetCachedConfig(&metav1.SetConfig{
		Account:        "test-account",
		AccessKey:      accessKey,
		CloudAPIURL:    "https://api.example.test",
		CloudReportURL: "https://report.example.test",
	}))

	var output bytes.Buffer
	require.NoError(t, ks.ViewCachedConfig(&metav1.ViewConfig{
		OutputFormat: "json",
		Writer:       &output,
	}))

	var rendered map[string]string
	require.NoError(t, json.Unmarshal(output.Bytes(), &rendered))
	assert.Equal(t, "test-account", rendered["accountID"])
	assert.Equal(t, "https://api.example.test", rendered["cloudAPIURL"])
	assert.Equal(t, "https://report.example.test", rendered["cloudReportURL"])
	assert.Equal(t, "****-123", rendered["accessKey"])
	assert.NotContains(t, output.String(), accessKey)
}

func TestDeleteCachedConfig_RemovesCachedConfig(t *testing.T) {
	isolateCachedConfigTest(t)

	ks := NewKubescape(context.Background())
	require.NoError(t, ks.SetCachedConfig(&metav1.SetConfig{Account: "test-account"}))
	_, err := os.Stat(cautils.ConfigFileFullPath())
	require.NoError(t, err)

	require.NoError(t, ks.DeleteCachedConfig(&metav1.DeleteConfig{}))
	_, err = os.Stat(cautils.ConfigFileFullPath())
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestDeleteCachedConfig_MissingFileIsNonFatal(t *testing.T) {
	isolateCachedConfigTest(t)

	_, err := os.Stat(cautils.ConfigFileFullPath())
	require.ErrorIs(t, err, os.ErrNotExist)

	ks := NewKubescape(context.Background())
	require.NoError(t, ks.DeleteCachedConfig(&metav1.DeleteConfig{}))
}
