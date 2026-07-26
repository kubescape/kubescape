package cautils

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func useTemporaryConfigStore(t *testing.T) {
	t.Helper()
	original := getter.DefaultLocalStore
	getter.DefaultLocalStore = t.TempDir()
	t.Cleanup(func() { getter.DefaultLocalStore = original })
}

func TestTenantConfigCacheLifecycleDataDriven(t *testing.T) {
	tests := []struct {
		name      string
		newConfig func() ITenantConfig
	}{
		{
			name: "local configuration",
			newConfig: func() ITenantConfig {
				return &LocalConfig{configObj: &ConfigObj{
					AccountID: "account", AccessKey: "secret", ClusterName: "local-cluster",
					CloudAPIURL: "https://api.example.com", CloudReportURL: "https://report.example.com",
				}}
			},
		},
		{
			name: "cluster configuration",
			newConfig: func() ITenantConfig {
				return &ClusterConfig{configObj: &ConfigObj{
					AccountID: "account", AccessKey: "secret", ClusterName: "remote-cluster",
					CloudAPIURL: "https://api.example.com", CloudReportURL: "https://report.example.com",
				}}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			useTemporaryConfigStore(t)
			config := test.newConfig()

			require.NoError(t, config.UpdateCachedConfig())
			info, err := os.Stat(ConfigFileFullPath())
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

			var persisted ConfigObj
			contents, err := os.ReadFile(ConfigFileFullPath())
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(contents, &persisted))
			assert.Equal(t, "account", persisted.AccountID)
			assert.Equal(t, "secret", persisted.AccessKey)
			assert.Empty(t, persisted.ClusterName, "cluster context is intentionally not cached")

			generatedID, err := config.GenerateAccountID()
			require.NoError(t, err)
			_, err = uuid.Parse(generatedID)
			require.NoError(t, err)

			require.NoError(t, config.DeleteCredentials())
			assert.Empty(t, config.GetAccountID())
			assert.Empty(t, config.GetAccessKey())

			require.NoError(t, config.DeleteCachedConfig(context.Background()))
			_, err = os.Stat(ConfigFileFullPath())
			assert.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestNewLocalConfigPrecedenceDataDriven(t *testing.T) {
	tests := []struct {
		name              string
		accountFlag       string
		accessKeyFlag     string
		clusterName       string
		customClusterName string
		envAccount        string
		envAccessKey      string
		wantAccount       string
		wantAccessKey     string
		wantCluster       string
	}{
		{
			name:        "explicit flags and custom cluster win",
			accountFlag: "flag-account", accessKeyFlag: "flag-key",
			clusterName: "ignored cluster", customClusterName: "production/eu-west",
			envAccount: "env-account", envAccessKey: "env-key",
			wantAccount: "flag-account", wantAccessKey: "flag-key", wantCluster: "production-eu-west",
		},
		{
			name:        "environment credentials and detected cluster are fallbacks",
			clusterName: "kind:development",
			envAccount:  "env-account", envAccessKey: "env-key",
			wantAccount: "env-account", wantAccessKey: "env-key", wantCluster: "kind-development",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			useTemporaryConfigStore(t)
			getter.SetKSCloudAPIConnector(nil)
			t.Cleanup(func() { getter.SetKSCloudAPIConnector(nil) })
			t.Setenv(accountIdEnvVar, test.envAccount)
			t.Setenv(accessKeyEnvVar, test.envAccessKey)
			t.Setenv(cloudApiUrlEnvVar, "")
			t.Setenv(cloudReportUrlEnvVar, "")

			config := NewLocalConfig(test.accountFlag, test.accessKeyFlag, test.clusterName, test.customClusterName)
			assert.Equal(t, test.wantAccount, config.GetAccountID())
			assert.Equal(t, test.wantAccessKey, config.GetAccessKey())
			assert.Equal(t, test.wantCluster, config.GetContextName())
		})
	}
}

func TestClusterConfigLoadsKubernetesSourcesDataDriven(t *testing.T) {
	tests := []struct {
		name       string
		objects    []runtime.Object
		wantConfig ConfigObj
		wantError  string
	}{
		{
			name: "labelled config map and credentials secret",
			objects: []runtime.Object{
				&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cloud", Namespace: "security", Labels: map[string]string{"kubescape.io/infra": "config"}}, Data: map[string]string{
					"clusterData": `{"clusterName":"production","cloudAPIURL":"https://api.example.com","cloudReportURL":"https://report.example.com"}`,
				}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "security", Labels: map[string]string{"kubescape.io/infra": "credentials"}}, Data: map[string][]byte{
					"account": []byte("tenant-id"), "accessKey": []byte("access-key"),
				}},
			},
			wantConfig: ConfigObj{AccountID: "tenant-id", AccessKey: "access-key", ClusterName: "production", CloudAPIURL: "https://api.example.com", CloudReportURL: "https://report.example.com"},
		},
		{
			name: "legacy named config map remains supported",
			objects: []runtime.Object{
				&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: kubescapeConfigMapName, Namespace: "security"}, Data: map[string]string{
					"clusterData": `{"clusterName":"legacy-cluster","cloudAPIURL":"https://legacy.example.com"}`,
				}},
			},
			wantConfig: ConfigObj{ClusterName: "legacy-cluster", CloudAPIURL: "https://legacy.example.com"},
		},
		{
			name: "malformed cluster data is rejected",
			objects: []runtime.Object{
				&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cloud", Namespace: "security", Labels: map[string]string{"kubescape.io/infra": "config"}}, Data: map[string]string{"clusterData": "not-json"}},
			},
			wantError: "invalid character",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			k8s := k8sinterface.NewKubernetesApiMock()
			k8s.KubernetesClient = fake.NewClientset(test.objects...)
			config := &ClusterConfig{k8s: k8s, configObj: &ConfigObj{}, configMapNamespace: "security"}

			err := config.updateConfigEmptyFieldsFromKubescapeConfigMap()
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
				return
			}
			require.NoError(t, err)
			require.NoError(t, config.updateConfigEmptyFieldsFromCredentialsSecret())
			assert.Equal(t, test.wantConfig, *config.configObj)
		})
	}
}
