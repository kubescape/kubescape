package cautils

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
	restclient "k8s.io/client-go/rest"
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

			err := config.updateConfigEmptyFieldsFromKubescapeConfigMap(context.Background())
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
				return
			}
			require.NoError(t, err)
			require.NoError(t, config.updateConfigEmptyFieldsFromCredentialsSecret(context.Background()))
			assert.Equal(t, test.wantConfig, *config.configObj)
		})
	}
}

func Test_GetDefaultNS(t *testing.T) {
	c := &ClusterConfig{configMapNamespace: "my-namespace"}
	assert.Equal(t, "my-namespace", c.GetDefaultNS())
}

func Test_loadConfigFromFile(t *testing.T) {
	t.Run("no file present returns nil without touching configObj", func(t *testing.T) {
		useTemporaryConfigStore(t)

		want := ConfigObj{AccountID: "sentinel-account", AccessKey: "sentinel-key", ClusterName: "sentinel-cluster"}
		configObj := want
		assert.NoError(t, loadConfigFromFile(&configObj))
		assert.Equal(t, want, configObj)
	})

	t.Run("existing file is loaded into configObj", func(t *testing.T) {
		useTemporaryConfigStore(t)

		want := &ConfigObj{AccountID: "file-account", AccessKey: "file-key", CloudAPIURL: "https://api.example.com"}
		fullPath := ConfigFileFullPath()
		require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0o700))
		require.NoError(t, os.WriteFile(fullPath, want.Config(), 0o600))

		configObj := &ConfigObj{}
		require.NoError(t, loadConfigFromFile(configObj))
		assert.Equal(t, want.AccountID, configObj.AccountID)
		assert.Equal(t, want.AccessKey, configObj.AccessKey)
		assert.Equal(t, want.CloudAPIURL, configObj.CloudAPIURL)
	})

	t.Run("malformed file returns an error", func(t *testing.T) {
		useTemporaryConfigStore(t)

		fullPath := ConfigFileFullPath()
		require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0o700))
		require.NoError(t, os.WriteFile(fullPath, []byte("not-json"), 0o600))

		assert.Error(t, loadConfigFromFile(&ConfigObj{}))
	})
}

func useTemporaryServicesConfigPath(t *testing.T, path string) {
	t.Helper()
	original := servicesConfigPath
	servicesConfigPath = path
	t.Cleanup(func() { servicesConfigPath = original })
}

func Test_loadUrlsFromFile(t *testing.T) {
	t.Run("missing services file leaves configObj untouched", func(t *testing.T) {
		useTemporaryServicesConfigPath(t, filepath.Join(t.TempDir(), "services.json"))

		want := ConfigObj{AccountID: "sentinel-account", AccessKey: "sentinel-key", ClusterName: "sentinel-cluster"}
		configObj := want
		assert.NoError(t, loadUrlsFromFile(&configObj))
		assert.Equal(t, want, configObj)
	})

	t.Run("valid services file populates cloud urls", func(t *testing.T) {
		servicesPath := filepath.Join(t.TempDir(), "services.json")
		useTemporaryServicesConfigPath(t, servicesPath)

		payload := `{"version":"v2","response":{"api-server":"https://api.example.com","event-receiver-http":"https://report.example.com"}}`
		require.NoError(t, os.WriteFile(servicesPath, []byte(payload), 0o600))

		configObj := &ConfigObj{}
		require.NoError(t, loadUrlsFromFile(configObj))
		assert.Equal(t, "https://api.example.com", configObj.CloudAPIURL)
		assert.Equal(t, "https://report.example.com", configObj.CloudReportURL)
	})
}

func Test_NewClusterConfig(t *testing.T) {
	useTemporaryConfigStore(t)
	getter.SetKSCloudAPIConnector(nil)
	t.Cleanup(func() { getter.SetKSCloudAPIConnector(nil) })
	t.Setenv(accountIdEnvVar, "")
	t.Setenv(accessKeyEnvVar, "")
	t.Setenv(cloudApiUrlEnvVar, "")
	t.Setenv(cloudReportUrlEnvVar, "")
	t.Setenv(defaultConfigMapNamespaceEnvVar, "security")

	objects := []runtime.Object{
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cloud", Namespace: "security", Labels: map[string]string{"kubescape.io/infra": "config"}}, Data: map[string]string{
			"clusterData": `{"cloudAPIURL":"https://api.example.com","cloudReportURL":"https://report.example.com"}`,
		}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "security", Labels: map[string]string{"kubescape.io/infra": "credentials"}}, Data: map[string][]byte{
			"account": []byte("tenant-id"), "accessKey": []byte("access-key"),
		}},
	}

	k8s := k8sinterface.NewKubernetesApiMock()
	k8s.KubernetesClient = fake.NewClientset(objects...)

	config := NewClusterConfig(context.Background(), k8s, "", "", "my:cluster", "")

	assert.Equal(t, "security", config.GetDefaultNS())
	assert.Equal(t, "tenant-id", config.GetAccountID())
	assert.Equal(t, "access-key", config.GetAccessKey())
	assert.Equal(t, "https://api.example.com", config.GetCloudAPIURL())
	assert.Equal(t, "https://report.example.com", config.GetCloudReportURL())
	assert.Equal(t, "my-cluster", config.GetContextName())
}

func Test_GetTenantConfig(t *testing.T) {
	useTemporaryConfigStore(t)
	getter.SetKSCloudAPIConnector(nil)
	t.Cleanup(func() { getter.SetKSCloudAPIConnector(nil) })

	originalConnected := k8sinterface.IsConnectedToCluster()
	t.Cleanup(func() { k8sinterface.SetConnectedToCluster(originalConnected) })

	originalK8SConfig := k8sinterface.K8SConfig
	t.Cleanup(func() { k8sinterface.K8SConfig = originalK8SConfig })

	t.Run("not connected to cluster returns LocalConfig", func(t *testing.T) {
		k8sinterface.SetConnectedToCluster(false)

		config := GetTenantConfig(context.Background(), "account", "key", "cluster", "", nil)
		_, ok := config.(*LocalConfig)
		assert.True(t, ok, "expected *LocalConfig when not connected to a cluster")
	})

	t.Run("connected to cluster with k8s client returns ClusterConfig", func(t *testing.T) {
		k8sinterface.K8SConfig = &restclient.Config{}
		k8sinterface.SetConnectedToCluster(true)

		k8s := k8sinterface.NewKubernetesApiMock()
		config := GetTenantConfig(context.Background(), "account", "key", "cluster", "", k8s)
		_, ok := config.(*ClusterConfig)
		assert.True(t, ok, "expected *ClusterConfig when connected to a cluster with a k8s client")
	})

	t.Run("connected to cluster without k8s client falls back to LocalConfig", func(t *testing.T) {
		k8sinterface.SetConnectedToCluster(true)

		config := GetTenantConfig(context.Background(), "account", "key", "cluster", "", nil)
		_, ok := config.(*LocalConfig)
		assert.True(t, ok, "expected *LocalConfig when k8s client is nil")
	})
}
