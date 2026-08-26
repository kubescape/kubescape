package core

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	controllerconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
)

func TestResolveClusterContext_ExplicitKubeconfigMatchesRESTTarget(t *testing.T) {
	defaultPath := writeContextKubeconfig(t, "context-b", "https://b.example")
	explicitPath := writeContextKubeconfig(t, "context-a", "https://a.example")
	t.Setenv("KUBECONFIG", defaultPath)
	defaultConfig, err := clientcmd.LoadFromFile(defaultPath)
	require.NoError(t, err)
	k8sinterface.SetClusterContextName("")
	k8sinterface.SetClientConfigAPI(defaultConfig)
	t.Cleanup(func() {
		k8sinterface.SetClientConfigAPI(nil)
		k8sinterface.SetClusterContextName("")
	})

	kubeconfigFlag := flag.Lookup(controllerconfig.KubeconfigFlagName)
	require.NotNil(t, kubeconfigFlag)
	originalFlagValue := kubeconfigFlag.Value.String()
	require.NoError(t, flag.Set(controllerconfig.KubeconfigFlagName, explicitPath))
	t.Cleanup(func() {
		require.NoError(t, flag.Set(controllerconfig.KubeconfigFlagName, originalFlagValue))
	})

	restConfig, err := controllerconfig.GetConfigWithContext("")
	require.NoError(t, err)
	require.Equal(t, "https://a.example", restConfig.Host)

	scanInfo := &cautils.ScanInfo{CustomClusterName: "friendly-name"}
	scanInfo.SetKubeconfigSelection(explicitPath, "")
	require.NoError(t, resolveClusterContext(scanInfo))
	assert.Equal(t, "context-a", scanInfo.GetClusterContextName())
	assert.Equal(t, "friendly-name", scanInfo.CustomClusterName,
		"resolving the kube context must not replace --cluster-name")
}

func TestResolveClusterContext_OfflineScanDoesNotLoadKubeconfig(t *testing.T) {
	manifest := filepath.Join(t.TempDir(), "pod.yaml")
	require.NoError(t, os.WriteFile(manifest, []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"), 0o600))

	scanInfo := &cautils.ScanInfo{InputPatterns: []string{manifest}}
	scanInfo.SetKubeconfigSelection(filepath.Join(t.TempDir(), "missing"), "")

	assert.NoError(t, resolveClusterContext(scanInfo),
		"an irrelevant kubeconfig must not break an offline manifest scan")
}

func TestResolveClusterContext_KubeContextOverrideMatchesRESTTarget(t *testing.T) {
	explicitPath := writeMultiContextKubeconfig(t)
	kubeconfigFlag := flag.Lookup(controllerconfig.KubeconfigFlagName)
	require.NotNil(t, kubeconfigFlag)
	originalFlagValue := kubeconfigFlag.Value.String()
	require.NoError(t, flag.Set(controllerconfig.KubeconfigFlagName, explicitPath))
	t.Cleanup(func() {
		require.NoError(t, flag.Set(controllerconfig.KubeconfigFlagName, originalFlagValue))
	})

	restConfig, err := controllerconfig.GetConfigWithContext("context-selected")
	require.NoError(t, err)
	require.Equal(t, "https://selected.example", restConfig.Host)

	scanInfo := &cautils.ScanInfo{}
	scanInfo.SetKubeconfigSelection(explicitPath, "context-selected")
	require.NoError(t, resolveClusterContext(scanInfo))
	assert.Equal(t, "context-selected", scanInfo.GetClusterContextName())
}

func TestGetInterfacesUsesResolvedContextForTenantConfig(t *testing.T) {
	var clusterConfigRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api":
			_, _ = fmt.Fprint(w, `{"kind":"APIVersions","apiVersion":"v1","versions":["v1"]}`)
		case "/apis":
			_, _ = fmt.Fprint(w, `{"kind":"APIGroupList","apiVersion":"v1","groups":[]}`)
		case "/api/v1":
			_, _ = fmt.Fprint(w, `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"v1","resources":[{"name":"configmaps","namespaced":true,"kind":"ConfigMap","verbs":["get","list"]},{"name":"secrets","namespaced":true,"kind":"Secret","verbs":["get","list"]}]}`)
		case "/api/v1/namespaces/kubescape/configmaps":
			clusterConfigRequests.Add(1)
			_, _ = fmt.Fprint(w, `{"kind":"ConfigMapList","apiVersion":"v1","items":[{"metadata":{"name":"cloud","namespace":"kubescape"},"data":{"clusterData":"{\"cloudAPIURL\":\"https://cluster-api.example\"}"}}]}`)
		case "/api/v1/namespaces/kubescape/secrets":
			clusterConfigRequests.Add(1)
			_, _ = fmt.Fprint(w, `{"kind":"SecretList","apiVersion":"v1","items":[{"metadata":{"name":"credentials","namespace":"kubescape"},"data":{"account":"YQ=="}}]}`)
		default:
			http.Error(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`, http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	defaultPath := writeContextKubeconfig(t, "context-b", "https://b.example")
	explicitPath := writeContextKubeconfig(t, "context-a", "https://a.example")
	defaultConfig, err := clientcmd.LoadFromFile(defaultPath)
	require.NoError(t, err)
	k8sinterface.SetClusterContextName("")
	k8sinterface.SetClientConfigAPI(defaultConfig)
	originalK8SConfig := k8sinterface.K8SConfig
	originalConnected := k8sinterface.IsConnectedToCluster()
	k8sinterface.K8SConfig = &rest.Config{Host: server.URL}
	k8sinterface.SetConnectedToCluster(true)
	originalStore := getter.DefaultLocalStore
	getter.DefaultLocalStore = t.TempDir()
	originalCloudAPI := getter.GetKSCloudAPIConnector()
	getter.SetKSCloudAPIConnector(nil)
	t.Cleanup(func() {
		getter.SetKSCloudAPIConnector(originalCloudAPI)
		getter.DefaultLocalStore = originalStore
		k8sinterface.K8SConfig = originalK8SConfig
		k8sinterface.SetConnectedToCluster(originalConnected)
		k8sinterface.SetClientConfigAPI(nil)
		k8sinterface.SetClusterContextName("")
	})

	manifest := filepath.Join(t.TempDir(), "pod.yaml")
	require.NoError(t, os.WriteFile(manifest, []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"), 0o600))
	scanInfo := &cautils.ScanInfo{InputPatterns: []string{manifest}, Local: true}
	scanInfo.SetKubeconfigSelection(explicitPath, "")
	require.NoError(t, scanInfo.ResolveClusterContextName())
	interfaces, err := getInterfaces(context.Background(), scanInfo, nil)
	require.NoError(t, err)

	assert.IsType(t, &cautils.ClusterConfig{}, interfaces.tenantConfig,
		"offline scans must preserve cluster-backed tenant configuration when a cluster connection is available")
	assert.Equal(t, int32(2), clusterConfigRequests.Load(),
		"the offline path must retain both cluster-backed tenant configuration reads")
	assert.Equal(t, "a", interfaces.tenantConfig.GetAccountID())
	assert.Equal(t, "context-a", interfaces.tenantConfig.GetContextName())
}

func writeContextKubeconfig(t *testing.T, contextName, server string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	contents := fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: %[1]s
clusters:
- name: cluster
  cluster:
    server: %[2]s
contexts:
- name: %[1]s
  context:
    cluster: cluster
    user: user
users:
- name: user
  user:
    token: test
`, contextName, server)
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func writeMultiContextKubeconfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	contents := `apiVersion: v1
kind: Config
current-context: context-current
clusters:
- name: cluster-current
  cluster:
    server: https://current.example
- name: cluster-selected
  cluster:
    server: https://selected.example
contexts:
- name: context-current
  context:
    cluster: cluster-current
    user: user
- name: context-selected
  context:
    cluster: cluster-selected
    user: user
users:
- name: user
  user:
    token: test
`
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}
