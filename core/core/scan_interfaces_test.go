package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	restclient "k8s.io/client-go/rest"
)

// getInterfaces returns (componentInterfaces, error) and Kubescape.Scan already
// propagates that error, but the cluster-connection branch used to call
// logger.Fatal, which is os.Exit(1). An embedded caller could not recover from
// an unreachable cluster, and running this test against that version killed the
// test binary instead of failing.
func TestGetInterfaces_ClusterConnectionFailureReturnsError(t *testing.T) {
	originalConnected := k8sinterface.IsConnectedToCluster()
	t.Cleanup(func() { k8sinterface.SetConnectedToCluster(originalConnected) })
	k8sinterface.SetConnectedToCluster(false)

	// No input patterns means the scanning context is ContextCluster.
	scanInfo := &cautils.ScanInfo{}
	require.Equal(t, cautils.ContextCluster, scanInfo.GetScanningContext())

	_, err := getInterfaces(context.Background(), scanInfo, nil)

	require.Error(t, err, "an unreachable cluster must be reported to the caller")
	assert.ErrorIs(t, err, ErrClusterConnection)
}

// A caller that survives one unreachable cluster must be able to keep going,
// which is the whole point of returning the error rather than exiting.
func TestGetInterfaces_ClusterConnectionFailureIsRecoverable(t *testing.T) {
	originalConnected := k8sinterface.IsConnectedToCluster()
	t.Cleanup(func() { k8sinterface.SetConnectedToCluster(originalConnected) })
	k8sinterface.SetConnectedToCluster(false)

	scanInfo := &cautils.ScanInfo{}

	for i := range 3 {
		_, err := getInterfaces(context.Background(), scanInfo, nil)
		require.Errorf(t, err, "call %d must return rather than terminate", i)
	}
}

// TestGetInterfaces_ClusterScanReusesKubernetesAPI verifies that in cluster scanning context,
// kubernetesAPIFunc is called exactly ONCE instead of twice, eliminating the redundant connection
// and ensuring the exact same client instance is reused for tenant configuration.
func TestGetInterfaces_ClusterScanReusesKubernetesAPI(t *testing.T) {
	var callCount atomic.Int32
	fakeK8s := &k8sinterface.KubernetesApi{
		KubernetesClient: fake.NewSimpleClientset(),
	}

	originalKubernetesAPIFunc := kubernetesAPIFunc
	kubernetesAPIFunc = func() *k8sinterface.KubernetesApi {
		callCount.Add(1)
		return fakeK8s
	}
	t.Cleanup(func() { kubernetesAPIFunc = originalKubernetesAPIFunc })

	originalConnected := k8sinterface.IsConnectedToCluster()
	t.Cleanup(func() { k8sinterface.SetConnectedToCluster(originalConnected) })
	k8sinterface.SetConnectedToCluster(true)

	scanInfo := &cautils.ScanInfo{
		Local: true,
	}
	require.Equal(t, cautils.ContextCluster, scanInfo.GetScanningContext())

	interfaces, err := getInterfaces(context.Background(), scanInfo, nil)
	require.NoError(t, err)

	assert.Equal(t, int32(1), callCount.Load(), "kubernetesAPIFunc must be called exactly once per cluster scan")
	assert.Same(t, fakeK8s, interfaces.k8s, "the returned interface must reuse the established k8s client")
}

// TestGetInterfaces_LoopVerification verifies that across repeated successive scans in a loop,
// exactly one k8s API client is initialized per scan iteration (best case), with no state leaks.
func TestGetInterfaces_LoopVerification(t *testing.T) {
	var callCount atomic.Int32
	fakeK8s := &k8sinterface.KubernetesApi{
		KubernetesClient: fake.NewSimpleClientset(),
	}

	originalKubernetesAPIFunc := kubernetesAPIFunc
	kubernetesAPIFunc = func() *k8sinterface.KubernetesApi {
		callCount.Add(1)
		return fakeK8s
	}
	t.Cleanup(func() { kubernetesAPIFunc = originalKubernetesAPIFunc })

	originalConnected := k8sinterface.IsConnectedToCluster()
	t.Cleanup(func() { k8sinterface.SetConnectedToCluster(originalConnected) })
	k8sinterface.SetConnectedToCluster(true)

	const iterations = 5
	for i := range iterations {
		scanInfo := &cautils.ScanInfo{
			Local: true,
		}
		interfaces, err := getInterfaces(context.Background(), scanInfo, nil)
		require.NoError(t, err, "iteration %d failed", i)
		assert.Same(t, fakeK8s, interfaces.k8s, "iteration %d should use established k8s client", i)
	}

	assert.Equal(t, int32(iterations), callCount.Load(),
		"in a loop of %d scans, exactly %d k8s API calls must be made (1 per scan, not 2)", iterations, iterations)
}

// TestGetInterfaces_WorstCase_UnreachableClusterInLoop verifies that when cluster connection fails,
// getInterfaces immediately halts and returns ErrClusterConnection without making redundant calls.
func TestGetInterfaces_WorstCase_UnreachableClusterInLoop(t *testing.T) {
	var callCount atomic.Int32

	originalKubernetesAPIFunc := kubernetesAPIFunc
	kubernetesAPIFunc = func() *k8sinterface.KubernetesApi {
		callCount.Add(1)
		return nil
	}
	t.Cleanup(func() { kubernetesAPIFunc = originalKubernetesAPIFunc })

	const iterations = 5
	for i := range iterations {
		scanInfo := &cautils.ScanInfo{
			Local: true,
		}
		_, err := getInterfaces(context.Background(), scanInfo, nil)
		require.ErrorIs(t, err, ErrClusterConnection, "iteration %d must fail with ErrClusterConnection", i)
	}

	assert.Equal(t, int32(iterations), callCount.Load(),
		"failed connections must fail fast with exactly 1 check per scan")
}

// TestGetInterfaces_OfflineScan_ClusterDisconnectedFallback verifies that offline manifest scans
// cleanly fall back to local configuration when no cluster connection is available.
func TestGetInterfaces_OfflineScan_ClusterDisconnectedFallback(t *testing.T) {
	originalKubernetesAPIFunc := kubernetesAPIFunc
	kubernetesAPIFunc = func() *k8sinterface.KubernetesApi {
		return nil
	}
	t.Cleanup(func() { kubernetesAPIFunc = originalKubernetesAPIFunc })

	originalConnected := k8sinterface.IsConnectedToCluster()
	t.Cleanup(func() { k8sinterface.SetConnectedToCluster(originalConnected) })
	k8sinterface.SetConnectedToCluster(false)

	scanInfo := &cautils.ScanInfo{
		InputPatterns: []string{"test.yaml"},
		Local:         true,
	}
	require.NotEqual(t, cautils.ContextCluster, scanInfo.GetScanningContext())

	interfaces, err := getInterfaces(context.Background(), scanInfo, nil)
	require.NoError(t, err)
	assert.Nil(t, interfaces.k8s, "offline scan must not retain k8s interface")
	assert.IsType(t, &cautils.LocalConfig{}, interfaces.tenantConfig, "offline scan without cluster must yield LocalConfig")
}

// TestGetInterfaces_NonClusterScanWithResolvedTenantConfigSkipsKubernetesAPI verifies that when scanning non-cluster
// targets (e.g. files/manifests) and all required tenant settings (AccountID, AccessKey, CloudReportURL, CloudAPIURL)
// are already resolved locally, kubernetesAPIFunc is never called.
func TestGetInterfaces_NonClusterScanWithResolvedTenantConfigSkipsKubernetesAPI(t *testing.T) {
	isolateCachedConfigTest(t)

	// Set backend URLs in env so local resolution succeeds
	t.Setenv("KS_CLOUD_API_URL", "https://api.kubescape.cloud")
	t.Setenv("KS_CLOUD_REPORT_URL", "https://report.kubescape.cloud")

	var callCount atomic.Int32
	originalKubernetesAPIFunc := kubernetesAPIFunc
	kubernetesAPIFunc = func() *k8sinterface.KubernetesApi {
		callCount.Add(1)
		return nil
	}
	t.Cleanup(func() { kubernetesAPIFunc = originalKubernetesAPIFunc })

	originalConnected := k8sinterface.IsConnectedToCluster()
	t.Cleanup(func() { k8sinterface.SetConnectedToCluster(originalConnected) })
	k8sinterface.SetConnectedToCluster(true)

	scanInfo := &cautils.ScanInfo{
		AccountID:     "11111111-2222-3333-4444-555555555555",
		AccessKey:     "my-access-key",
		InputPatterns: []string{"manifest.yaml"},
		Local:         true,
	}
	require.NotEqual(t, cautils.ContextCluster, scanInfo.GetScanningContext())

	interfaces, err := getInterfaces(context.Background(), scanInfo, nil)
	require.NoError(t, err)
	assert.Nil(t, interfaces.k8s)
	assert.Equal(t, int32(0), callCount.Load(), "kubernetesAPIFunc must not be called when all tenant settings are already resolved locally")
	assert.IsType(t, &cautils.LocalConfig{}, interfaces.tenantConfig, "fully resolved local tenant config must yield LocalConfig")
	assert.Equal(t, "11111111-2222-3333-4444-555555555555", interfaces.tenantConfig.GetAccountID())
	assert.Equal(t, "my-access-key", interfaces.tenantConfig.GetAccessKey())
	assert.Equal(t, "https://report.kubescape.cloud", interfaces.tenantConfig.GetCloudReportURL())
	assert.Equal(t, "https://api.kubescape.cloud", interfaces.tenantConfig.GetCloudAPIURL())
}

// TestGetInterfaces_NonClusterScan_AccountOnlyPreservesClusterFallback verifies that
// when scanning non-cluster targets with only an AccountID supplied (incomplete configuration),
// the cluster fallback is preserved to retrieve the access key and backend URLs from
// the cluster's Secret and ConfigMap fixtures.
func TestGetInterfaces_NonClusterScan_AccountOnlyPreservesClusterFallback(t *testing.T) {
	isolateCachedConfigTest(t)

	const (
		expectedAccountID = "11111111-2222-3333-4444-555555555555"
		expectedAccessKey = "secret-access-key-123"
		expectedReportURL = "https://report.kubescape.cloud"
		expectedAPIURL    = "https://api.kubescape.cloud"
		ksNamespace       = "kubescape"
	)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubescape-credentials",
			Namespace: ksNamespace,
			Labels: map[string]string{
				"kubescape.io/infra": "credentials",
			},
		},
		Data: map[string][]byte{
			"account":   []byte(expectedAccountID),
			"accessKey": []byte(expectedAccessKey),
		},
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubescape-config",
			Namespace: ksNamespace,
			Labels: map[string]string{
				"kubescape.io/infra": "config",
			},
		},
		Data: map[string]string{
			"clusterData": fmt.Sprintf(`{"cloudReportURL":%q,"cloudAPIURL":%q}`, expectedReportURL, expectedAPIURL),
		},
	}

	fakeClient := fake.NewSimpleClientset(secret, configMap)
	fakeK8s := &k8sinterface.KubernetesApi{
		KubernetesClient: fakeClient,
	}

	var callCount atomic.Int32
	originalKubernetesAPIFunc := kubernetesAPIFunc
	kubernetesAPIFunc = func() *k8sinterface.KubernetesApi {
		callCount.Add(1)
		return fakeK8s
	}
	t.Cleanup(func() { kubernetesAPIFunc = originalKubernetesAPIFunc })

	originalK8SConfig := k8sinterface.K8SConfig
	t.Cleanup(func() { k8sinterface.K8SConfig = originalK8SConfig })
	k8sinterface.K8SConfig = &restclient.Config{}

	originalConnected := k8sinterface.IsConnectedToCluster()
	t.Cleanup(func() { k8sinterface.SetConnectedToCluster(originalConnected) })
	k8sinterface.SetConnectedToCluster(true)

	// Scan supplied a valid account UUID but no access key or URLs. Local: true avoids version-check traffic.
	scanInfo := &cautils.ScanInfo{
		AccountID:     expectedAccountID,
		InputPatterns: []string{"manifest.yaml"},
		Local:         true,
	}
	require.NotEqual(t, cautils.ContextCluster, scanInfo.GetScanningContext())

	interfaces, err := getInterfaces(context.Background(), scanInfo, nil)
	require.NoError(t, err)

	assert.Equal(t, int32(1), callCount.Load(), "kubernetesAPIFunc must be called when tenant settings are incomplete")
	assert.IsType(t, &cautils.ClusterConfig{}, interfaces.tenantConfig, "tenant config must fall back to ClusterConfig")
	assert.Equal(t, expectedAccessKey, interfaces.tenantConfig.GetAccessKey(), "access key must be loaded from cluster Secret")
	assert.Equal(t, expectedReportURL, interfaces.tenantConfig.GetCloudReportURL(), "report URL must be loaded from cluster ConfigMap")
	assert.Equal(t, expectedAPIURL, interfaces.tenantConfig.GetCloudAPIURL(), "API URL must be loaded from cluster ConfigMap")

	// Normal submission decision checked separately with fresh non-local ScanInfo and explicit submission enabled
	submitScanInfo := &cautils.ScanInfo{}
	submitScanInfo.Submit.SetBool(true)
	setSubmitBehavior(submitScanInfo, interfaces.tenantConfig)
	assert.True(t, submitScanInfo.Submit.GetBool(), "explicit submission must remain enabled when credentials and report URL are loaded from cluster")
}

// TestGetInterfaces_NonClusterScan_CachedAccountMismatchPreservesClusterFallback verifies that
// when the local cache contains credentials for Account A, but an account-only scan is run
// for Account B, getInterfaces does not accept localTenantConfig with mismatched credentials,
// but falls back to the Kubernetes cluster Secret to retrieve Account B's credentials.
func TestGetInterfaces_NonClusterScan_CachedAccountMismatchPreservesClusterFallback(t *testing.T) {
	isolateCachedConfigTest(t)

	const (
		cachedAccountID = "aaaa1111-2222-3333-4444-555555555555"
		cachedAccessKey = "cached-access-key-A"
		targetAccountID = "bbbb1111-2222-3333-4444-555555555555"
		clusterKey      = "cluster-access-key-B"
		reportURL       = "https://report.kubescape.cloud"
		apiURL          = "https://api.kubescape.cloud"
		ksNamespace     = "kubescape"
	)

	// Populate the local cache file with Account A and its key
	cachedData, err := json.Marshal(&cautils.ConfigObj{ // #nosec G117 -- test fixture; marshals a mock config object
		AccountID:      cachedAccountID,
		AccessKey:      cachedAccessKey,
		CloudReportURL: reportURL,
		CloudAPIURL:    apiURL,
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cautils.ConfigFileFullPath(), cachedData, 0o600))

	// Cluster has Secret and ConfigMap for Account B
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubescape-credentials",
			Namespace: ksNamespace,
			Labels: map[string]string{
				"kubescape.io/infra": "credentials",
			},
		},
		Data: map[string][]byte{
			"account":   []byte(targetAccountID),
			"accessKey": []byte(clusterKey),
		},
	}
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubescape-config",
			Namespace: ksNamespace,
			Labels: map[string]string{
				"kubescape.io/infra": "config",
			},
		},
		Data: map[string]string{
			"clusterData": fmt.Sprintf(`{"cloudReportURL":%q,"cloudAPIURL":%q}`, reportURL, apiURL),
		},
	}

	fakeClient := fake.NewSimpleClientset(secret, configMap)
	fakeK8s := &k8sinterface.KubernetesApi{
		KubernetesClient: fakeClient,
	}

	var callCount atomic.Int32
	originalKubernetesAPIFunc := kubernetesAPIFunc
	kubernetesAPIFunc = func() *k8sinterface.KubernetesApi {
		callCount.Add(1)
		return fakeK8s
	}
	t.Cleanup(func() { kubernetesAPIFunc = originalKubernetesAPIFunc })

	originalK8SConfig := k8sinterface.K8SConfig
	t.Cleanup(func() { k8sinterface.K8SConfig = originalK8SConfig })
	k8sinterface.K8SConfig = &restclient.Config{}

	originalConnected := k8sinterface.IsConnectedToCluster()
	t.Cleanup(func() { k8sinterface.SetConnectedToCluster(originalConnected) })
	k8sinterface.SetConnectedToCluster(true)

	// Scan specifies Account B only (account override without matching access key).
	scanInfo := &cautils.ScanInfo{
		AccountID:     targetAccountID,
		InputPatterns: []string{"manifest.yaml"},
		Local:         true,
	}

	interfaces, err := getInterfaces(context.Background(), scanInfo, nil)
	require.NoError(t, err)

	assert.Equal(t, int32(1), callCount.Load(), "kubernetesAPIFunc must be called when account override has no matching key")
	assert.IsType(t, &cautils.ClusterConfig{}, interfaces.tenantConfig)
	assert.Equal(t, targetAccountID, interfaces.tenantConfig.GetAccountID())
	assert.Equal(t, clusterKey, interfaces.tenantConfig.GetAccessKey(), "must use cluster secret key, not mismatched cached key")
}

// TestGetInterfaces_NonClusterScan_NoFlagsUsesPairedCachedConfigAndSkipsKubernetesAPI verifies that
// when no account or access key flags/env vars are provided and local cache contains all required
// paired settings, kubernetesAPIFunc is skipped.
func TestGetInterfaces_NonClusterScan_NoFlagsUsesPairedCachedConfigAndSkipsKubernetesAPI(t *testing.T) {
	isolateCachedConfigTest(t)

	const (
		cachedAccountID = "aaaa1111-2222-3333-4444-555555555555"
		cachedAccessKey = "cached-access-key-A"
		reportURL       = "https://report.kubescape.cloud"
		apiURL          = "https://api.kubescape.cloud"
	)

	cachedData, err := json.Marshal(&cautils.ConfigObj{ // #nosec G117 -- test fixture; marshals a mock config object
		AccountID:      cachedAccountID,
		AccessKey:      cachedAccessKey,
		CloudReportURL: reportURL,
		CloudAPIURL:    apiURL,
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cautils.ConfigFileFullPath(), cachedData, 0o600))

	var callCount atomic.Int32
	originalKubernetesAPIFunc := kubernetesAPIFunc
	kubernetesAPIFunc = func() *k8sinterface.KubernetesApi {
		callCount.Add(1)
		return nil
	}
	t.Cleanup(func() { kubernetesAPIFunc = originalKubernetesAPIFunc })

	originalConnected := k8sinterface.IsConnectedToCluster()
	t.Cleanup(func() { k8sinterface.SetConnectedToCluster(originalConnected) })
	k8sinterface.SetConnectedToCluster(true)

	// No flags provided
	scanInfo := &cautils.ScanInfo{
		InputPatterns: []string{"manifest.yaml"},
		Local:         true,
	}

	interfaces, err := getInterfaces(context.Background(), scanInfo, nil)
	require.NoError(t, err)

	assert.Equal(t, int32(0), callCount.Load(), "kubernetesAPIFunc must not be called when cached config is complete and paired")
	assert.IsType(t, &cautils.LocalConfig{}, interfaces.tenantConfig)
	assert.Equal(t, cachedAccountID, interfaces.tenantConfig.GetAccountID())
	assert.Equal(t, cachedAccessKey, interfaces.tenantConfig.GetAccessKey())
}
