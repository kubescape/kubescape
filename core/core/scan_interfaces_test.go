package core

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"
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
