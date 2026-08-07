package core

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	assert.ErrorContains(t, err, "failed connecting to Kubernetes cluster")
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
