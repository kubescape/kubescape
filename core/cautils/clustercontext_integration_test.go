package cautils

import (
	"context"
	"os"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// groundTruthKubeSystemUID builds a client directly from clientcmd for contextName,
// bypassing k8sinterface entirely, and returns that cluster's kube-system namespace UID.
// This is the independent reference the integration test below checks
// EnterClusterContext + k8sinterface.NewKubernetesApi against: if it only compared two
// k8sinterface-derived values against each other, a bug that made both wrong in the same
// way (e.g. both stuck on a third, unrelated context) could still pass.
func groundTruthKubeSystemUID(t *testing.T, contextName string) string {
	t.Helper()
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{CurrentContext: contextName}
	restConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides).ClientConfig()
	require.NoError(t, err)

	clientset, err := kubernetes.NewForConfig(restConfig)
	require.NoError(t, err)

	ns, err := clientset.CoreV1().Namespaces().Get(context.Background(), "kube-system", metav1.GetOptions{})
	require.NoError(t, err)
	return string(ns.UID)
}

// TestEnterClusterContext_TwoRealClusters is the two-kind-cluster regression case the
// isolation fix exists for: scan two real clusters in a row, in one process, and confirm
// the second scan actually observes the second cluster - not the first cluster's config,
// discovery snapshot, or connection state left over from the first.
//
// Opt-in and skipped by default: needs `kind create cluster --name fleet-test-a` and
// `--name fleet-test-b` already running (KUBESCAPE_INTEGRATION_KIND=1 to enable).
func TestEnterClusterContext_TwoRealClusters(t *testing.T) {
	if os.Getenv("KUBESCAPE_INTEGRATION_KIND") == "" {
		t.Skip("set KUBESCAPE_INTEGRATION_KIND=1 with kind clusters fleet-test-a and fleet-test-b running to enable")
	}

	const contextA = "kind-fleet-test-a"
	const contextB = "kind-fleet-test-b"

	resetClusterContextState(t)
	t.Cleanup(func() { resetClusterContextState(t) })

	// Use the default kubeconfig location (where `kind` registers cluster contexts),
	// regardless of what the environment's KUBECONFIG happens to be set to elsewhere in
	// the test run.
	oldKubeconfig, hadKubeconfig := os.LookupEnv("KUBECONFIG")
	require.NoError(t, os.Unsetenv("KUBECONFIG"))
	t.Cleanup(func() {
		if hadKubeconfig {
			_ = os.Setenv("KUBECONFIG", oldKubeconfig)
		}
	})

	wantUIDA := groundTruthKubeSystemUID(t, contextA)
	wantUIDB := groundTruthKubeSystemUID(t, contextB)
	require.NotEqual(t, wantUIDA, wantUIDB, "test setup: the two kind clusters must be distinct")

	// Simulate cmd/root.go's single startup call, same as every non-fleet invocation.
	k8sinterface.SetClusterContextName(contextA)

	leaveA := EnterClusterContext(contextA)
	gotUIDA := fetchKubeSystemUID(t)
	require.Equal(t, wantUIDA, gotUIDA, "scan of context A did not observe cluster A")
	leaveA()

	leaveB := EnterClusterContext(contextB)
	gotUIDB := fetchKubeSystemUID(t)
	require.Equal(t, wantUIDB, gotUIDB,
		"scan of context B observed cluster A's data (uid=%s) instead of cluster B's (uid=%s) - "+
			"this is the cross-cluster state leak the isolation fix exists to close", gotUIDA, wantUIDB)
	leaveB()
}

// fetchKubeSystemUID reads kube-system's UID through the same k8sinterface.NewKubernetesApi
// path core/core's scan setup (getKubernetesApi) uses, so this exercises the production
// code the bug actually lives in rather than a client built specifically for the test.
func fetchKubeSystemUID(t *testing.T) string {
	t.Helper()
	require.True(t, k8sinterface.IsConnectedToCluster())
	k8sAPI := k8sinterface.NewKubernetesApi()
	ns, err := k8sAPI.KubernetesClient.CoreV1().Namespaces().Get(context.Background(), "kube-system", metav1.GetOptions{})
	require.NoError(t, err)
	return string(ns.UID)
}
