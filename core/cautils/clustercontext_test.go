package cautils

import (
	"os"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/require"
)

// resetClusterContextState clears the k8sinterface globals EnterClusterContext relies on,
// so this test is independent of whatever ran before/after it in the same package.
func resetClusterContextState(t *testing.T) {
	t.Helper()
	k8sinterface.SetClusterContextName("")
	k8sinterface.K8SConfig = nil
	k8sinterface.SetClientConfigAPI(nil)
	k8sinterface.SetConnectedToCluster(true)
}

func TestEnterClusterContext_SwitchesAndRestores(t *testing.T) {
	resetClusterContextState(t)
	t.Cleanup(func() { resetClusterContextState(t) })

	path := writeScanInfoMultiContextKubeconfig(t)
	oldKubeconfig, hadKubeconfig := os.LookupEnv("KUBECONFIG")
	require.NoError(t, os.Setenv("KUBECONFIG", path))
	t.Cleanup(func() {
		if hadKubeconfig {
			_ = os.Setenv("KUBECONFIG", oldKubeconfig)
		} else {
			_ = os.Unsetenv("KUBECONFIG")
		}
	})

	// Simulate cmd/root.go's startup: the CLI's own single-cluster context, set once
	// before any fleet-style iteration begins.
	k8sinterface.SetClusterContextName("context-current")
	require.True(t, k8sinterface.IsConnectedToCluster())
	require.Equal(t, "https://current.example", k8sinterface.GetK8sConfig().Host)

	leave := EnterClusterContext("context-selected")
	require.Equal(t, "context-selected", k8sinterface.GetContextName())
	require.True(t, k8sinterface.IsConnectedToCluster())
	require.Equal(t, "https://selected.example", k8sinterface.GetK8sConfig().Host,
		"EnterClusterContext did not switch to the target context's config")

	leave()
	require.Equal(t, "context-current", k8sinterface.GetContextName(),
		"leave() did not restore the context that was active before EnterClusterContext")
	require.True(t, k8sinterface.IsConnectedToCluster())
	require.Equal(t, "https://current.example", k8sinterface.GetK8sConfig().Host,
		"leave() restored the context name but not the config that goes with it")
}

// A scan against the entered context can fail partway; leave must still be able to run
// from a deferred call regardless of what the scan itself did to state in between. This
// only exercises that leave() is safe to call after arbitrary intervening
// SetClusterContextName calls, not actual panic recovery (which is the caller's job).
func TestEnterClusterContext_LeaveAfterInterveningContextChange(t *testing.T) {
	resetClusterContextState(t)
	t.Cleanup(func() { resetClusterContextState(t) })

	path := writeScanInfoMultiContextKubeconfig(t)
	require.NoError(t, os.Setenv("KUBECONFIG", path))
	t.Cleanup(func() { _ = os.Unsetenv("KUBECONFIG") })

	k8sinterface.SetClusterContextName("context-current")
	leave := EnterClusterContext("context-selected")

	// leave captured "context-current" as the context to restore at the moment
	// EnterClusterContext was called, regardless of what happens to the active
	// context afterward.
	k8sinterface.SetClusterContextName("context-selected")

	leave()
	require.Equal(t, "context-current", k8sinterface.GetContextName())
}
