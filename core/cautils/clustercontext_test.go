package cautils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/require"
)

// writeThreeContextKubeconfig extends writeScanInfoMultiContextKubeconfig's two contexts
// with a third, distinct one, so a test can exercise a genuine intervening context change
// (switching to a context that differs from both the original and the entered one) rather
// than a no-op switch back to a context that's already active.
func writeThreeContextKubeconfig(t *testing.T) string {
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
- name: cluster-third
  cluster:
    server: https://third.example
contexts:
- name: context-current
  context:
    cluster: cluster-current
    user: user
- name: context-selected
  context:
    cluster: cluster-selected
    user: user
- name: context-third
  context:
    cluster: cluster-third
    user: user
users:
- name: user
  user:
    token: test
`
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

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

	path := writeThreeContextKubeconfig(t)
	oldKubeconfig, hadKubeconfig := os.LookupEnv("KUBECONFIG")
	require.NoError(t, os.Setenv("KUBECONFIG", path))
	t.Cleanup(func() {
		if hadKubeconfig {
			_ = os.Setenv("KUBECONFIG", oldKubeconfig)
		} else {
			_ = os.Unsetenv("KUBECONFIG")
		}
	})

	k8sinterface.SetClusterContextName("context-current")
	leave := EnterClusterContext("context-selected")

	// leave captured "context-current" as the context to restore at the moment
	// EnterClusterContext was called. Switch to a third, previously-untouched context
	// before calling leave, so restoration is checked against a genuine intervening
	// change rather than a no-op switch back to the context that was already active.
	k8sinterface.SetClusterContextName("context-third")
	require.Equal(t, "https://third.example", k8sinterface.GetK8sConfig().Host)

	leave()
	require.Equal(t, "context-current", k8sinterface.GetContextName())
	require.Equal(t, "https://current.example", k8sinterface.GetK8sConfig().Host,
		"leave() restored the context name but not the config that goes with it")
}
