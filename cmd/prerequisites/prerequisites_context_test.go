package prerequisites

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/kubescape/sizing-checker/pkg/common"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
)

// twoContextKubeconfig has two clusters, and its current-context is ctx-a.
const twoContextKubeconfig = `apiVersion: v1
kind: Config
current-context: ctx-a
clusters:
- name: cluster-a
  cluster:
    server: https://cluster-a.example:6443
- name: cluster-b
  cluster:
    server: https://cluster-b.example:6443
contexts:
- name: ctx-a
  context:
    cluster: cluster-a
    user: tester
- name: ctx-b
  context:
    cluster: cluster-b
    user: tester
users:
- name: tester
  user:
    token: not-a-real-token
`

func writeTwoContextKubeconfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, os.WriteFile(path, []byte(twoContextKubeconfig), 0o600))
	return path
}

// runUnderRoot runs `prerequisites args...` below a root that declares
// --kube-context the way the real root command does. The real client builder
// runs; only collecting the cluster data is replaced. The stub records which
// server the client it was handed points at, then stops the command.
func runUnderRoot(t *testing.T, args ...string) (host string, collected bool, err error) {
	t.Helper()
	// Keep the client builder out of the in-cluster branch.
	t.Setenv("KUBERNETES_SERVICE_HOST", "")

	origCollect := collectClusterData
	t.Cleanup(func() { collectClusterData = origCollect })
	collectClusterData = func(_ context.Context, clientSet *kubernetes.Clientset) (*common.ClusterData, error) {
		collected = true
		host = clientSet.CoreV1().RESTClient().Get().URL().Host
		return &common.ClusterData{}, errors.New("stop after collecting")
	}

	root := &cobra.Command{Use: "kubescape", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().String("kube-context", "", "Kube context. Default will use the current-context")
	root.AddCommand(GetPreReqCmd(&mocks.MockIKubescape{}))
	root.SetArgs(append([]string{"prerequisites"}, args...))

	err = root.Execute()
	return host, collected, err
}

func TestPrerequisitesKubeContext(t *testing.T) {
	kubeconfig := writeTwoContextKubeconfig(t)

	t.Run("uses the current-context without --kube-context", func(t *testing.T) {
		host, collected, err := runUnderRoot(t, "--kubeconfig", kubeconfig)
		require.True(t, collected)
		require.ErrorContains(t, err, "stop after collecting")
		assert.Equal(t, "cluster-a.example:6443", host)
	})

	t.Run("--kube-context selects another context", func(t *testing.T) {
		host, collected, err := runUnderRoot(t, "--kubeconfig", kubeconfig, "--kube-context", "ctx-b")
		require.True(t, collected)
		require.ErrorContains(t, err, "stop after collecting")
		assert.Equal(t, "cluster-b.example:6443", host)
	})

	t.Run("an unknown --kube-context is an error, not the current-context", func(t *testing.T) {
		_, collected, err := runUnderRoot(t, "--kubeconfig", kubeconfig, "--kube-context", "nope")
		assert.False(t, collected, "the checks must not run against a cluster the user did not name")
		assert.ErrorContains(t, err, "could not create kube client")
	})
}

func TestPrerequisitesReadsKUBECONFIG(t *testing.T) {
	// No kubeconfig at the default location: only $KUBECONFIG points at one.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("KUBECONFIG", writeTwoContextKubeconfig(t))

	host, collected, err := runUnderRoot(t)
	require.True(t, collected)
	require.ErrorContains(t, err, "stop after collecting")
	assert.Equal(t, "cluster-a.example:6443", host)

	host, collected, err = runUnderRoot(t, "--kube-context", "ctx-b")
	require.True(t, collected)
	require.ErrorContains(t, err, "stop after collecting")
	assert.Equal(t, "cluster-b.example:6443", host)
}
