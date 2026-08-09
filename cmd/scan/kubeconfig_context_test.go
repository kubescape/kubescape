package scan

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	controllerconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
)

func TestGetScanCommand_CapturesExplicitKubeconfigSelection(t *testing.T) {
	explicitPath := writeScanKubeconfig(t, "context-a")
	restoreKubeconfigFlag(t)

	mockKubescape := &imageScanCaptureKubescape{}
	cmd := GetScanCommand(mockKubescape)
	cmd.SetArgs([]string{"image", "--kubeconfig", explicitPath, "nginx:latest"})
	require.NoError(t, cmd.Execute())
	require.NotNil(t, mockKubescape.scanInfo)

	require.NoError(t, mockKubescape.scanInfo.ResolveClusterContextName())
	assert.Equal(t, "context-a", mockKubescape.scanInfo.GetClusterContextName())
}

func TestGetScanCommand_ImageScanDoesNotLoadIrrelevantKubeconfig(t *testing.T) {
	restoreKubeconfigFlag(t)

	mockKubescape := &imageScanCaptureKubescape{}
	cmd := GetScanCommand(mockKubescape)
	cmd.SetArgs([]string{
		"image",
		"--kubeconfig", filepath.Join(t.TempDir(), "missing"),
		"nginx:latest",
	})

	assert.NoError(t, cmd.Execute())
}

func TestGetScanCommand_CapturesKubeContextOverride(t *testing.T) {
	explicitPath := writeScanMultiContextKubeconfig(t)
	restoreKubeconfigFlag(t)

	mockKubescape := &imageScanCaptureKubescape{}
	rootCmd := &cobra.Command{Use: "kubescape"}
	rootCmd.PersistentFlags().String("kube-context", "", "")
	rootCmd.AddCommand(GetScanCommand(mockKubescape))
	rootCmd.SetArgs([]string{
		"scan", "image",
		"--kubeconfig", explicitPath,
		"--kube-context", "context-selected",
		"nginx:latest",
	})
	require.NoError(t, rootCmd.Execute())
	require.NotNil(t, mockKubescape.scanInfo)

	require.NoError(t, mockKubescape.scanInfo.ResolveClusterContextName())
	assert.Equal(t, "context-selected", mockKubescape.scanInfo.GetClusterContextName())
}

func TestGetScanCommand_CapturesKubeContextOverrideWithDefaultKubeconfig(t *testing.T) {
	defaultPath := writeScanMultiContextKubeconfig(t)
	t.Setenv("KUBECONFIG", defaultPath)
	restoreKubeconfigFlag(t)

	mockKubescape := &imageScanCaptureKubescape{}
	rootCmd := &cobra.Command{Use: "kubescape"}
	rootCmd.PersistentFlags().String("kube-context", "", "")
	rootCmd.AddCommand(GetScanCommand(mockKubescape))
	rootCmd.SetArgs([]string{
		"scan", "image",
		"--kube-context", "context-selected",
		"nginx:latest",
	})
	require.NoError(t, rootCmd.Execute())
	require.NotNil(t, mockKubescape.scanInfo)

	require.NoError(t, mockKubescape.scanInfo.ResolveClusterContextName())
	assert.Equal(t, "context-selected", mockKubescape.scanInfo.GetClusterContextName())
}

func restoreKubeconfigFlag(t *testing.T) {
	t.Helper()
	kubeconfigFlag := flag.Lookup(controllerconfig.KubeconfigFlagName)
	require.NotNil(t, kubeconfigFlag)
	original := kubeconfigFlag.Value.String()
	t.Cleanup(func() {
		require.NoError(t, flag.Set(controllerconfig.KubeconfigFlagName, original))
	})
}

func writeScanKubeconfig(t *testing.T, contextName string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	contents := fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: %[1]s
clusters:
- name: cluster
  cluster:
    server: https://a.example
contexts:
- name: %[1]s
  context:
    cluster: cluster
    user: user
users:
- name: user
  user:
    token: test
`, contextName)
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func writeScanMultiContextKubeconfig(t *testing.T) string {
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
