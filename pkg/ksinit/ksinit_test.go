package ksinit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCreateKsObjectConnectionReturnsKubeconfigErrors(t *testing.T) {
	tests := []struct {
		name          string
		setupEnv      func(t *testing.T)
		wantErrSubstr string
	}{
		{
			name: "explicit kubeconfig path does not exist",
			setupEnv: func(t *testing.T) {
				t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing-config"))
			},
			wantErrSubstr: "no such file or directory",
		},
		{
			name: "home kubeconfig path does not exist and in cluster config is unavailable",
			setupEnv: func(t *testing.T) {
				t.Setenv("KUBECONFIG", "")
				t.Setenv("HOME", t.TempDir())
				t.Setenv("KUBERNETES_SERVICE_HOST", "")
				t.Setenv("KUBERNETES_SERVICE_PORT", "")
			},
			wantErrSubstr: "KUBERNETES_SERVICE_HOST",
		},
		{
			name: "invalid explicit kubeconfig content",
			setupEnv: func(t *testing.T) {
				configPath := filepath.Join(t.TempDir(), "config")
				require.NoError(t, os.WriteFile(configPath, []byte("bad: ["), 0600))
				t.Setenv("KUBECONFIG", configPath)
			},
			wantErrSubstr: "error loading config file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupEnv(t)

			got, err := CreateKsObjectConnection("default", time.Second)

			require.Nil(t, got)
			require.ErrorContains(t, err, tt.wantErrSubstr)
		})
	}
}

func TestCreateKsObjectConnectionSuccess(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, os.WriteFile(configPath, []byte(kubeconfigForServer("https://127.0.0.1:6443")), 0600))
	t.Setenv("KUBECONFIG", configPath)

	got, err := CreateKsObjectConnection("default", time.Second)

	require.NoError(t, err)
	require.NotNil(t, got)
}

// TestCreateKsObjectConnectionUsesHomeKubeconfig covers the default lookup:
// with no KUBECONFIG set, the kubeconfig under the home directory is used.
func TestCreateKsObjectConnectionUsesHomeKubeconfig(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".kube"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".kube", "config"), []byte(kubeconfigForServer("https://127.0.0.1:6443")), 0600))

	t.Setenv("KUBECONFIG", "")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	got, err := CreateKsObjectConnection("default", time.Second)

	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "127.0.0.1:6443", got.RESTClient().Get().URL().Host)
}

// TestCreateKsObjectConnectionIgnoresWorkingDirectoryKubeconfig guards against
// resolving the home kubeconfig to the relative path ".kube/config" when the
// home directory is unknown (HOME unset on unix, and never set on Windows).
// That made the lookup relative to the current working directory, so a
// kubeconfig dropped next to the scanned files was silently used to reach an
// arbitrary API server. Without a home directory the in-cluster configuration
// is the only remaining source.
func TestCreateKsObjectConnectionIgnoresWorkingDirectoryKubeconfig(t *testing.T) {
	workdir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(workdir, ".kube"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(workdir, ".kube", "config"), []byte(kubeconfigForServer("https://untrusted.example:6443")), 0600))
	t.Chdir(workdir)

	t.Setenv("KUBECONFIG", "")
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	got, err := CreateKsObjectConnection("default", time.Second)

	require.Nil(t, got)
	require.ErrorContains(t, err, "KUBERNETES_SERVICE_HOST")
}

func kubeconfigForServer(server string) string {
	return `apiVersion: v1
clusters:
- cluster:
    server: ` + server + `
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
kind: Config
preferences: {}
users:
- name: test-user
  user: {}`
}
