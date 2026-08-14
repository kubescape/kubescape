package hostsensorutils

import (
	"os"
	"testing"

	restclient "k8s.io/client-go/rest"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withK8sHost(t *testing.T, host string) {
	t.Helper()
	original := k8sinterface.K8SConfig
	t.Cleanup(func() { k8sinterface.K8SConfig = original })
	// Always set a non-nil config, even for the empty-host case: a nil
	// K8SConfig makes IsConnectedToCluster() lazily load ~/.kube/config from
	// disk, which on a machine that has one would resolve a real host and
	// defeat the "unresolved identity" scenario this helper is meant to set up.
	k8sinterface.K8SConfig = &restclient.Config{Host: host}
}

func withTempCacheDir(t *testing.T) {
	t.Helper()
	original := DefaultCacheDir
	t.Cleanup(func() { DefaultCacheDir = original })
	DefaultCacheDir = t.TempDir()
}

// TestLoadFromCache_DisabledByDefault guards against host sensor data being
// written to or served from disk when HOSTSENSOR_CACHE_TTL is unset: caching
// used to be unconditional, which meant a scan could silently report node
// state from up to two hours earlier, and wrote host data to disk even for
// users who never opted into caching at all.
func TestLoadFromCache_DisabledByDefault(t *testing.T) {
	withTempCacheDir(t)
	t.Setenv(HostSensorCacheTtlEnvVar, "")
	withK8sHost(t, "https://cluster-a.example.com")

	env := hostsensor.HostSensorDataEnvelope{}
	env.SetName("node-a")
	require.NoError(t, saveToCache("ctx", "KubeletInfo", []hostsensor.HostSensorDataEnvelope{env}))

	path, err := getCacheFilePath("ctx", "KubeletInfo")
	require.NoError(t, err)
	_, statErr := os.Stat(path)
	assert.ErrorIs(t, statErr, os.ErrNotExist, "saveToCache must not write to disk when caching is disabled")

	_, err = loadFromCache("ctx", "KubeletInfo")
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// TestCacheFilePath_DiffersByClusterHost guards against two clusters that
// share a kubeconfig context name (the kubeadm/kind/minikube default)
// colliding on the same cache file.
func TestCacheFilePath_DiffersByClusterHost(t *testing.T) {
	withTempCacheDir(t)

	withK8sHost(t, "https://cluster-a.example.com")
	pathA, err := getCacheFilePath("kubernetes-admin@kubernetes", "KubeletInfo")
	require.NoError(t, err)

	withK8sHost(t, "https://cluster-b.example.com")
	pathB, err := getCacheFilePath("kubernetes-admin@kubernetes", "KubeletInfo")
	require.NoError(t, err)

	assert.NotEqual(t, pathA, pathB)
}

// TestHostSensorCache_OptInRoundTrip verifies that with the opt-in TTL set,
// data written by one cluster is not readable under a different cluster's
// identity, even when the context name is identical.
func TestHostSensorCache_OptInRoundTrip(t *testing.T) {
	withTempCacheDir(t)
	t.Setenv(HostSensorCacheTtlEnvVar, "1h")

	withK8sHost(t, "https://cluster-a.example.com")
	env := hostsensor.HostSensorDataEnvelope{}
	env.SetName("node-a")
	require.NoError(t, saveToCache("kubernetes-admin@kubernetes", "KubeletInfo", []hostsensor.HostSensorDataEnvelope{env}))

	got, err := loadFromCache("kubernetes-admin@kubernetes", "KubeletInfo")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "node-a", got[0].GetName())

	withK8sHost(t, "https://cluster-b.example.com")
	_, err = loadFromCache("kubernetes-admin@kubernetes", "KubeletInfo")
	assert.Error(t, err, "cluster B must not read cluster A's cached host data")
}

// TestLoadFromCache_UnresolvedClusterIdentityIsRejected guards against the
// "unknown" fallback in clusterIdentity acting as a shared cache key: every
// caller with no resolvable API server host would otherwise land on the same
// file, and a read there could return another cluster's data. saveToCache is
// expected to skip the write entirely, since loadFromCache would never serve
// it back.
func TestLoadFromCache_UnresolvedClusterIdentityIsRejected(t *testing.T) {
	withTempCacheDir(t)
	t.Setenv(HostSensorCacheTtlEnvVar, "1h")
	withK8sHost(t, "")

	env := hostsensor.HostSensorDataEnvelope{}
	env.SetName("node-a")
	require.NoError(t, saveToCache("kubernetes-admin@kubernetes", "KubeletInfo", []hostsensor.HostSensorDataEnvelope{env}))

	path, err := getCacheFilePath("kubernetes-admin@kubernetes", "KubeletInfo")
	require.NoError(t, err)
	_, statErr := os.Stat(path)
	assert.ErrorIs(t, statErr, os.ErrNotExist, "saveToCache must not write to disk when cluster identity cannot be resolved")

	_, err = loadFromCache("kubernetes-admin@kubernetes", "KubeletInfo")
	assert.ErrorIs(t, err, os.ErrNotExist)
}
