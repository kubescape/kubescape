package hostsensorutils

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

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

// writeCacheEntry writes a cache file directly, bypassing the saveToCache
// guards, to stand in for an entry left behind by an earlier version.
func writeCacheEntry(t *testing.T, clusterName, resourceName string, envelopes []hostsensor.HostSensorDataEnvelope) {
	t.Helper()

	path, err := getCacheFilePath(clusterName, resourceName)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))

	data, err := json.Marshal(envelopes)
	require.NoError(t, err)

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, err = gw.Write(data)
	require.NoError(t, err)
	require.NoError(t, gw.Close())
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0600))
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

func TestSaveToCache_ConcurrentWritersUseDistinctTemporaryFiles(t *testing.T) {
	withTempCacheDir(t)
	t.Setenv(HostSensorCacheTtlEnvVar, "1h")
	withK8sHost(t, "https://cluster-a.example.com")

	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	renameAtBarrier := func(oldPath, newPath string) error {
		ready <- struct{}{}
		<-release
		return os.Rename(oldPath, newPath)
	}

	errCh := make(chan error, 2)
	for _, name := range []string{"node-a", "node-b"} {
		env := hostsensor.HostSensorDataEnvelope{}
		env.SetName(name)
		go func() {
			errCh <- saveToCacheWithRename("ctx", "KubeletInfo", []hostsensor.HostSensorDataEnvelope{env}, renameAtBarrier)
		}()
	}

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for range 2 {
		select {
		case <-ready:
		case err := <-errCh:
			require.NoError(t, err, "writer exited before reaching rename")
			t.Fatal("writer exited before reaching rename")
		case <-timer.C:
			t.Fatal("writers did not reach rename barrier")
		}
	}
	close(release)
	released = true
	require.NoError(t, <-errCh)
	require.NoError(t, <-errCh)

	got, err := loadFromCache("ctx", "KubeletInfo")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Contains(t, []string{"node-a", "node-b"}, got[0].GetName())
}

// TestSaveToCache_SkipsEmptyEnvelopes guards against a node-agent outage being
// pinned for the whole TTL: an empty collection records the absence of node
// data, which every later scan in the window would then serve as fact.
func TestSaveToCache_SkipsEmptyEnvelopes(t *testing.T) {
	withTempCacheDir(t)
	t.Setenv(HostSensorCacheTtlEnvVar, "1h")
	withK8sHost(t, "https://cluster-a.example.com")

	require.NoError(t, saveToCache("ctx", "KubeletInfo", nil))
	require.NoError(t, saveToCache("ctx", "KubeletInfo", []hostsensor.HostSensorDataEnvelope{}))

	path, err := getCacheFilePath("ctx", "KubeletInfo")
	require.NoError(t, err)
	_, statErr := os.Stat(path)
	assert.ErrorIs(t, statErr, os.ErrNotExist, "an empty collection must not be persisted")
}

// An empty entry already on disk must read as a miss so the scan collects
// again, rather than as a cluster with no node data.
func TestLoadFromCache_EmptyEntryIsTreatedAsMiss(t *testing.T) {
	withTempCacheDir(t)
	t.Setenv(HostSensorCacheTtlEnvVar, "1h")
	withK8sHost(t, "https://cluster-a.example.com")

	writeCacheEntry(t, "ctx", "KubeletInfo", []hostsensor.HostSensorDataEnvelope{})

	_, err := loadFromCache("ctx", "KubeletInfo")
	assert.ErrorIs(t, err, os.ErrNotExist)
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
