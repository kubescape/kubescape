package hostsensorutils

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"strings"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
)

// HostSensorCacheTtlEnvVar opts into reusing cached host sensor CRD data
// across scans. Unset (the default) disables the cache entirely, since host
// sensor data is live node state that a scan is expected to reflect.
const HostSensorCacheTtlEnvVar = "HOSTSENSOR_CACHE_TTL"

var DefaultCacheDir string

func init() {
	if home, err := os.UserHomeDir(); err == nil {
		DefaultCacheDir = filepath.Join(home, ".kubescape", "cache", "hostsensor")
	}
}

func getHostSensorCacheTtl() time.Duration {
	ttl, _ := cautils.ParseDurationEnvVar(HostSensorCacheTtlEnvVar, 0)
	return ttl
}

func getCacheDir() (string, error) {
	if DefaultCacheDir == "" {
		return "", fmt.Errorf("cache directory not configured")
	}
	return DefaultCacheDir, nil
}

// clusterIdentity returns a short hash of the API server host, so cache files
// for two clusters that happen to share a kubeconfig context name (a common
// default with kubeadm, kind and minikube) never collide.
func clusterIdentity() string {
	config := k8sinterface.GetK8sConfig()
	if config == nil || config.Host == "" {
		return "unknown"
	}
	sum := sha256.Sum256([]byte(config.Host))
	return hex.EncodeToString(sum[:])[:12]
}

func getCacheFilePath(clusterName, resourceName string) (string, error) {
	dir, err := getCacheDir()
	if err != nil {
		return "", err
	}

	safeClusterName := strings.ReplaceAll(clusterName, "/", "_")
	safeClusterName = strings.ReplaceAll(safeClusterName, ":", "_")
	safeClusterName = strings.ReplaceAll(safeClusterName, "\\", "_")
	if safeClusterName == "" {
		safeClusterName = "default"
	}

	return filepath.Join(dir, fmt.Sprintf("%s-%s-%s-v1.json.gz", safeClusterName, clusterIdentity(), resourceName)), nil
}

func loadFromCache(clusterName, resourceName string) ([]hostsensor.HostSensorDataEnvelope, error) {
	ttl := getHostSensorCacheTtl()
	if ttl <= 0 {
		return nil, os.ErrNotExist
	}

	if clusterIdentity() == "unknown" {
		// Without a resolvable API server host, every caller collapses onto the
		// same cache key; serving it would risk mixing in another cluster's data.
		return nil, os.ErrNotExist
	}

	path, err := getCacheFilePath(clusterName, resourceName)
	if err != nil {
		return nil, err
	}

	stat, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if time.Since(stat.ModTime()) > ttl {
		os.Remove(path) // #nosec G104 -- best-effort removal of an expired cache file
		return nil, fmt.Errorf("cache expired")
	}

	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	data, err := io.ReadAll(gr)
	if err != nil {
		return nil, err
	}

	var envelopes []hostsensor.HostSensorDataEnvelope
	if err := json.Unmarshal(data, &envelopes); err != nil {
		return nil, err
	}

	if len(envelopes) == 0 {
		// An empty entry carries no node data, only the absence of it. Serving it
		// keeps a node-agent outage reported as "didn't report any <resource>"
		// until the TTL runs out, long after the agent is back.
		return nil, os.ErrNotExist
	}

	logger.L().Debug("Loaded host sensor envelopes from cache", helpers.String("resource", resourceName), helpers.Int("count", len(envelopes)))
	return envelopes, nil
}

func saveToCache(clusterName, resourceName string, envelopes []hostsensor.HostSensorDataEnvelope) error {
	return saveToCacheWithRename(clusterName, resourceName, envelopes, os.Rename)
}

func saveToCacheWithRename(clusterName, resourceName string, envelopes []hostsensor.HostSensorDataEnvelope, rename func(string, string) error) error {
	if getHostSensorCacheTtl() <= 0 || clusterIdentity() == "unknown" {
		// An unresolved API server host is a shared cache key across every
		// caller in that state; loadFromCache always refuses to read it back,
		// so writing it is dead I/O and unnecessary disk data at rest.
		return nil
	}

	if len(envelopes) == 0 {
		// Nothing collected means the node-agent had nothing to report yet, not
		// that the cluster has no node data. Persisting it would pin that outage
		// for the whole TTL, and loadFromCache refuses to serve it back anyway.
		return nil
	}

	path, err := getCacheFilePath(clusterName, resourceName)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	f, err := os.CreateTemp(dir, ".hostsensor-cache-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := f.Name()

	cleanup := true
	defer func() {
		f.Close() // #nosec G104 -- best-effort close in defer cleanup
		if cleanup {
			os.Remove(tmpPath) // #nosec G104 -- best-effort removal of a temp cache file
		}
	}()

	gw := gzip.NewWriter(f)

	data, err := json.Marshal(envelopes)
	if err != nil {
		gw.Close() // #nosec G104 -- best-effort close on the error path
		return err
	}

	if _, err := gw.Write(data); err != nil {
		gw.Close() // #nosec G104 -- best-effort close on the error path
		return err
	}

	if err := gw.Close(); err != nil {
		return err
	}

	if err := f.Close(); err != nil {
		return err
	}

	if err := rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false

	logger.L().Debug("Saved host sensor envelopes to cache", helpers.String("resource", resourceName), helpers.Int("count", len(envelopes)))
	return nil
}
