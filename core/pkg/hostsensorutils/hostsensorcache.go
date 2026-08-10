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
	"github.com/kubescape/kubescape/v3/core/cautils"
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
		os.Remove(path)
		return nil, fmt.Errorf("cache expired")
	}

	f, err := os.Open(path)
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

	logger.L().Debug("Loaded host sensor envelopes from cache", helpers.String("resource", resourceName), helpers.Int("count", len(envelopes)))
	return envelopes, nil
}

func saveToCache(clusterName, resourceName string, envelopes []hostsensor.HostSensorDataEnvelope) error {
	path, err := getCacheFilePath(clusterName, resourceName)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	tmpPath := path + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	cleanup := true
	defer func() {
		f.Close()
		if cleanup {
			os.Remove(tmpPath)
		}
	}()

	gw := gzip.NewWriter(f)

	data, err := json.Marshal(envelopes)
	if err != nil {
		gw.Close()
		return err
	}

	if _, err := gw.Write(data); err != nil {
		gw.Close()
		return err
	}

	if err := gw.Close(); err != nil {
		return err
	}

	if err := f.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false

	logger.L().Debug("Saved host sensor envelopes to cache", helpers.String("resource", resourceName), helpers.Int("count", len(envelopes)))
	return nil
}
