package hostsensorutils

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"strings"
	"time"
)

var DefaultCacheDir string

func init() {
	if home, err := os.UserHomeDir(); err == nil {
		DefaultCacheDir = filepath.Join(home, ".kubescape", "cache", "hostsensor")
	}
}

func getCacheDir() (string, error) {
	if DefaultCacheDir == "" {
		return "", fmt.Errorf("cache directory not configured")
	}
	return DefaultCacheDir, nil
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

	return filepath.Join(dir, fmt.Sprintf("%s-%s-v1.json.gz", safeClusterName, resourceName)), nil
}

func loadFromCache(clusterName, resourceName string) ([]hostsensor.HostSensorDataEnvelope, error) {
	path, err := getCacheFilePath(clusterName, resourceName)
	if err != nil {
		return nil, err
	}

	stat, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if time.Since(stat.ModTime()) > 2*time.Hour {
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
