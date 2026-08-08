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

func getCacheFilePath(resourceName string) (string, error) {
	dir, err := getCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, fmt.Sprintf("%s.json.gz", resourceName)), nil
}

func loadFromCache(resourceName string) ([]hostsensor.HostSensorDataEnvelope, error) {
	path, err := getCacheFilePath(resourceName)
	if err != nil {
		return nil, err
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

func saveToCache(resourceName string, envelopes []hostsensor.HostSensorDataEnvelope) error {
	path, err := getCacheFilePath(resourceName)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

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

	logger.L().Debug("Saved host sensor envelopes to cache", helpers.String("resource", resourceName), helpers.Int("count", len(envelopes)))
	return nil
}
