package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/kubescape/kubescape/v4/core/pkg/filesizelimit"
	"github.com/spf13/viper"
)

const clusterDataFileName = "clusterData.json"

var (
	// ErrConfigNotRegular is returned when clusterData.json is not a regular file.
	ErrConfigNotRegular = errors.New("config file is not a regular file")
	// ErrConfigTooLarge is returned when clusterData.json exceeds the maximum size limit.
	ErrConfigTooLarge = errors.New("config file exceeds maximum size limit")
)

type Config struct {
	Namespace             string `mapstructure:"namespace"`
	ClusterName           string `mapstructure:"clusterName"`
	ContinuousPostureScan bool   `mapstructure:"continuousPostureScan"`
}

func joinPreserveSymlinks(dir, name string) string {
	if strings.TrimSpace(dir) == "" {
		return ""
	}
	if os.IsPathSeparator(dir[len(dir)-1]) {
		return dir + name
	}
	return dir + string(os.PathSeparator) + name
}

func openRegularFile(path string, notRegularErr error) (*os.File, os.FileInfo, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil, os.ErrNotExist
	}
	statInfo, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if statInfo.IsDir() {
		return nil, nil, fmt.Errorf("%q is a directory, not a file: %w", path, notRegularErr)
	}
	if !statInfo.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w: %q", notRegularErr, path)
	}

	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if info.IsDir() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%q is a directory, not a file: %w", path, notRegularErr)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%w: %q", notRegularErr, path)
	}
	return file, info, nil
}

func readBoundedRegularFile(path string, limit int64, notRegularErr, tooLargeErr error) ([]byte, error) {
	f, info, err := openRegularFile(path, notRegularErr)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if info.Size() > limit {
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", tooLargeErr, path, limit)
	}

	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		clear(data)
		return nil, err
	}
	if int64(len(data)) > limit {
		clear(data)
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", tooLargeErr, path, limit)
	}
	return data, nil
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (Config, error) {
	configPath := joinPreserveSymlinks(path, clusterDataFileName)
	data, err := readBoundedRegularFile(configPath, filesizelimit.GetMaxFileSize(), ErrConfigNotRegular, ErrConfigTooLarge)
	if err != nil {
		return Config{}, err
	}

	v := viper.New()
	v.SetConfigType("json")
	v.AutomaticEnv()
	if err := v.ReadConfig(bytes.NewReader(data)); err != nil {
		return Config{}, err
	}

	var config Config
	err = v.Unmarshal(&config)
	return config, err
}
