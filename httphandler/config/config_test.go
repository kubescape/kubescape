package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/filesizelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Loads configuration from file successfully
func TestLoadConfigFromFileSuccessfully(t *testing.T) {
	// Set up test data
	path := "/path/to/config"
	expectedConfig := Config{
		Namespace:             "",
		ClusterName:           "",
		ContinuousPostureScan: false,
	}

	// Call the function under test
	config, err := LoadConfig(path)

	// Check the result
	assert.Equal(t, expectedConfig, config)
	assert.NotNil(t, err)
}

func TestLoadConfig_RejectsOversizedFile(t *testing.T) {
	t.Setenv(filesizelimit.MaxFileSizeEnvVar, "64")
	dir := t.TempDir()
	payload := `{"namespace":"default","clusterName":"` + strings.Repeat("a", 80) + `","continuousPostureScan":true}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "clusterData.json"), []byte(payload), 0o600))

	cfg, err := LoadConfig(dir)
	require.ErrorIs(t, err, ErrConfigTooLarge)
	require.Equal(t, Config{}, cfg)
}

func TestLoadConfig_LoadsValidAndRejectsNonRegular(t *testing.T) {
	t.Run("loads valid file within limit", func(t *testing.T) {
		payload := `{"namespace":"prod","clusterName":"my-cluster","continuousPostureScan":true}`
		t.Setenv(filesizelimit.MaxFileSizeEnvVar, "1024")
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "clusterData.json"), []byte(payload), 0o600))

		cfg, err := LoadConfig(dir)
		require.NoError(t, err)
		require.Equal(t, Config{
			Namespace:             "prod",
			ClusterName:           "my-cluster",
			ContinuousPostureScan: true,
		}, cfg)
	})

	t.Run("applies environment overrides with AutomaticEnv", func(t *testing.T) {
		payload := `{"namespace":"prod","clusterName":"my-cluster","continuousPostureScan":false}`
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "clusterData.json"), []byte(payload), 0o600))
		t.Setenv("NAMESPACE", "env-ns")

		cfg, err := LoadConfig(dir)
		require.NoError(t, err)
		require.Equal(t, "env-ns", cfg.Namespace)
		require.Equal(t, "my-cluster", cfg.ClusterName)
	})

	t.Run("rejects directory named clusterData.json", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(dir, "clusterData.json"), 0o700))

		cfg, err := LoadConfig(dir)
		require.ErrorIs(t, err, ErrConfigNotRegular)
		require.Equal(t, Config{}, cfg)
	})

	t.Run("preserves symlink parent traversal", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation requires elevated privileges on Windows")
		}
		root := t.TempDir()
		cfgDir := filepath.Join(root, "cfg")
		secretsDir := filepath.Join(root, "secrets")
		currentDir := filepath.Join(secretsDir, "current")
		require.NoError(t, os.MkdirAll(cfgDir, 0o700))
		require.NoError(t, os.MkdirAll(currentDir, 0o700))

		payload := `{"namespace":"ns1","clusterName":"c1","continuousPostureScan":false}`
		require.NoError(t, os.WriteFile(filepath.Join(secretsDir, "clusterData.json"), []byte(payload), 0o600))
		linkDir := filepath.Join(cfgDir, "link")
		require.NoError(t, os.Symlink(currentDir, linkDir))

		cfg, err := LoadConfig(linkDir + string(os.PathSeparator) + "..")
		require.NoError(t, err)
		require.Equal(t, Config{Namespace: "ns1", ClusterName: "c1"}, cfg)
	})
}
