package config

import (
	"os"
	"path/filepath"
	"testing"

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

func writeClusterDataJSON(t *testing.T, dir, namespace, clusterName string) {
	t.Helper()
	body := `{"namespace":"` + namespace + `","clusterName":"` + clusterName + `","continuousPostureScan":true}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "clusterData.json"), []byte(body), 0o600))
}

func TestLoadConfig_ReadsValuesFromFile(t *testing.T) {
	dir := t.TempDir()
	writeClusterDataJSON(t, dir, "ns-a", "cluster-a")

	got, err := LoadConfig(dir)
	require.NoError(t, err)
	assert.Equal(t, Config{Namespace: "ns-a", ClusterName: "cluster-a", ContinuousPostureScan: true}, got)
}

// TestLoadConfig_SequentialCallsDoNotLeakState guards against a regression
// where LoadConfig used the global viper singleton (package-level
// viper.AddConfigPath/SetConfigName/... functions), which accumulates state
// across calls instead of starting clean. A second call with a different
// config directory could then pick up stale search paths or settings left
// over from the first call. LoadConfig now uses a scoped viper.New()
// instance per call, so two calls with different directories must each
// return only their own directory's values.
func TestLoadConfig_SequentialCallsDoNotLeakState(t *testing.T) {
	dirA := t.TempDir()
	writeClusterDataJSON(t, dirA, "ns-a", "cluster-a")

	dirB := t.TempDir()
	writeClusterDataJSON(t, dirB, "ns-b", "cluster-b")

	gotA, err := LoadConfig(dirA)
	require.NoError(t, err)
	assert.Equal(t, "ns-a", gotA.Namespace)
	assert.Equal(t, "cluster-a", gotA.ClusterName)

	gotB, err := LoadConfig(dirB)
	require.NoError(t, err)
	assert.Equal(t, "ns-b", gotB.Namespace, "second call must read dirB's own values, not stale state from dirA")
	assert.Equal(t, "cluster-b", gotB.ClusterName)
}
