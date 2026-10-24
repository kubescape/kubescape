package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	v1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capturingDelete records the DeleteConfig passed to DeleteCachedConfig
// so tests can assert that command arguments are wired through.
type capturingDelete struct {
	mocks.MockIKubescape
	captured *v1.DeleteConfig
	err      error
}

func (c *capturingDelete) DeleteCachedConfig(dc *v1.DeleteConfig) error {
	c.captured = dc
	return c.err
}

func executeDeleteCmd(ks *capturingDelete, args ...string) error {
	root := &cobra.Command{Use: "config", SilenceUsage: true, SilenceErrors: true}
	root.AddCommand(getDeleteCmd(ks))
	root.SetArgs(append([]string{"delete"}, args...))
	return root.Execute()
}

func TestGetDeleteCmd(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}
	configCmd := getDeleteCmd(mockKubescape)

	assert.Equal(t, "delete [KEY...]", configCmd.Use)
	assert.Equal(t, "Delete cached configurations", configCmd.Short)

	// Verify the cache subcommand is registered
	cacheSubcmd, _, err := configCmd.Find([]string{"cache"})
	require.NoError(t, err)
	require.NotNil(t, cacheSubcmd)
	assert.Equal(t, "cache", cacheSubcmd.Use)
}

func TestGetDeleteCmd_RunEPassesKeys(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantKeys []string
	}{
		{
			name:     "no arguments deletes all cached configuration",
			args:     []string{},
			wantKeys: []string{},
		},
		{
			name:     "single key argument",
			args:     []string{"accountID"},
			wantKeys: []string{"accountID"},
		},
		{
			name:     "multiple key arguments",
			args:     []string{"accountID", "clusterName", "cloudReportURL"},
			wantKeys: []string{"accountID", "clusterName", "cloudReportURL"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &capturingDelete{}
			err := executeDeleteCmd(mock, tt.args...)
			require.NoError(t, err)
			require.NotNil(t, mock.captured)
			if len(tt.wantKeys) == 0 {
				assert.Empty(t, mock.captured.Keys)
			} else {
				assert.Equal(t, tt.wantKeys, mock.captured.Keys)
			}
		})
	}
}

func TestGetDeleteCmd_RunEReturnsError(t *testing.T) {
	deleteErr := errors.New("delete config failed")
	mock := &capturingDelete{err: deleteErr}

	err := executeDeleteCmd(mock, "accountID")
	require.Error(t, err)
	assert.EqualError(t, err, "delete config failed")
}

func TestGetDeleteCacheCmd(t *testing.T) {
	cmd := getDeleteCacheCmd()

	assert.Equal(t, "cache", cmd.Use)
	assert.Equal(t, "Delete the incremental scan cache", cmd.Short)
	assert.Contains(t, cmd.Long, "Deletes the cache file used by 'kubescape scan --incremental'")
}

func TestGetDeleteCacheCmd_RunEDeletesCacheFile(t *testing.T) {
	tempDir := t.TempDir()
	origStore := getter.DefaultLocalStore
	t.Cleanup(func() { getter.DefaultLocalStore = origStore })
	getter.DefaultLocalStore = tempDir

	cacheFile := filepath.Join(tempDir, "incremental-scan-cache.json")
	require.NoError(t, os.WriteFile(cacheFile, []byte(`{"test": "cached"}`), 0o600))
	require.FileExists(t, cacheFile)

	mock := &capturingDelete{}
	err := executeDeleteCmd(mock, "cache")
	require.NoError(t, err)
	assert.NoFileExists(t, cacheFile)
	assert.Nil(t, mock.captured, "delete cache should not invoke DeleteCachedConfig")
}

func TestGetDeleteCacheCmd_RunENoOpWhenDirDoesNotExist(t *testing.T) {
	nonExistentDir := filepath.Join(t.TempDir(), "does-not-exist")
	origStore := getter.DefaultLocalStore
	t.Cleanup(func() { getter.DefaultLocalStore = origStore })
	getter.DefaultLocalStore = nonExistentDir

	mock := &capturingDelete{}
	err := executeDeleteCmd(mock, "cache")
	require.NoError(t, err)
}

func TestGetDeleteCacheCmd_RunEReturnsErrorOnFailure(t *testing.T) {
	// A path containing a NUL character causes os.Stat to fail with EINVAL on all platforms (Unix and Windows),
	// ensuring a non-IsNotExist error that exercises the error propagation branch.
	invalidDir := "invalid\x00dir"

	origStore := getter.DefaultLocalStore
	t.Cleanup(func() { getter.DefaultLocalStore = origStore })
	getter.DefaultLocalStore = invalidDir

	mock := &capturingDelete{}
	err := executeDeleteCmd(mock, "cache")
	require.Error(t, err)
	assert.ErrorContains(t, err, "inspect incremental scan cache directory for deletion")
}
