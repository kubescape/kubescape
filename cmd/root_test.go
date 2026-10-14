package cmd

import (
	"context"
	"testing"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)


func TestScanSubcommand_RunsRootPersistentPreRun(t *testing.T) {
	prevLoggerVal := rootInfo.Logger
	prevLoggerName := rootInfo.LoggerName
	prevCacheDir := rootInfo.CacheDir
	prevStore := getter.DefaultLocalStore
	prevLevel := logger.L().GetLevel()
	t.Cleanup(func() {
		rootInfo.Logger = prevLoggerVal
		rootInfo.LoggerName = prevLoggerName
		rootInfo.CacheDir = prevCacheDir
		getter.DefaultLocalStore = prevStore
		_ = logger.L().SetLevel(prevLevel)
	})

	// Force a known baseline that ONLY root's PersistentPreRun (via initLoggerLevel) can move off of.
	require.NoError(t, logger.L().SetLevel(helpers.WarningLevel.String()))

	cmd := NewDefaultKubescapeCommand(context.Background(), "", "", "")
	cmd.SetArgs([]string{"scan", "--controls-version", "bad/value", "-l", "debug"})
	err := cmd.Execute()

	// scanCmd's PersistentPreRunE still runs and still validates --controls-version.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --controls-version")

	// rootCmd's PersistentPreRun also ran: initLoggerLevel moved the logger singleton
	// off the "warning" baseline to "debug" — the ONLY code path that can do that here.
	// With the bug present (hook shadowed), this would still read "warning" and fail.
	assert.Equal(t, helpers.DebugLevel.String(), logger.L().GetLevel())
}

func TestEnableTraverseRunHooksIsSetForRootAndScanHooks(t *testing.T) {
	assert.True(t, cobra.EnableTraverseRunHooks, "root.go's PersistentPreRun and scan.go's PersistentPreRunE both need cobra to traverse all ancestor hooks, not just the closest one")
}
