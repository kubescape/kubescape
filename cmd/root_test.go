package cmd

import (
	"context"
	"os"
	"testing"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScanSubcommand_RunsRootPersistentPreRun verifies that root PersistentPreRun hooks execute when running scan subcommands.
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

// TestEnableTraverseRunHooksIsSetForRootAndScanHooks verifies that cobra.EnableTraverseRunHooks is enabled for hook inheritance.
func TestEnableTraverseRunHooksIsSetForRootAndScanHooks(t *testing.T) {
	assert.True(t, cobra.EnableTraverseRunHooks, "root.go's PersistentPreRun and scan.go's PersistentPreRunE both need cobra to traverse all ancestor hooks, not just the closest one")
}

// TestExecute_Success verifies that Execute runs the root command with valid arguments and returns no error.
func TestExecute_Success(t *testing.T) {
	prevArgs := os.Args
	t.Cleanup(func() { os.Args = prevArgs })
	os.Args = []string{"kubescape", "version", "--format", "json"}

	t.Setenv("KS_SKIP_UPDATE_CHECK", "true")
	err := Execute(context.Background(), "v3.0.0", "abc1234", "2026-01-01")
	require.NoError(t, err)
}

// TestExecute_Error verifies that Execute returns an error when given an invalid subcommand.
func TestExecute_Error(t *testing.T) {
	prevArgs := os.Args
	t.Cleanup(func() { os.Args = prevArgs })
	os.Args = []string{"kubescape", "nonexistent-subcommand"}

	err := Execute(context.Background(), "v3.0.0", "abc1234", "2026-01-01")
	require.Error(t, err)
}

// TestRootCmd_KrewPluginUsageTemplate verifies that NewDefaultKubescapeCommand adjusts the usage template when invoked as a kubectl plugin.
func TestRootCmd_KrewPluginUsageTemplate(t *testing.T) {
	prevArgs := os.Args
	t.Cleanup(func() { os.Args = prevArgs })
	os.Args = []string{"kubectl-kubescape"}

	cmd := NewDefaultKubescapeCommand(context.Background(), "v3.0.0", "abc1234", "2026-01-01")
	require.NotNil(t, cmd)
	assert.Contains(t, cmd.UsageTemplate(), "kubectl {{.UseLine}}")
	assert.Contains(t, cmd.UsageTemplate(), "kubectl {{.CommandPath}}")
}

// TestRootCmd_PersistentPreRunE_LoggerError verifies that PersistentPreRunE returns an error when an invalid logger level is specified.
func TestRootCmd_PersistentPreRunE_LoggerError(t *testing.T) {
	prevLoggerVal := rootInfo.Logger
	prevLoggerName := rootInfo.LoggerName
	t.Cleanup(func() {
		rootInfo.Logger = prevLoggerVal
		rootInfo.LoggerName = prevLoggerName
	})

	cmd := NewDefaultKubescapeCommand(context.Background(), "", "", "")
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--logger", "invalid-level", "version"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "supported levels")
}

// TestRootCmd_PersistentPreRunE_DiscoveryServerError verifies that PersistentPreRunE returns an error when an invalid server discovery URL is provided.
func TestRootCmd_PersistentPreRunE_DiscoveryServerError(t *testing.T) {
	cmd := NewDefaultKubescapeCommand(context.Background(), "", "", "")
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--server", "://invalid-scheme", "version"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create service discovery client")
}

// TestRootCmd_PersistentPreRunE_KubeContext verifies that the --kube-context flag sets both rootInfo.KubeContext and k8sinterface context.
func TestRootCmd_PersistentPreRunE_KubeContext(t *testing.T) {
	prevContext := rootInfo.KubeContext
	prevK8sContext := k8sinterface.GetContextName()
	t.Cleanup(func() {
		rootInfo.KubeContext = prevContext
		k8sinterface.SetClusterContextName(prevK8sContext)
	})

	t.Setenv("KS_SKIP_UPDATE_CHECK", "true")
	cmd := NewDefaultKubescapeCommand(context.Background(), "", "", "")
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--kube-context", "test-cluster-context", "version", "--format", "json"})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Equal(t, "test-cluster-context", rootInfo.KubeContext)
	assert.Equal(t, "test-cluster-context", k8sinterface.GetContextName())
}
