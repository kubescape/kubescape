package cmd

import (
	"context"
	"testing"

	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/go-logger/iconlogger"
	"github.com/kubescape/go-logger/zaplogger"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCmdWithLoggerFlag mirrors root: logger on PersistentFlags, bound to rootInfo.Logger.
func testCmdWithLoggerFlag(t *testing.T) *cobra.Command {
	t.Helper()
	c := &cobra.Command{Use: "kubescape-test"}
	c.PersistentFlags().StringVarP(&rootInfo.Logger, "logger", "l", helpers.InfoLevel.String(), "log level")
	return c
}

// TestInitLoggerLevel_KSLoggerPrecedence tests flag and environment variable precedence for logger levels.
func TestInitLoggerLevel_KSLoggerPrecedence(t *testing.T) {
	t.Run("KS_LOGGER applies when logger flag not set", func(t *testing.T) {
		prevLogger := rootInfo.Logger
		prevLoggerName := rootInfo.LoggerName
		t.Cleanup(func() {
			rootInfo.Logger = prevLogger
			rootInfo.LoggerName = prevLoggerName
		})

		t.Setenv("KS_LOGGER", "debug")
		cmd := testCmdWithLoggerFlag(t)
		assert.NoError(t, cmd.ParseFlags([]string{}))
		rootInfo.LoggerName = zaplogger.LoggerName

		initLogger()
		assert.NoError(t, initLoggerLevel(cmd))

		assert.Equal(t, "debug", rootInfo.Logger)
	})

	t.Run("explicit non-default logger level wins over KS_LOGGER", func(t *testing.T) {
		prevLogger := rootInfo.Logger
		prevLoggerName := rootInfo.LoggerName
		t.Cleanup(func() {
			rootInfo.Logger = prevLogger
			rootInfo.LoggerName = prevLoggerName
		})

		t.Setenv("KS_LOGGER", "error")
		cmd := testCmdWithLoggerFlag(t)
		assert.NoError(t, cmd.ParseFlags([]string{"-l", helpers.WarningLevel.String()}))
		rootInfo.LoggerName = zaplogger.LoggerName

		initLogger()
		assert.NoError(t, initLoggerLevel(cmd))

		assert.Equal(t, helpers.WarningLevel.String(), rootInfo.Logger)
	})

	t.Run("explicit -l info wins over KS_LOGGER", func(t *testing.T) {
		prevLogger := rootInfo.Logger
		prevLoggerName := rootInfo.LoggerName
		t.Cleanup(func() {
			rootInfo.Logger = prevLogger
			rootInfo.LoggerName = prevLoggerName
		})

		t.Setenv("KS_LOGGER", "debug")
		cmd := testCmdWithLoggerFlag(t)
		assert.NoError(t, cmd.ParseFlags([]string{"-l", helpers.InfoLevel.String()}))
		rootInfo.LoggerName = zaplogger.LoggerName

		initLogger()
		assert.NoError(t, initLoggerLevel(cmd))

		assert.Equal(t, helpers.InfoLevel.String(), rootInfo.Logger)
	})

	t.Run("explicit --logger on root wins for subcommand path", func(t *testing.T) {
		prevLogger := rootInfo.Logger
		prevLoggerName := rootInfo.LoggerName
		t.Cleanup(func() {
			rootInfo.Logger = prevLogger
			rootInfo.LoggerName = prevLoggerName
		})

		t.Setenv("KS_LOGGER", "debug")

		rootCmd := &cobra.Command{Use: "kubescape"}
		rootCmd.PersistentFlags().StringVarP(&rootInfo.Logger, "logger", "l", helpers.InfoLevel.String(), "log level")
		versionCmd := &cobra.Command{Use: "version"}
		rootCmd.AddCommand(versionCmd)

		assert.NoError(t, rootCmd.ParseFlags([]string{"--logger", helpers.InfoLevel.String()}))

		rootInfo.LoggerName = zaplogger.LoggerName
		initLogger()
		assert.NoError(t, initLoggerLevel(versionCmd))

		assert.Equal(t, helpers.InfoLevel.String(), rootInfo.Logger)
	})
}

// TestInitLoggerNameFallback tests terminal detection fallback for the logger name.
func TestInitLoggerNameFallback(t *testing.T) {
	t.Run("terminal uses iconlogger", func(t *testing.T) {
		prevLoggerName := rootInfo.LoggerName
		prevIsTerminal := isTerminal
		t.Cleanup(func() {
			rootInfo.LoggerName = prevLoggerName
			isTerminal = prevIsTerminal
		})

		rootInfo.LoggerName = ""
		t.Setenv("KS_LOGGER_NAME", "")
		isTerminal = func(uintptr) bool { return true }

		initLogger()

		assert.Equal(t, iconlogger.LoggerName, rootInfo.LoggerName)
	})

	t.Run("non-terminal uses zaplogger", func(t *testing.T) {
		prevLoggerName := rootInfo.LoggerName
		prevIsTerminal := isTerminal
		t.Cleanup(func() {
			rootInfo.LoggerName = prevLoggerName
			isTerminal = prevIsTerminal
		})

		rootInfo.LoggerName = ""
		t.Setenv("KS_LOGGER_NAME", "")
		isTerminal = func(uintptr) bool { return false }

		initLogger()

		assert.Equal(t, zaplogger.LoggerName, rootInfo.LoggerName)
	})
}

// testCmdWithCacheDirFlag mirrors root: cache-dir on PersistentFlags, bound to rootInfo.CacheDir.
func testCmdWithCacheDirFlag(t *testing.T) *cobra.Command {
	t.Helper()
	c := &cobra.Command{Use: "kubescape-test"}
	c.PersistentFlags().StringVar(&rootInfo.CacheDir, "cache-dir", getter.DefaultLocalStore, "cache dir")
	return c
}

// TestInitCacheDir_KSCacheDirPrecedence tests flag and environment variable precedence for the cache directory.
func TestInitCacheDir_KSCacheDirPrecedence(t *testing.T) {
	t.Run("KS_CACHE_DIR applies when --cache-dir flag not set", func(t *testing.T) {
		prevStore := getter.DefaultLocalStore
		prevCacheDir := rootInfo.CacheDir
		t.Cleanup(func() {
			getter.DefaultLocalStore = prevStore
			rootInfo.CacheDir = prevCacheDir
		})

		t.Setenv("KS_CACHE_DIR", "/tmp/ks-env-cache")
		cmd := testCmdWithCacheDirFlag(t)
		assert.NoError(t, cmd.ParseFlags([]string{}))

		initCacheDir(cmd)

		assert.Equal(t, "/tmp/ks-env-cache", getter.DefaultLocalStore)
	})

	t.Run("explicit --cache-dir wins over KS_CACHE_DIR even when value equals default", func(t *testing.T) {
		prevStore := getter.DefaultLocalStore
		prevCacheDir := rootInfo.CacheDir
		t.Cleanup(func() {
			getter.DefaultLocalStore = prevStore
			rootInfo.CacheDir = prevCacheDir
		})

		defaultVal := getter.DefaultLocalStore
		t.Setenv("KS_CACHE_DIR", "/tmp/ks-env-cache")
		cmd := testCmdWithCacheDirFlag(t)
		// Pass the default value explicitly — this is the core bug case
		assert.NoError(t, cmd.ParseFlags([]string{"--cache-dir", defaultVal}))

		initCacheDir(cmd)

		// env var must NOT win; flag value (== default) must be used
		assert.Equal(t, defaultVal, getter.DefaultLocalStore)
	})

	t.Run("explicit --cache-dir with non-default value wins over KS_CACHE_DIR", func(t *testing.T) {
		prevStore := getter.DefaultLocalStore
		prevCacheDir := rootInfo.CacheDir
		t.Cleanup(func() {
			getter.DefaultLocalStore = prevStore
			rootInfo.CacheDir = prevCacheDir
		})

		t.Setenv("KS_CACHE_DIR", "/tmp/ks-env-cache")
		cmd := testCmdWithCacheDirFlag(t)
		assert.NoError(t, cmd.ParseFlags([]string{"--cache-dir", "/tmp/explicit-cache"}))

		initCacheDir(cmd)

		assert.Equal(t, "/tmp/explicit-cache", getter.DefaultLocalStore)
	})

	t.Run("nil cmd falls back to KS_CACHE_DIR", func(t *testing.T) {
		prevStore := getter.DefaultLocalStore
		prevCacheDir := rootInfo.CacheDir
		t.Cleanup(func() {
			getter.DefaultLocalStore = prevStore
			rootInfo.CacheDir = prevCacheDir
		})

		t.Setenv("KS_CACHE_DIR", "/tmp/ks-env-cache")

		initCacheDir(nil)

		assert.Equal(t, "/tmp/ks-env-cache", getter.DefaultLocalStore)
	})

	t.Run("no flag no env — default store unchanged", func(t *testing.T) {
		prevStore := getter.DefaultLocalStore
		prevCacheDir := rootInfo.CacheDir
		t.Cleanup(func() {
			getter.DefaultLocalStore = prevStore
			rootInfo.CacheDir = prevCacheDir
		})

		cmd := testCmdWithCacheDirFlag(t)
		assert.NoError(t, cmd.ParseFlags([]string{}))

		initCacheDir(cmd)

		assert.Equal(t, prevStore, getter.DefaultLocalStore)
	})

	t.Run("explicit --cache-dir on root wins for subcommand path", func(t *testing.T) {
		prevStore := getter.DefaultLocalStore
		prevCacheDir := rootInfo.CacheDir
		t.Cleanup(func() {
			getter.DefaultLocalStore = prevStore
			rootInfo.CacheDir = prevCacheDir
		})

		defaultVal := getter.DefaultLocalStore
		t.Setenv("KS_CACHE_DIR", "/tmp/ks-env-cache")

		rootCmd := &cobra.Command{Use: "kubescape"}
		rootCmd.PersistentFlags().StringVar(&rootInfo.CacheDir, "cache-dir", getter.DefaultLocalStore, "cache dir")
		scanCmd := &cobra.Command{Use: "scan"}
		rootCmd.AddCommand(scanCmd)
		assert.NoError(t, rootCmd.ParseFlags([]string{"--cache-dir", defaultVal}))

		initCacheDir(scanCmd)

		assert.Equal(t, defaultVal, getter.DefaultLocalStore)
	})
}

// TestInitLogger_KSLoggerNameEnv tests environment variable precedence for KS_LOGGER_NAME.
func TestInitLogger_KSLoggerNameEnv(t *testing.T) {
	t.Run("env sets logger name when empty", func(t *testing.T) {
		prevLoggerName := rootInfo.LoggerName
		t.Cleanup(func() {
			rootInfo.LoggerName = prevLoggerName
		})

		rootInfo.LoggerName = ""
		t.Setenv("KS_LOGGER_NAME", "custom-logger")

		initLogger()

		assert.Equal(t, "custom-logger", rootInfo.LoggerName)
	})

	t.Run("existing logger name wins over env", func(t *testing.T) {
		prevLoggerName := rootInfo.LoggerName
		t.Cleanup(func() {
			rootInfo.LoggerName = prevLoggerName
		})

		rootInfo.LoggerName = zaplogger.LoggerName
		t.Setenv("KS_LOGGER_NAME", "custom-logger")

		initLogger()

		assert.Equal(t, zaplogger.LoggerName, rootInfo.LoggerName)
	})

	t.Run("existing logger name stays when env empty", func(t *testing.T) {
		prevLoggerName := rootInfo.LoggerName
		t.Cleanup(func() {
			rootInfo.LoggerName = prevLoggerName
		})

		rootInfo.LoggerName = zaplogger.LoggerName
		t.Setenv("KS_LOGGER_NAME", "")

		initLogger()

		assert.Equal(t, zaplogger.LoggerName, rootInfo.LoggerName)
	})

	t.Run("env applies after logger name cleared", func(t *testing.T) {
		prevLoggerName := rootInfo.LoggerName
		t.Cleanup(func() {
			rootInfo.LoggerName = prevLoggerName
		})

		rootInfo.LoggerName = zaplogger.LoggerName
		t.Setenv("KS_LOGGER_NAME", "custom-logger")
		rootInfo.LoggerName = ""

		initLogger()

		assert.Equal(t, "custom-logger", rootInfo.LoggerName)
	})
}

// TestInitLoggerLevel_InvalidLevel verifies that initLoggerLevel returns an error when rootInfo.Logger contains an unsupported level.
func TestInitLoggerLevel_InvalidLevel(t *testing.T) {
	prevLogger := rootInfo.Logger
	prevLoggerName := rootInfo.LoggerName
	t.Cleanup(func() {
		rootInfo.Logger = prevLogger
		rootInfo.LoggerName = prevLoggerName
	})

	rootInfo.LoggerName = zaplogger.LoggerName
	initLogger()

	cmd := testCmdWithLoggerFlag(t)
	rootInfo.Logger = "unsupported-level"
	err := initLoggerLevel(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "supported levels:")
}

// TestInitLoggerLevel_NilCmd verifies that initLoggerLevel falls back to KS_LOGGER when the command is nil.
func TestInitLoggerLevel_NilCmd(t *testing.T) {
	prevLogger := rootInfo.Logger
	prevLoggerName := rootInfo.LoggerName
	t.Cleanup(func() {
		rootInfo.Logger = prevLogger
		rootInfo.LoggerName = prevLoggerName
	})

	t.Setenv("KS_LOGGER", "warning")
	rootInfo.Logger = helpers.InfoLevel.String()
	rootInfo.LoggerName = zaplogger.LoggerName
	initLogger()

	err := initLoggerLevel(nil)
	require.NoError(t, err)
	assert.Equal(t, "warning", rootInfo.Logger)
}

// TestInitLoggerLevel_ChildCmdWithoutRoot verifies that initLoggerLevel reads the logger flag defined on a standalone child command without root.
func TestInitLoggerLevel_ChildCmdWithoutRoot(t *testing.T) {
	prevLogger := rootInfo.Logger
	t.Cleanup(func() { rootInfo.Logger = prevLogger })

	childCmd := &cobra.Command{Use: "standalone"}
	childCmd.Flags().StringVar(&rootInfo.Logger, "logger", helpers.InfoLevel.String(), "log level")
	require.NoError(t, childCmd.ParseFlags([]string{"--logger", helpers.ErrorLevel.String()}))

	err := initLoggerLevel(childCmd)
	require.NoError(t, err)
	assert.Equal(t, helpers.ErrorLevel.String(), rootInfo.Logger)
}

// TestInitCacheDir_ChildCmdWithoutRoot verifies that initCacheDir reads the cache-dir flag defined on a standalone child command without root.
func TestInitCacheDir_ChildCmdWithoutRoot(t *testing.T) {
	prevStore := getter.DefaultLocalStore
	prevCacheDir := rootInfo.CacheDir
	t.Cleanup(func() {
		getter.DefaultLocalStore = prevStore
		rootInfo.CacheDir = prevCacheDir
	})

	childCmd := &cobra.Command{Use: "standalone"}
	childCmd.Flags().StringVar(&rootInfo.CacheDir, "cache-dir", getter.DefaultLocalStore, "cache dir")
	require.NoError(t, childCmd.ParseFlags([]string{"--cache-dir", "/tmp/standalone-cache"}))

	initCacheDir(childCmd)
	assert.Equal(t, "/tmp/standalone-cache", getter.DefaultLocalStore)
}

// TestInitEnvironment verifies that initEnvironment returns nil for an empty discovery URL and an error for an invalid URL.
func TestInitEnvironment(t *testing.T) {
	t.Run("empty server url returns nil", func(t *testing.T) {
		prevURL := rootInfo.DiscoveryServerURL
		t.Cleanup(func() { rootInfo.DiscoveryServerURL = prevURL })

		rootInfo.DiscoveryServerURL = ""
		assert.NoError(t, initEnvironment(context.Background()))
	})

	t.Run("invalid server url returns error", func(t *testing.T) {
		prevURL := rootInfo.DiscoveryServerURL
		t.Cleanup(func() { rootInfo.DiscoveryServerURL = prevURL })

		rootInfo.DiscoveryServerURL = "://bad-scheme"
		err := initEnvironment(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create service discovery client")
	})
}
