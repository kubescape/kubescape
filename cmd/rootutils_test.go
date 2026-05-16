package cmd

import (
	"testing"

	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/go-logger/iconlogger"
	"github.com/kubescape/go-logger/zaplogger"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// testCmdWithLoggerFlag mirrors root: logger on PersistentFlags, bound to rootInfo.Logger.
func testCmdWithLoggerFlag(t *testing.T) *cobra.Command {
	t.Helper()
	c := &cobra.Command{Use: "kubescape-test"}
	c.PersistentFlags().StringVarP(&rootInfo.Logger, "logger", "l", helpers.InfoLevel.String(), "log level")
	return c
}

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
		initLoggerLevel(cmd)

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
		initLoggerLevel(cmd)

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
		initLoggerLevel(cmd)

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
		initLoggerLevel(versionCmd)

		assert.Equal(t, helpers.InfoLevel.String(), rootInfo.Logger)
	})
}

func TestInitLogger_KSLoggerNameEnv(t *testing.T) {
	prevLoggerName := rootInfo.LoggerName
	prevIsTerminal := isTerminal
	t.Cleanup(func() {
		rootInfo.LoggerName = prevLoggerName
		isTerminal = prevIsTerminal
	})

	rootInfo.LoggerName = ""
	t.Setenv("KS_LOGGER_NAME", iconlogger.LoggerName)
	isTerminal = func(uintptr) bool { return false }

	initLogger()

	assert.Equal(t, iconlogger.LoggerName, rootInfo.LoggerName)
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
