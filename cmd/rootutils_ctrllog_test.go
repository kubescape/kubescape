package cmd

import (
	"errors"
	"os"
	"testing"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/prettylogger"
	"github.com/stretchr/testify/require"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

// TestInitLogger_ControllerRuntimeLogsReachKubescapeLogger checks that initLogger
// gives controller-runtime a logger. Without one, controller-runtime discards
// everything it logs and, once the process is 30 seconds old, prints a
// "log.SetLogger(...) was never called" notice with a goroutine stack trace to
// stderr the first time it logs. k8sinterface.GetK8sConfig logs through it when
// there is no kubeconfig, so a local-file scan that takes more than 30 seconds
// hit that notice.
func TestInitLogger_ControllerRuntimeLogsReachKubescapeLogger(t *testing.T) {
	prevLoggerName := rootInfo.LoggerName
	origLogger := logger.L().LoggerName()
	origLevel := logger.L().GetLevel()
	origWriter := logger.L().GetWriter()
	t.Cleanup(func() {
		rootInfo.LoggerName = prevLoggerName
		logger.InitLogger(origLogger)
		_ = logger.L().SetLevel(origLevel)
		logger.L().SetWriter(origWriter)
	})

	rootInfo.LoggerName = prettylogger.LoggerName
	initLogger()
	require.NoError(t, logger.L().SetLevel("debug"))

	logFile, err := os.CreateTemp(t.TempDir(), "log-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = logFile.Close() })
	logger.L().SetWriter(logFile)

	ctrllog.Log.Error(errors.New("no configuration has been provided"), "unable to load in-cluster config")

	require.NoError(t, logFile.Sync())
	output, err := os.ReadFile(logFile.Name())
	require.NoError(t, err)
	require.Contains(t, string(output), "unable to load in-cluster config")
	require.Contains(t, string(output), "no configuration has been provided")
}
