package operator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/prettylogger"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetOperatorScanConfigCmd verifies command creation, name, and subcommand tracking.
func TestGetOperatorScanConfigCmd(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}
	operatorInfo := cautils.OperatorInfo{
		Namespace: "namespace",
	}

	cmd := getOperatorScanConfigCmd(mockKubescape, &operatorInfo)

	assert.Equal(t, "configurations", cmd.Use)

	err := cmd.Args(&cobra.Command{}, []string{})
	assert.NoError(t, err)
	assert.Contains(t, operatorInfo.Subcommands, cautils.OperatorSubCommand("config"))

	err = cmd.Args(&cobra.Command{}, []string{"configurations"})
	assert.NoError(t, err)
}

// TestGetOperatorScanConfigCmd_FlagsRegistered verifies that required flags are registered and have expected defaults.
func TestGetOperatorScanConfigCmd_FlagsRegistered(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}
	cmd := getOperatorScanConfigCmd(mockKubescape, &cautils.OperatorInfo{})

	for _, name := range []string{"include-namespaces", "exclude-namespaces", "frameworks", "enable-host-scan"} {
		assert.NotNil(t, cmd.PersistentFlags().Lookup(name), "flag --%s should be registered", name)
	}

	includeNs, err := cmd.PersistentFlags().GetStringSlice("include-namespaces")
	require.NoError(t, err)
	assert.Empty(t, includeNs)

	excludeNs, err := cmd.PersistentFlags().GetStringSlice("exclude-namespaces")
	require.NoError(t, err)
	assert.Empty(t, excludeNs)

	frameworks, err := cmd.PersistentFlags().GetStringSlice("frameworks")
	require.NoError(t, err)
	assert.Equal(t, []string{"all"}, frameworks)

	hostScan, err := cmd.PersistentFlags().GetBool("enable-host-scan")
	require.NoError(t, err)
	assert.False(t, hostScan)
}

func withCapturableLogger(t *testing.T) {
	t.Helper()
	origLogger := logger.L().LoggerName()
	origLevel := logger.L().GetLevel()
	origWriter := logger.L().GetWriter()
	logger.InitLogger(prettylogger.LoggerName)
	_ = logger.L().SetLevel("debug")
	t.Cleanup(func() {
		logger.InitLogger(origLogger)
		_ = logger.L().SetLevel(origLevel)
		logger.L().SetWriter(origWriter)
	})
}

// TestOperatorScanConfigCmd_ExecutionSuccess verifies successful scan triggering, command payload, and logging.
func TestOperatorScanConfigCmd_ExecutionSuccess(t *testing.T) {
	withCapturableLogger(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/triggerAction", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		var payload apis.Commands
		err := json.NewDecoder(r.Body).Decode(&payload)
		assert.NoError(t, err)
		require.Len(t, payload.Commands, 1)
		assert.Equal(t, apis.TypeRunKubescape, payload.Commands[0].CommandName)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")
	prevAdapter := newOperatorAdapter
	newOperatorAdapter = func(scanInfo cautils.OperatorScanInfo, _ string, _ ...context.Context) (*core.OperatorAdapter, error) {
		conn := &stubOperatorConnector{host: host}
		return core.NewOperatorAdapterWithConnector(scanInfo, conn), nil
	}
	t.Cleanup(func() { newOperatorAdapter = prevAdapter })

	cmd := getOperatorScanCmd(&mocks.MockIKubescape{}, &cautils.OperatorInfo{})
	cmd.SetArgs([]string{"configurations", "--include-namespaces", "test-ns", "--enable-host-scan=true"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	var err error
	output := captureLog(t, func() {
		err = cmd.Execute()
	})

	require.NoError(t, err)
	assert.Contains(t, output, "Kubescape Operator Triggering for configuration scanning")
	assert.Contains(t, output, "Triggered Kubescape Operator for configuration scanning")
}

// TestOperatorScanConfigCmd_AdapterCreationError verifies error propagation when adapter creation fails.
func TestOperatorScanConfigCmd_AdapterCreationError(t *testing.T) {
	prevAdapter := newOperatorAdapter
	newOperatorAdapter = func(_ cautils.OperatorScanInfo, _ string, _ ...context.Context) (*core.OperatorAdapter, error) {
		return nil, errors.New("failed to connect to cluster operator")
	}
	t.Cleanup(func() { newOperatorAdapter = prevAdapter })

	cmd := getOperatorScanCmd(&mocks.MockIKubescape{}, &cautils.OperatorInfo{})
	cmd.SetArgs([]string{"configurations"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect to cluster operator")
}

// TestOperatorScanConfigCmd_ScanError verifies error reporting when triggerAction returns an error.
func TestOperatorScanConfigCmd_ScanError(t *testing.T) {
	withCapturableLogger(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")
	prevAdapter := newOperatorAdapter
	newOperatorAdapter = func(scanInfo cautils.OperatorScanInfo, _ string, _ ...context.Context) (*core.OperatorAdapter, error) {
		conn := &stubOperatorConnector{host: host}
		return core.NewOperatorAdapterWithConnector(scanInfo, conn), nil
	}
	t.Cleanup(func() { newOperatorAdapter = prevAdapter })

	cmd := getOperatorScanCmd(&mocks.MockIKubescape{}, &cautils.OperatorInfo{})
	cmd.SetArgs([]string{"configurations"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	var err error
	output := captureLog(t, func() {
		err = cmd.Execute()
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "http-error: 500")
	assert.Contains(t, output, "Failed to triggering Kubescape Operator for configuration scanning")
}
