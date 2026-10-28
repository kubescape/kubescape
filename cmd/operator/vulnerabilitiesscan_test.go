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
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetOperatorScanVulnerabilitiesCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}
	operatorInfo := cautils.OperatorInfo{
		Namespace: "namespace",
	}

	cmd := getOperatorScanVulnerabilitiesCmd(mockKubescape, &operatorInfo)

	assert.Equal(t, "vulnerabilities", cmd.Use)

	err := cmd.Args(&cobra.Command{}, []string{"random-arg"})
	assert.Nil(t, err)
}

func TestOperatorScanVulnerabilitiesCmd_ResolvesClusterNameAfterRootPreRun(t *testing.T) {
	previousContext := k8sinterface.GetContextName()
	k8sinterface.SetClusterContextName("construction-context")
	t.Cleanup(func() { k8sinterface.SetClusterContextName(previousContext) })

	previousAdapter := newOperatorAdapter
	var gotScanInfo cautils.OperatorScanInfo
	newOperatorAdapter = func(scanInfo cautils.OperatorScanInfo, _ string, _ ...context.Context) (*core.OperatorAdapter, error) {
		gotScanInfo = scanInfo
		return nil, errors.New("stub: no real cluster in unit tests")
	}
	t.Cleanup(func() { newOperatorAdapter = previousAdapter })

	var kubeContext string
	rootCmd := &cobra.Command{
		Use: "kubescape",
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			k8sinterface.SetClusterContextName(kubeContext)
			return nil
		},
	}
	rootCmd.PersistentFlags().StringVar(&kubeContext, "kube-context", "", "")
	rootCmd.AddCommand(getOperatorScanVulnerabilitiesCmd(&mocks.MockIKubescape{}, &cautils.OperatorInfo{}))
	rootCmd.SetArgs([]string{"vulnerabilities", "--kube-context", "selected-context"})
	rootCmd.SetOut(io.Discard)
	rootCmd.SetErr(io.Discard)

	err := rootCmd.Execute()
	require.ErrorContains(t, err, "stub: no real cluster in unit tests")

	vulnerabilitiesScanInfo, ok := gotScanInfo.(*cautils.VulnerabilitiesScanInfo)
	require.True(t, ok)
	assert.Equal(t, "selected-context", vulnerabilitiesScanInfo.ClusterName)

	payload := vulnerabilitiesScanInfo.GetRequestPayload()
	require.Len(t, payload.Commands, 1)
	assert.Equal(t, "wlid://cluster-selected-context/namespace-", payload.Commands[0].WildWlid)
}

func TestOperatorScanVulnerabilitiesCmd_ContextCanceled(t *testing.T) {
	var capturedCtx context.Context
	prevAdapter := newOperatorAdapter
	newOperatorAdapter = func(scanInfo cautils.OperatorScanInfo, _ string, ctx ...context.Context) (*core.OperatorAdapter, error) {
		if len(ctx) > 0 {
			capturedCtx = ctx[0]
		}
		if capturedCtx != nil && capturedCtx.Err() != nil {
			return nil, capturedCtx.Err()
		}
		return nil, errors.New("unexpected call")
	}
	t.Cleanup(func() { newOperatorAdapter = prevAdapter })

	cmd := getOperatorScanVulnerabilitiesCmd(&mocks.MockIKubescape{}, &cautils.OperatorInfo{})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := cmd.ExecuteContext(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, ctx, capturedCtx, "constructor must receive the command context")
}

func TestOperatorScanVulnerabilitiesCmd_ContextCanceled_NoPortForward(t *testing.T) {
	var startForwarderCalled bool
	prevAdapter := newOperatorAdapter
	newOperatorAdapter = func(scanInfo cautils.OperatorScanInfo, _ string, ctx ...context.Context) (*core.OperatorAdapter, error) {
		conn := &stubOperatorConnector{
			onStart: func() { startForwarderCalled = true },
		}
		return core.NewOperatorAdapterWithConnector(scanInfo, conn), nil
	}
	t.Cleanup(func() { newOperatorAdapter = prevAdapter })

	cmd := getOperatorScanVulnerabilitiesCmd(&mocks.MockIKubescape{}, &cautils.OperatorInfo{})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := cmd.ExecuteContext(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, startForwarderCalled, "must not attempt to start port forwarding when context is canceled")
}

// TestOperatorScanVulnerabilitiesCmd_FlagsAndArgs verifies command use string, subcommand tracking, and flag registration.
func TestOperatorScanVulnerabilitiesCmd_FlagsAndArgs(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}
	operatorInfo := cautils.OperatorInfo{
		Namespace: "custom-namespace",
	}

	cmd := getOperatorScanVulnerabilitiesCmd(mockKubescape, &operatorInfo)
	assert.Equal(t, "vulnerabilities", cmd.Use)

	err := cmd.Args(&cobra.Command{}, []string{"test"})
	assert.NoError(t, err)
	assert.Contains(t, operatorInfo.Subcommands, cautils.OperatorSubCommand("vulnerabilities"))

	flag := cmd.PersistentFlags().Lookup("include-namespaces")
	assert.NotNil(t, flag)

	includeNs, err := cmd.PersistentFlags().GetStringSlice("include-namespaces")
	require.NoError(t, err)
	assert.Empty(t, includeNs)
}

// TestOperatorScanVulnerabilitiesCmd_ExecutionSuccess verifies successful scan triggering, command payload, and confirmation logging.
func TestOperatorScanVulnerabilitiesCmd_ExecutionSuccess(t *testing.T) {
	withCapturableLogger(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/triggerAction", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		var payload apis.Commands
		err := json.NewDecoder(r.Body).Decode(&payload)
		assert.NoError(t, err)
		require.Len(t, payload.Commands, 2)
		assert.Equal(t, apis.TypeScanImages, payload.Commands[0].CommandName)
		assert.Contains(t, payload.Commands[0].WildWlid, "namespace-dev")
		assert.Equal(t, apis.TypeScanImages, payload.Commands[1].CommandName)
		assert.Contains(t, payload.Commands[1].WildWlid, "namespace-staging")

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
	cmd.SetArgs([]string{"vulnerabilities", "--include-namespaces", "dev,staging"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	var err error
	output := captureLog(t, func() {
		err = cmd.Execute()
	})

	require.NoError(t, err)
	assert.Contains(t, output, "Triggering the Kubescape Operator for vulnerability scanning")
	assert.Contains(t, output, "Triggered Kubescape Operator for vulnerability scanning")
}

// TestOperatorScanVulnerabilitiesCmd_ScanError verifies error logging when triggering the scan fails.
func TestOperatorScanVulnerabilitiesCmd_ScanError(t *testing.T) {
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
	cmd.SetArgs([]string{"vulnerabilities"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	var err error
	output := captureLog(t, func() {
		err = cmd.Execute()
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "http-error: 500")
	assert.Contains(t, output, "Failed to trigger the Kubescape Operator for vulnerability scanning")
}
