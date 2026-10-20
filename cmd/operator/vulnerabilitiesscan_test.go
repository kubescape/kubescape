package operator

import (
	"context"
	"errors"
	"io"
	"testing"

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
	var startForwarderCalled bool
	prevAdapter := newOperatorAdapter
	newOperatorAdapter = func(scanInfo cautils.OperatorScanInfo, _ string, ctx ...context.Context) (*core.OperatorAdapter, error) {
		if len(ctx) > 0 {
			capturedCtx = ctx[0]
		}
		if capturedCtx != nil && capturedCtx.Err() != nil {
			return nil, capturedCtx.Err()
		}
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
	assert.Equal(t, ctx, capturedCtx, "constructor must receive the command context")
	assert.False(t, startForwarderCalled, "must not attempt to start port forwarding when context is canceled")
}
