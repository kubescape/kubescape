package operator

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	buf, err := os.CreateTemp(t.TempDir(), "log-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = buf.Close() })
	prev := logger.L().GetWriter()
	logger.L().SetWriter(buf)
	t.Cleanup(func() { logger.L().SetWriter(prev) })

	fn()

	require.NoError(t, buf.Sync())
	b, err := os.ReadFile(buf.Name())
	require.NoError(t, err)
	return string(b)
}

func TestGetOperatorRemediateCmd(t *testing.T) {
	cmd := getOperatorRemediateCmd(&mocks.MockIKubescape{}, cautils.OperatorInfo{})

	assert.Equal(t, "remediate <action>", cmd.Use)

	// no action -> error
	err := cmd.Args(&cobra.Command{}, []string{})
	assert.Error(t, err)

	// supported actions pass arg validation
	assert.Nil(t, cmd.Args(&cobra.Command{}, []string{annotateSubCommand}))
	assert.Nil(t, cmd.Args(&cobra.Command{}, []string{quarantineSubCommand}))
	assert.Nil(t, cmd.Args(&cobra.Command{}, []string{revertSubCommand}))

	// unknown action is rejected
	err = cmd.Args(&cobra.Command{}, []string{"explode"})
	assert.Error(t, err)

	// exactly one action is required: extra positional args are rejected
	err = cmd.Args(&cobra.Command{}, []string{annotateSubCommand, "unexpected"})
	assert.Error(t, err)

	// expected flags are registered
	for _, name := range []string{"namespace", "kind", "target-namespace", "name", "control", "min-severity", "reason", "finding-ref", "confirm"} {
		assert.NotNil(t, cmd.PersistentFlags().Lookup(name), "flag --%s should be registered", name)
	}

	// the findings-driven flags default to empty, so a plain invocation is never
	// silently a cluster-wide selector run
	for _, name := range []string{"control", "min-severity"} {
		value, err := cmd.PersistentFlags().GetString(name)
		assert.NoError(t, err)
		assert.Empty(t, value, "flag --%s should default to empty", name)
	}

	// confirm defaults to false (dry-run is the default; --confirm is the only apply switch)
	confirm, err := cmd.PersistentFlags().GetBool("confirm")
	assert.NoError(t, err)
	assert.False(t, confirm)
}

func TestOperatorRemediateCmd_ContextCanceled(t *testing.T) {
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

	cmd := getOperatorRemediateCmd(&mocks.MockIKubescape{}, cautils.OperatorInfo{})
	cmd.SetArgs([]string{annotateSubCommand, "--kind", "Deployment", "--name", "test-app", "--target-namespace", "default"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := cmd.ExecuteContext(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, ctx, capturedCtx, "constructor must receive the command context")
}

func TestOperatorRemediateCmd_ContextCanceled_NoPortForward(t *testing.T) {
	var startForwarderCalled bool
	prevAdapter := newOperatorAdapter
	newOperatorAdapter = func(scanInfo cautils.OperatorScanInfo, _ string, ctx ...context.Context) (*core.OperatorAdapter, error) {
		conn := &stubOperatorConnector{
			onStart: func() { startForwarderCalled = true },
		}
		return core.NewOperatorAdapterWithConnector(scanInfo, conn), nil
	}
	t.Cleanup(func() { newOperatorAdapter = prevAdapter })

	cmd := getOperatorRemediateCmd(&mocks.MockIKubescape{}, cautils.OperatorInfo{})
	cmd.SetArgs([]string{annotateSubCommand, "--kind", "Deployment", "--name", "test-app", "--target-namespace", "default"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := cmd.ExecuteContext(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, startForwarderCalled, "must not attempt to start port forwarding when context is canceled")
}

func TestOperatorRemediateCmd_CancellationDiagnostic(t *testing.T) {
	prevAdapter := newOperatorAdapter
	newOperatorAdapter = func(scanInfo cautils.OperatorScanInfo, _ string, ctx ...context.Context) (*core.OperatorAdapter, error) {
		conn := &stubOperatorConnector{}
		return core.NewOperatorAdapterWithConnector(scanInfo, conn), nil
	}
	t.Cleanup(func() { newOperatorAdapter = prevAdapter })

	cmd := getOperatorRemediateCmd(&mocks.MockIKubescape{}, cautils.OperatorInfo{})
	cmd.SetArgs([]string{annotateSubCommand, "--kind", "Deployment", "--name", "test-app", "--target-namespace", "default"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var err error
	output := captureLog(t, func() {
		err = cmd.ExecuteContext(ctx)
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Contains(t, output, "Remediation submission canceled; submission outcome is unknown")
	assert.Contains(t, output, "kubectl get events -n default --field-selector reason=KubescapeRemediation")
}
