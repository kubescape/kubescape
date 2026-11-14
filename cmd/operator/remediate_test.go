package operator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/prettylogger"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureLog(t *testing.T, fn func()) string {
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

	buf, err := os.CreateTemp(t.TempDir(), "log-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = buf.Close() })
	logger.L().SetWriter(buf)

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
	assert.Nil(t, cmd.Args(&cobra.Command{}, []string{patchSubCommand}))
	assert.Nil(t, cmd.Args(&cobra.Command{}, []string{quarantineSubCommand}))
	assert.Nil(t, cmd.Args(&cobra.Command{}, []string{revertSubCommand}))

	// unknown action is rejected
	err = cmd.Args(&cobra.Command{}, []string{"explode"})
	assert.Error(t, err)

	// exactly one action is required: extra positional args are rejected
	err = cmd.Args(&cobra.Command{}, []string{annotateSubCommand, "unexpected"})
	assert.Error(t, err)

	// expected flags are registered
	for _, name := range []string{"namespace", "kind", "target-namespace", "name", "control", "min-severity", "reason", "finding-ref", "patch", "patch-type", "confirm"} {
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

func TestOperatorRemediateCmd_ContextCanceled_NoCommandsCreated(t *testing.T) {
	op := newFakeOperator(t, "")
	op.install(t)

	cmd := getOperatorRemediateCmd(&mocks.MockIKubescape{}, cautils.OperatorInfo{})
	cmd.SetArgs([]string{annotateSubCommand, "--kind", "Deployment", "--name", "test-app", "--target-namespace", "default"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := cmd.ExecuteContext(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, op.created(t), "must not create operator commands when context is canceled")
}

func TestOperatorRemediateCmd_CancellationDiagnostic(t *testing.T) {
	op := newFakeOperator(t, "")
	op.install(t)

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

// TestOperatorRemediateCmd_RunE_InvalidArgsCount verifies error reporting when not exactly one action argument is passed.
func TestOperatorRemediateCmd_RunE_InvalidArgsCount(t *testing.T) {
	cmd := getOperatorRemediateCmd(&mocks.MockIKubescape{}, cautils.OperatorInfo{})
	err := cmd.RunE(&cobra.Command{}, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "for the operator remediate sub-command, you must pass exactly one action")

	err = cmd.RunE(&cobra.Command{}, []string{"annotate", "extra"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "for the operator remediate sub-command, you must pass exactly one action")
}

// TestOperatorRemediateCmd_PayloadValidationErrors verifies validation error cases for targets and selectors.
func TestOperatorRemediateCmd_PayloadValidationErrors(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		errContains string
	}{
		{
			name:        "no target or selector",
			args:        []string{"annotate"},
			errContains: "remediation requires a target",
		},
		{
			name:        "both target and selector",
			args:        []string{"annotate", "--kind", "Deployment", "--name", "api", "--target-namespace", "default", "--control", "C-0016"},
			errContains: "mutually exclusive",
		},
		{
			name:        "selector with target-namespace",
			args:        []string{"quarantine", "--control", "C-0016", "--target-namespace", "default"},
			errContains: "--target-namespace cannot be combined with --control/--min-severity",
		},
		{
			name:        "unsupported target kind",
			args:        []string{"annotate", "--kind", "ConfigMap", "--name", "api", "--target-namespace", "default"},
			errContains: "unsupported target kind",
		},
		{
			name:        "missing target-namespace",
			args:        []string{"annotate", "--kind", "Deployment", "--name", "api"},
			errContains: "requires --target-namespace",
		},
		{
			name:        "missing name",
			args:        []string{"annotate", "--kind", "Deployment", "--target-namespace", "default"},
			errContains: "remediation target requires --kind and --name",
		},
		{
			name:        "patch without patch body",
			args:        []string{"patch", "--kind", "Deployment", "--name", "api", "--target-namespace", "default"},
			errContains: "patch remediation requires --patch",
		},
		{
			name:        "patch with invalid json",
			args:        []string{"patch", "--kind", "Deployment", "--name", "api", "--target-namespace", "default", "--patch", "invalid-json"},
			errContains: "invalid --patch",
		},
		{
			name:        "patch with null json",
			args:        []string{"patch", "--kind", "Deployment", "--name", "api", "--target-namespace", "default", "--patch", "null"},
			errContains: "invalid --patch",
		},
		{
			name:        "patch with non-object json",
			args:        []string{"patch", "--kind", "Deployment", "--name", "api", "--target-namespace", "default", "--patch", `["array"]`},
			errContains: "invalid --patch",
		},
		{
			name:        "patch with unsupported patch-type",
			args:        []string{"patch", "--kind", "Deployment", "--name", "api", "--target-namespace", "default", "--patch", `{"spec":{}}`, "--patch-type", "jsonpatch"},
			errContains: "unsupported --patch-type",
		},
		{
			name:        "annotate with patch flag",
			args:        []string{"annotate", "--kind", "Deployment", "--name", "api", "--target-namespace", "default", "--patch", `{"spec":{}}`},
			errContains: "--patch is only supported with the \"patch\" action",
		},
		{
			name:        "annotate with patch-type flag",
			args:        []string{"annotate", "--kind", "Deployment", "--name", "api", "--target-namespace", "default", "--patch-type", "merge"},
			errContains: "--patch-type is only supported with the \"patch\" action",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := getOperatorRemediateCmd(&mocks.MockIKubescape{}, cautils.OperatorInfo{})
			cmd.SetArgs(tt.args)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)

			err := cmd.Execute()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

// TestOperatorRemediateCmd_ReasonWarning verifies warning output when --reason is omitted for annotate, patch and quarantine.
func TestOperatorRemediateCmd_ReasonWarning(t *testing.T) {
	for _, action := range []string{annotateSubCommand, patchSubCommand, quarantineSubCommand} {
		t.Run(action, func(t *testing.T) {
			op := newFakeOperator(t, "")
			op.install(t)

			cmd := getOperatorRemediateCmd(&mocks.MockIKubescape{}, cautils.OperatorInfo{})
			args := []string{action, "--kind", "Deployment", "--name", "api", "--target-namespace", "default"}
			if action == patchSubCommand {
				args = append(args, "--patch", `{"spec":{"replicas":1}}`)
			}
			cmd.SetArgs(args)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)

			var err error
			output := captureLog(t, func() {
				err = cmd.Execute()
			})

			require.NoError(t, err)
			assert.Contains(t, output, fmt.Sprintf("no --reason provided; %s records an audit trail, consider adding --reason to justify the action", action))
			assert.Contains(t, output, fmt.Sprintf("Previewing remediation %q via Kubescape Operator", action))
			assert.Contains(t, output, "Submitted remediation (dry-run)")
			assert.Contains(t, output, "kubectl get events -n default --field-selector reason=KubescapeRemediation")
		})
	}
}

// TestOperatorRemediateCmd_PatchSuccess verifies successful execution of patch remediation in dry-run and apply modes.
func TestOperatorRemediateCmd_PatchSuccess(t *testing.T) {
	for _, confirm := range []bool{false, true} {
		name := "dry-run"
		if confirm {
			name = "apply"
		}
		t.Run(name, func(t *testing.T) {
			op := newFakeOperator(t, "")
			op.install(t)

			cmd := getOperatorRemediateCmd(&mocks.MockIKubescape{}, cautils.OperatorInfo{})
			args := []string{"patch", "--kind", "Deployment", "--name", "api", "--target-namespace", "default", "--patch", `{"spec":{"replicas":2}}`, "--patch-type", "merge", "--reason", "scale up"}
			if confirm {
				args = append(args, "--confirm")
			}
			cmd.SetArgs(args)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)

			var err error
			output := captureLog(t, func() {
				err = cmd.Execute()
			})

			require.NoError(t, err)
			if confirm {
				assert.Contains(t, output, "Applying remediation \"patch\" via Kubescape Operator")
				assert.Contains(t, output, "Submitted remediation (apply)")
			} else {
				assert.Contains(t, output, "Previewing remediation \"patch\" via Kubescape Operator")
				assert.Contains(t, output, "Submitted remediation (dry-run)")
			}
		})
	}
}

// TestOperatorRemediateCmd_SelectorClusterWideWarningAndEvents verifies cluster-wide warning and events scope for selectors.
func TestOperatorRemediateCmd_SelectorClusterWideWarningAndEvents(t *testing.T) {
	op := newFakeOperator(t, "")
	op.install(t)

	cmd := getOperatorRemediateCmd(&mocks.MockIKubescape{}, cautils.OperatorInfo{})
	cmd.SetArgs([]string{quarantineSubCommand, "--control", "C-0016", "--min-severity", "High", "--confirm"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	var err error
	output := captureLog(t, func() {
		err = cmd.Execute()
	})

	require.NoError(t, err)
	assert.Contains(t, output, "applying \"quarantine\" to every workload matching the selector, across all namespaces")
	assert.Contains(t, output, "Applying remediation \"quarantine\" via Kubescape Operator")
	assert.Contains(t, output, "Submitted remediation (apply)")
	assert.Contains(t, output, "kubectl get events --all-namespaces --field-selector reason=KubescapeRemediation")
}

// TestOperatorRemediateCmd_AdapterCreationError verifies error propagation when adapter creation fails.
func TestOperatorRemediateCmd_AdapterCreationError(t *testing.T) {
	prevAdapter := newOperatorAdapter
	newOperatorAdapter = func(_ cautils.OperatorScanInfo, _ string, _ ...context.Context) (*core.OperatorAdapter, error) {
		return nil, errors.New("cannot create adapter for remediation")
	}
	t.Cleanup(func() { newOperatorAdapter = prevAdapter })

	cmd := getOperatorRemediateCmd(&mocks.MockIKubescape{}, cautils.OperatorInfo{})
	cmd.SetArgs([]string{revertSubCommand, "--kind", "Deployment", "--name", "api", "--target-namespace", "default"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot create adapter for remediation")
}

// TestOperatorRemediateCmd_GenericScanError verifies error reporting when remediation submission returns an error.
func TestOperatorRemediateCmd_GenericScanError(t *testing.T) {
	op := newFakeOperator(t, "scan blew up")
	op.install(t)

	cmd := getOperatorRemediateCmd(&mocks.MockIKubescape{}, cautils.OperatorInfo{})
	cmd.SetArgs([]string{revertSubCommand, "--kind", "Deployment", "--name", "api", "--target-namespace", "default"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	var err error
	output := captureLog(t, func() {
		err = cmd.Execute()
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed: scan blew up")
	assert.Contains(t, output, "Failed to submit remediation to Kubescape Operator")
}
