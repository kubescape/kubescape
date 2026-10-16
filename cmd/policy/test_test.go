package policy

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyTestCmd_PassingRuleReturnsNoError(t *testing.T) {
	dir, err := filepath.Abs("../../rules/modify-node-status-v1")
	require.NoError(t, err)

	cmd := getPolicyTestCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{dir})

	err = cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "cases passed")
}

func TestPolicyTestCmd_AllInTreeRulesPass(t *testing.T) {
	dir, err := filepath.Abs("../../rules")
	require.NoError(t, err)

	cmd := getPolicyTestCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{dir})
	cmd.SilenceUsage = true

	err = cmd.Execute()
	require.NoError(t, err, out.String())
	assert.Regexp(t, `\n[1-9][0-9]*/[1-9][0-9]* cases passed\n`, out.String())
}

func TestPolicyTestCmd_MissingPathReturnsError(t *testing.T) {
	cmd := getPolicyTestCmd()
	cmd.SetArgs([]string{"/nonexistent/path/for/policy/test"})
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true

	err := cmd.Execute()
	assert.Error(t, err)
}

func TestPolicyTestCmd_ContextCanceledReturnsError(t *testing.T) {
	dir, err := filepath.Abs("../../rules")
	require.NoError(t, err)

	cmd := getPolicyTestCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{dir})
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = cmd.ExecuteContext(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestPolicyUpdateCmd_ContextCanceledReturnsError(t *testing.T) {
	dir, err := filepath.Abs("../../rules")
	require.NoError(t, err)

	cmd := getPolicyTestCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{dir, "--update"})
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = cmd.ExecuteContext(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}
