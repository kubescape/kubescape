package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
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

// policyResultWriter simulates an output destination failing either immediately
// or only when the command writes its final summary.
type policyResultWriter struct {
	summaryOnly bool
	err         error
}

func (w policyResultWriter) Write(p []byte) (int, error) {
	if !w.summaryOnly || strings.Contains(string(p), "cases passed") || strings.Contains(string(p), "case(s) updated") {
		return 0, w.err
	}
	return len(p), nil
}

func TestPolicyTestCmd_ReturnsOutputErrors(t *testing.T) {
	for _, update := range []bool{false, true} {
		for _, summaryOnly := range []bool{false, true} {
			for _, color := range []string{"0", "1"} {
				name := fmt.Sprintf("update=%t/summary=%t/color=%s", update, summaryOnly, color)
				t.Run(name, func(t *testing.T) {
					setupColorTest(t)
					t.Setenv("FORCE_COLOR", color)
					dir := filepath.Join(t.TempDir(), "rule")
					_, err := runPolicyCmdWithOut(t, "policy", "init", dir)
					require.NoError(t, err)
					writeErr := errors.New("output destination unavailable")
					cmd := getPolicyTestCmd()
					cmd.SetOut(policyResultWriter{summaryOnly: summaryOnly, err: writeErr})
					cmd.SilenceErrors = true
					args := []string{dir}
					if update {
						args = append(args, "--update")
					}
					cmd.SetArgs(args)
					require.ErrorIs(t, cmd.Execute(), writeErr)
				})
			}
		}
	}
}
