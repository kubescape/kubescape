package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
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

func TestPolicyTest_NoCasesReturnsError(t *testing.T) {
	for _, tt := range []struct {
		name         string
		rules        []string
		emptyTestDir bool
		update       bool
	}{
		{name: "missing test directory", rules: []string{"rule"}},
		{name: "empty test directory", rules: []string{"rule"}, emptyTestDir: true},
		{name: "multiple rules without cases", rules: []string{"first-rule", "second-rule"}},
		{name: "update without cases", rules: []string{"rule"}, update: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			for _, name := range tt.rules {
				dir := filepath.Join(root, name)
				_, err := runPolicyCmdWithOut(t, "policy", "init", dir)
				require.NoError(t, err)
				testDir := filepath.Join(dir, "test")
				require.NoError(t, os.RemoveAll(testDir))
				if tt.emptyTestDir {
					require.NoError(t, os.Mkdir(testDir, 0o755))
				}
			}

			path := root
			if len(tt.rules) == 1 {
				path = filepath.Join(root, tt.rules[0])
			}
			args := []string{path}
			if tt.update {
				args = append(args, "--update")
			}
			cmd := getPolicyTestCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetArgs(args)
			cmd.SilenceErrors = true

			require.ErrorContains(t, cmd.Execute(), "no test cases", out.String())
		})
	}
}

func TestPolicyTest_MixedRulesRunCases(t *testing.T) {
	root := t.TempDir()
	withoutCases := filepath.Join(root, "without-cases")
	_, err := runPolicyCmdWithOut(t, "policy", "init", withoutCases)
	require.NoError(t, err)
	require.NoError(t, os.RemoveAll(filepath.Join(withoutCases, "test")))
	_, err = runPolicyCmdWithOut(t, "policy", "init", filepath.Join(root, "with-cases"))
	require.NoError(t, err)

	cmd := getPolicyTestCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{root})

	require.NoError(t, cmd.Execute(), out.String())
	assert.Contains(t, out.String(), "PASS")
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
