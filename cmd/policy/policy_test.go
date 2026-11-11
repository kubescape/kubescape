package policy

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()

	root := &cobra.Command{Use: "kubescape"}
	root.AddCommand(GetPolicyCmd())

	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs(args)

	err := root.Execute()
	return out.String(), err
}

func TestPolicyInit_ScaffoldsRuleThatPassesTest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-privileged-containers")

	out, err := runCmd(t, "policy", "init", dir)
	require.NoError(t, err)
	assert.Contains(t, out, "wrote")
	assert.Contains(t, out, "raw.rego")
	assert.Contains(t, out, "expected.json")

	out, err = runCmd(t, "policy", "test", dir)
	require.NoError(t, err)
	assert.Contains(t, out, "2/2 cases passed")
}

func TestPolicyInit_HonoursKindFlag(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-privileged-pods")

	_, err := runCmd(t, "policy", "init", dir, "--kind", "Pod")
	require.NoError(t, err)

	metadata, err := os.ReadFile(filepath.Join(dir, "rule.metadata.json"))
	require.NoError(t, err)
	assert.Contains(t, string(metadata), `"Pod"`)

	_, err = runCmd(t, "policy", "test", dir)
	require.NoError(t, err)
}

func TestPolicyInit_RejectsUnsupportedKind(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "check-service")

	_, err := runCmd(t, "policy", "init", dir, "--kind", "Service")
	require.ErrorContains(t, err, "unsupported kind")
}

func TestPolicyTestUpdate_RewritesExpectations(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-privileged-containers")
	_, err := runCmd(t, "policy", "init", dir)
	require.NoError(t, err)

	expected := filepath.Join(dir, "test", "flagged", "expected.json")
	require.NoError(t, os.WriteFile(expected, []byte("[]\n"), 0o600))

	_, err = runCmd(t, "policy", "test", dir)
	require.Error(t, err)

	out, err := runCmd(t, "policy", "test", dir, "--update")
	require.NoError(t, err)
	assert.Contains(t, out, "UPDATED")
	assert.Contains(t, out, "1 case(s) updated")

	_, err = runCmd(t, "policy", "test", dir)
	require.NoError(t, err)
}

func TestPolicyTestUpdate_IsIdempotent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-privileged-containers")
	_, err := runCmd(t, "policy", "init", dir)
	require.NoError(t, err)

	out, err := runCmd(t, "policy", "test", dir, "--update")
	require.NoError(t, err)
	assert.Contains(t, out, "UNCHANGED")
	assert.Contains(t, out, "0 case(s) updated")
}

func TestPolicyTest_RunSelectsMatchingCases(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-privileged-containers")
	_, err := runCmd(t, "policy", "init", dir)
	require.NoError(t, err)
	// Break the case --run leaves out, so the first run only passes if it is skipped.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test", "flagged", "expected.json"), []byte("[]\n"), 0o600))

	out, err := runCmd(t, "policy", "test", dir, "--run", "^no-privileged-containers/clean$")
	require.NoError(t, err, out)
	assert.Contains(t, out, "PASS no-privileged-containers/clean")
	assert.NotContains(t, out, "flagged")
	assert.Contains(t, out, "1/1 cases passed")

	out, err = runCmd(t, "policy", "test", dir, "--run", "flagged")
	require.ErrorContains(t, err, "1 test case(s) failed")
	assert.Contains(t, out, "FAIL no-privileged-containers/flagged")
	assert.NotContains(t, out, "/clean")
}

func TestPolicyTestUpdate_RunRewritesOnlyMatchingCases(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-privileged-containers")
	_, err := runCmd(t, "policy", "init", dir)
	require.NoError(t, err)

	flagged := filepath.Join(dir, "test", "flagged", "expected.json")
	clean := filepath.Join(dir, "test", "clean", "expected.json")
	require.NoError(t, os.WriteFile(flagged, []byte("[]\n"), 0o600))
	require.NoError(t, os.WriteFile(clean, []byte("not json\n"), 0o600))

	out, err := runCmd(t, "policy", "test", dir, "--update", "--run", "/flagged$")
	require.NoError(t, err, out)
	assert.Contains(t, out, "UPDATED no-privileged-containers/flagged")
	assert.NotContains(t, out, "/clean")
	assert.Contains(t, out, "1 case(s) updated")

	got, err := os.ReadFile(clean)
	require.NoError(t, err)
	assert.Equal(t, "not json\n", string(got), "a case --run does not select must be left untouched")

	_, err = runCmd(t, "policy", "test", dir, "--run", "/flagged$")
	require.NoError(t, err)
}

func TestPolicyTest_RunWithoutMatchesReturnsError(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-privileged-containers")
	_, err := runCmd(t, "policy", "init", dir)
	require.NoError(t, err)

	for _, args := range [][]string{
		{"policy", "test", dir, "--run", "no-such-case"},
		{"policy", "test", dir, "--run", "no-such-case", "--update"},
	} {
		t.Run(strings.Join(args[3:], " "), func(t *testing.T) {
			out, err := runCmd(t, args...)
			require.ErrorContains(t, err, `match --run "no-such-case"`)
			assert.NotContains(t, out, "Usage:")
			assert.NotContains(t, out, "cases passed")
			assert.NotContains(t, out, "case(s) updated")
		})
	}
}

func TestPolicyTest_RejectsInvalidRunPattern(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-privileged-containers")
	_, err := runCmd(t, "policy", "init", dir)
	require.NoError(t, err)

	out, err := runCmd(t, "policy", "test", dir, "--run", "flagged(")
	require.ErrorContains(t, err, "invalid --run pattern")
	assert.Contains(t, out, "Usage:")
}

func TestPolicyTest_ReportsMissingRules(t *testing.T) {
	_, err := runCmd(t, "policy", "test", t.TempDir())
	require.ErrorContains(t, err, "no rule directories")
}

func TestPolicy_RuntimeFailuresDoNotPrintUsage(t *testing.T) {
	scaffold := func(t *testing.T) string {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "no-privileged-containers")
		_, err := runCmd(t, "policy", "init", dir)
		require.NoError(t, err)
		return dir
	}

	tests := []struct {
		name    string
		args    func(t *testing.T) []string
		wantErr string
	}{
		{
			name: "test with a failing case",
			args: func(t *testing.T) []string {
				dir := scaffold(t)
				require.NoError(t, os.WriteFile(filepath.Join(dir, "test", "flagged", "expected.json"), []byte("[]\n"), 0o600))
				return []string{"policy", "test", dir}
			},
			wantErr: "1 test case(s) failed",
		},
		{
			name: "test --update with a case that cannot be evaluated",
			args: func(t *testing.T) []string {
				dir := scaffold(t)
				require.NoError(t, os.WriteFile(filepath.Join(dir, "test", "flagged", "input", "resource.yaml"), []byte("bad: [yaml\n"), 0o600))
				return []string{"policy", "test", dir, "--update"}
			},
			wantErr: "1 test case(s) could not be evaluated",
		},
		{
			name: "test without rules",
			args: func(t *testing.T) []string {
				return []string{"policy", "test", t.TempDir()}
			},
			wantErr: "no rule directories",
		},
		{
			name: "init over an existing rule",
			args: func(t *testing.T) []string {
				return []string{"policy", "init", scaffold(t)}
			},
			wantErr: "--force",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := runCmd(t, tt.args(t)...)
			require.ErrorContains(t, err, tt.wantErr)
			assert.NotContains(t, out, "Usage:")
		})
	}
}

func TestPolicy_ArgumentErrorsPrintUsage(t *testing.T) {
	for _, args := range [][]string{
		{"policy", "test"},
		{"policy", "init"},
		{"policy", "init", "one", "two"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			out, err := runCmd(t, args...)
			require.Error(t, err)
			assert.Contains(t, out, "Usage:")
		})
	}
}
