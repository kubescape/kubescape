package policy

import (
	"bytes"
	"os"
	"path/filepath"
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

func TestPolicyTest_ReportsMissingRules(t *testing.T) {
	_, err := runCmd(t, "policy", "test", t.TempDir())
	require.ErrorContains(t, err, "no rule directories")
}
