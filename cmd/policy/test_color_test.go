package policy

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/jwalton/gchalk"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func setupColorTest(t *testing.T) {
	t.Helper()
	oldLevel := gchalk.GetLevel()
	t.Cleanup(func() {
		gchalk.SetLevel(oldLevel)
	})
	gchalk.SetLevel(gchalk.LevelAnsi256)
	t.Setenv("FORCE_COLOR", "1")
	if oldNoColor, set := os.LookupEnv("NO_COLOR"); set {
		_ = os.Unsetenv("NO_COLOR")
		t.Cleanup(func() {
			_ = os.Setenv("NO_COLOR", oldNoColor)
		})
	}
}

func runPolicyCmdWithOut(t *testing.T, args ...string) (string, error) {
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

func TestPolicyTest_PassIsGreen(t *testing.T) {
	setupColorTest(t)
	dir := filepath.Join(t.TempDir(), "rule-pass")
	_, err := runPolicyCmdWithOut(t, "policy", "init", dir)
	require.NoError(t, err)

	out, err := runPolicyCmdWithOut(t, "policy", "test", dir)
	require.NoError(t, err)

	assert.True(t, ansiRegex.MatchString(out), "output should contain ANSI escape codes")
	assert.Contains(t, out, gchalk.WithBrightGreen().Bold("PASS"))
	assert.Contains(t, out, gchalk.WithBrightGreen().Bold("2"))
	assert.Contains(t, out, gchalk.Bold("2"))
	assert.Contains(t, out, "cases passed")
}

func TestPolicyTest_FailIsRed(t *testing.T) {
	setupColorTest(t)
	dir := filepath.Join(t.TempDir(), "rule-fail")
	_, err := runPolicyCmdWithOut(t, "policy", "init", dir)
	require.NoError(t, err)

	// Corrupt expected.json so test fails
	expected := filepath.Join(dir, "test", "flagged", "expected.json")
	require.NoError(t, os.WriteFile(expected, []byte("[]\n"), 0o600))

	out, err := runPolicyCmdWithOut(t, "policy", "test", dir)
	require.Error(t, err)

	assert.True(t, ansiRegex.MatchString(out), "output should contain ANSI escape codes")
	assert.Contains(t, out, gchalk.WithBrightRed().Bold("FAIL"))
	assert.Contains(t, out, gchalk.WithBrightGreen().Bold("PASS"))
	assert.Contains(t, out, gchalk.WithBrightGreen().Bold("1"))
	assert.Contains(t, out, gchalk.Bold("2"))
}

func TestPolicyTest_AllFailShowsRedCount(t *testing.T) {
	setupColorTest(t)
	dir := filepath.Join(t.TempDir(), "rule-all-fail")
	_, err := runPolicyCmdWithOut(t, "policy", "init", dir)
	require.NoError(t, err)

	// Corrupt both expected.json files so 0 cases pass
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test", "flagged", "expected.json"), []byte("[]\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test", "clean", "expected.json"), []byte(`[{"extra": true}]`+"\n"), 0o600))

	out, err := runPolicyCmdWithOut(t, "policy", "test", dir)
	require.Error(t, err)

	assert.Contains(t, out, gchalk.WithBrightRed().Bold("FAIL"))
	assert.Contains(t, out, gchalk.WithBrightRed().Bold("0"))
	assert.Contains(t, out, gchalk.Bold("2"))
}

func TestPolicyUpdate_BadgesColored(t *testing.T) {
	setupColorTest(t)
	dir := filepath.Join(t.TempDir(), "rule-update")
	_, err := runPolicyCmdWithOut(t, "policy", "init", dir)
	require.NoError(t, err)

	// Corrupt expected.json to trigger UPDATED
	expected := filepath.Join(dir, "test", "flagged", "expected.json")
	require.NoError(t, os.WriteFile(expected, []byte("[]\n"), 0o600))

	out, err := runPolicyCmdWithOut(t, "policy", "test", dir, "--update")
	require.NoError(t, err)

	assert.Contains(t, out, gchalk.WithBrightYellow().Bold("UPDATED"))
	assert.Contains(t, out, gchalk.Bold("UNCHANGED"))
	assert.Contains(t, out, gchalk.WithBrightYellow().Bold("1"))
	assert.Contains(t, out, "case(s) updated")

	// Running update again is idempotent -> UNCHANGED
	out2, err := runPolicyCmdWithOut(t, "policy", "test", dir, "--update")
	require.NoError(t, err)
	assert.NotContains(t, out2, gchalk.WithBrightYellow().Bold("UPDATED"))
	assert.Contains(t, out2, gchalk.Bold("UNCHANGED"))
	assert.Contains(t, out2, gchalk.Bold("0"))
}

func TestPolicyInit_WroteIsGreenAndCyan(t *testing.T) {
	setupColorTest(t)
	dir := filepath.Join(t.TempDir(), "rule-init")

	out, err := runPolicyCmdWithOut(t, "policy", "init", dir)
	require.NoError(t, err)

	assert.True(t, ansiRegex.MatchString(out), "output should contain ANSI escape codes")
	assert.Contains(t, out, gchalk.WithBrightGreen().Bold("wrote"))
	assert.Contains(t, out, gchalk.BrightCyan(filepath.Join(dir, "raw.rego")))
	assert.Contains(t, out, gchalk.WithBrightWhite().Bold("kubescape policy test "+dir))
}

func TestPolicy_NoColorEnvTakesPrecedence(t *testing.T) {
	setupColorTest(t)
	t.Setenv("NO_COLOR", "1")

	dir := filepath.Join(t.TempDir(), "rule-nocolor")
	out, err := runPolicyCmdWithOut(t, "policy", "init", dir)
	require.NoError(t, err)
	assert.False(t, ansiRegex.MatchString(out), "init output must not contain ANSI with NO_COLOR")

	out, err = runPolicyCmdWithOut(t, "policy", "test", dir)
	require.NoError(t, err)
	assert.False(t, ansiRegex.MatchString(out), "test output must not contain ANSI with NO_COLOR")
}

func TestPolicy_DestinationFileNotTerminal(t *testing.T) {
	// Without FORCE_COLOR, writing to a file should not output ANSI
	if _, set := os.LookupEnv("FORCE_COLOR"); set {
		_ = os.Unsetenv("FORCE_COLOR")
		t.Cleanup(func() { _ = os.Setenv("FORCE_COLOR", "1") })
	}
	if _, set := os.LookupEnv("NO_COLOR"); set {
		_ = os.Unsetenv("NO_COLOR")
	}

	dir := filepath.Join(t.TempDir(), "rule-file")
	_, err := runPolicyCmdWithOut(t, "policy", "init", dir)
	require.NoError(t, err)

	tmpFile, err := os.Create(filepath.Join(t.TempDir(), "out.txt"))
	require.NoError(t, err)
	defer tmpFile.Close()

	root := &cobra.Command{Use: "kubescape"}
	root.AddCommand(GetPolicyCmd())
	root.SetOut(tmpFile)
	root.SetErr(tmpFile)
	root.SetArgs([]string{"policy", "test", dir})

	err = root.Execute()
	require.NoError(t, err)

	content, err := os.ReadFile(tmpFile.Name())
	require.NoError(t, err)
	assert.False(t, ansiRegex.MatchString(string(content)), "file destination should not contain ANSI codes")
	assert.Contains(t, string(content), "PASS")
	assert.Contains(t, string(content), "2/2 cases passed")
}

func TestShouldColor_ForceColorVariations(t *testing.T) {
	oldLevel := gchalk.GetLevel()
	defer gchalk.SetLevel(oldLevel)
	gchalk.SetLevel(gchalk.LevelAnsi256)

	tmpFile, err := os.Create(filepath.Join(t.TempDir(), "check.txt"))
	require.NoError(t, err)
	defer tmpFile.Close()

	// Isolate from inherited NO_COLOR
	if old, set := os.LookupEnv("NO_COLOR"); set {
		_ = os.Unsetenv("NO_COLOR")
		defer os.Setenv("NO_COLOR", old)
	}

	// 1. FORCE_COLOR unset on non-terminal file -> false
	_ = os.Unsetenv("FORCE_COLOR")
	assert.False(t, shouldColor(tmpFile), "unset FORCE_COLOR on file should be false")

	// 2. FORCE_COLOR empty string -> true
	t.Setenv("FORCE_COLOR", "")
	assert.True(t, shouldColor(tmpFile), "empty string FORCE_COLOR should force color")

	// 3. FORCE_COLOR="0" -> false
	t.Setenv("FORCE_COLOR", "0")
	assert.False(t, shouldColor(tmpFile), "FORCE_COLOR=0 should disable color")

	// 4. FORCE_COLOR="1" -> true
	t.Setenv("FORCE_COLOR", "1")
	assert.True(t, shouldColor(tmpFile), "FORCE_COLOR=1 should force color")

	// 5. NO_COLOR set takes precedence over FORCE_COLOR
	t.Setenv("NO_COLOR", "1")
	assert.False(t, shouldColor(tmpFile), "NO_COLOR should take precedence over FORCE_COLOR")
}
