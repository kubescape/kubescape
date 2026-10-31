package version

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	"github.com/jwalton/gchalk"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHelperProcess_Version(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	ks := core.NewKubescape(context.Background())
	cmd := GetVersionCmd(ks, "v3.0.1", "abc1234", "2026-10-30")
	cmd.SetArgs([]string{"--format", "text"})
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestGetVersionCmd_TextOutput_WithColor(t *testing.T) {
	t.Setenv("KS_SKIP_UPDATE_CHECK", "true")
	if orig, ok := os.LookupEnv("NO_COLOR"); ok {
		os.Unsetenv("NO_COLOR")
		t.Cleanup(func() {
			_ = os.Setenv("NO_COLOR", orig)
		})
	}
	t.Setenv("FORCE_COLOR", "1")
	prevLevel := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prevLevel)

	ks := core.NewKubescape(context.Background())
	cmd := GetVersionCmd(ks, "v3.0.1", "abc1234", "2026-10-30")
	require.NotNil(t, cmd)

	buf := bytes.NewBufferString("")
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"--format", "text"})
	require.NoError(t, cmd.Execute())

	out, err := io.ReadAll(buf)
	require.NoError(t, err)

	outStr := string(out)
	assert.Contains(t, outStr, "Your current version is: "+gchalk.WithBrightGreen().Bold("v3.0.1"))
	assert.Contains(t, outStr, "Build commit: "+gchalk.BrightCyan("abc1234"))
	assert.Contains(t, outStr, "Build date: "+gchalk.BrightWhite("2026-10-30"))
}

func TestGetVersionCmd_TextOutput_NoColorPrecedence(t *testing.T) {
	t.Setenv("KS_SKIP_UPDATE_CHECK", "true")
	t.Setenv("FORCE_COLOR", "1")
	t.Setenv("NO_COLOR", "1")
	prevLevel := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prevLevel)

	ks := core.NewKubescape(context.Background())
	cmd := GetVersionCmd(ks, "v3.0.1", "abc1234", "2026-10-30")
	require.NotNil(t, cmd)

	buf := bytes.NewBufferString("")
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"--format", "text"})
	require.NoError(t, cmd.Execute())

	out, err := io.ReadAll(buf)
	require.NoError(t, err)

	outStr := string(out)
	assert.NotContains(t, outStr, "\x1b[", "NO_COLOR must ensure zero ANSI escape sequences")
	assert.Contains(t, outStr, "Your current version is: v3.0.1")
	assert.Contains(t, outStr, "Build commit: abc1234")
	assert.Contains(t, outStr, "Build date: 2026-10-30")
}

func TestGetVersionCmd_TextOutput_EmptyNoColorTreatedAsUnset(t *testing.T) {
	t.Setenv("KS_SKIP_UPDATE_CHECK", "true")
	if orig, ok := os.LookupEnv("NO_COLOR"); ok {
		t.Cleanup(func() {
			_ = os.Setenv("NO_COLOR", orig)
		})
	}
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "1")
	prevLevel := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prevLevel)

	ks := core.NewKubescape(context.Background())
	cmd := GetVersionCmd(ks, "v3.0.1", "abc1234", "2026-10-30")
	require.NotNil(t, cmd)

	buf := bytes.NewBufferString("")
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"--format", "text"})
	require.NoError(t, cmd.Execute())

	out, err := io.ReadAll(buf)
	require.NoError(t, err)

	outStr := string(out)
	assert.Contains(t, outStr, "Your current version is: "+gchalk.WithBrightGreen().Bold("v3.0.1"))
	assert.Contains(t, outStr, "Build commit: "+gchalk.BrightCyan("abc1234"))
	assert.Contains(t, outStr, "Build date: "+gchalk.BrightWhite("2026-10-30"))
}

func TestGetVersionCmd_TextOutput_RedirectedUnforcedNoANSI(t *testing.T) {
	t.Setenv("KS_SKIP_UPDATE_CHECK", "true")
	t.Setenv("FORCE_COLOR", "")
	t.Setenv("NO_COLOR", "")
	os.Unsetenv("FORCE_COLOR")
	os.Unsetenv("NO_COLOR")
	prevLevel := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prevLevel)

	ks := core.NewKubescape(context.Background())
	cmd := GetVersionCmd(ks, "v3.0.1", "abc1234", "2026-10-30")
	require.NotNil(t, cmd)

	buf := bytes.NewBufferString("")
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"--format", "text"})
	require.NoError(t, cmd.Execute())

	out, err := io.ReadAll(buf)
	require.NoError(t, err)

	outStr := string(out)
	assert.NotContains(t, outStr, "\x1b[", "redirected text output must have zero ANSI escapes")
	assert.Contains(t, outStr, "Your current version is: v3.0.1")
}

func TestGetVersionCmd_ExportPathsHaveZeroANSI(t *testing.T) {
	t.Setenv("KS_SKIP_UPDATE_CHECK", "true")
	t.Setenv("FORCE_COLOR", "1")
	prevLevel := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prevLevel)

	ks := core.NewKubescape(context.Background())

	// JSON format check
	jsonCmd := GetVersionCmd(ks, "v3.0.1", "abc1234", "2026-10-30")
	jsonBuf := bytes.NewBufferString("")
	jsonCmd.SetOut(jsonBuf)
	jsonCmd.SetArgs([]string{"--format", "json"})
	require.NoError(t, jsonCmd.Execute())

	jsonOut, err := io.ReadAll(jsonBuf)
	require.NoError(t, err)
	assert.NotContains(t, string(jsonOut), "\x1b[", "JSON export must have zero ANSI codes")

	// YAML format check
	yamlCmd := GetVersionCmd(ks, "v3.0.1", "abc1234", "2026-10-30")
	yamlBuf := bytes.NewBufferString("")
	yamlCmd.SetOut(yamlBuf)
	yamlCmd.SetArgs([]string{"--format", "yaml"})
	require.NoError(t, yamlCmd.Execute())

	yamlOut, err := io.ReadAll(yamlBuf)
	require.NoError(t, err)
	assert.NotContains(t, string(yamlOut), "\x1b[", "YAML export must have zero ANSI codes")
}
