package update

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	"github.com/jwalton/gchalk"
	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHelperProcess_Update(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	mode := os.Getenv("TEST_UPDATE_MODE")
	switch mode {
	case "latest":
		versioncheck.BuildNumber = "v3.0.0"
		versioncheck.LatestReleaseVersion = "v3.0.0"
		newVersionCheckHandler = func() versioncheck.IVersionCheckHandler {
			return &stubVersionCheckHandler{latest: "v3.0.0"}
		}
	case "available":
		versioncheck.BuildNumber = "v3.0.0"
		versioncheck.LatestReleaseVersion = "v3.1.0"
		newVersionCheckHandler = func() versioncheck.IVersionCheckHandler {
			return &stubVersionCheckHandler{latest: "v3.1.0"}
		}
	}
	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	cmd.SetArgs([]string{"--format", "text"})
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestGetUpdateCmd_TextOutput_AvailableReleaseWithColor(t *testing.T) {
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

	withVersionCheckHandler(t, &stubVersionCheckHandler{latest: "v3.1.0"})
	withVersionGlobals(t, "v3.0.0", "")

	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	require.NotNil(t, cmd)

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--format", "text"})
	require.NoError(t, cmd.Execute())

	outStr := buf.String()
	assert.Contains(t, outStr, "Version "+gchalk.WithBrightGreen().Bold("v3.1.0")+" is available")
	assert.Contains(t, outStr, "Please refer to our installation documentation: "+gchalk.BrightCyan(installationLink))
}

func TestGetUpdateCmd_TextOutput_DevBuildWithColor(t *testing.T) {
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

	withVersionCheckHandler(t, versioncheck.NewVersionCheckHandlerMock())
	withVersionGlobals(t, "dev", "v3.1.0")

	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	require.NotNil(t, cmd)

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--format", "text"})
	require.NoError(t, cmd.Execute())

	outStr := buf.String()
	assert.Contains(t, outStr, gchalk.BrightYellow("Nothing to update")+": you are running the development version")
}

func TestGetUpdateCmd_TextOutput_LatestVersionWithColor(t *testing.T) {
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

	withVersionCheckHandler(t, &stubVersionCheckHandler{latest: "v3.0.0"})
	withVersionGlobals(t, "v3.0.0", "")

	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	require.NotNil(t, cmd)

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--format", "text"})
	require.NoError(t, cmd.Execute())

	outStr := buf.String()
	assert.Contains(t, outStr, gchalk.BrightYellow("Nothing to update")+": you are running the latest version")
}

func TestGetUpdateCmd_TextOutput_NoColorPrecedence(t *testing.T) {
	t.Setenv("FORCE_COLOR", "1")
	t.Setenv("NO_COLOR", "1")
	prevLevel := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prevLevel)

	withVersionCheckHandler(t, &stubVersionCheckHandler{latest: "v3.1.0"})
	withVersionGlobals(t, "v3.0.0", "")

	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	require.NotNil(t, cmd)

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--format", "text"})
	require.NoError(t, cmd.Execute())

	outStr := buf.String()
	assert.NotContains(t, outStr, "\x1b[", "NO_COLOR must ensure zero ANSI escape sequences")
	assert.Contains(t, outStr, "Version v3.1.0 is available. Please refer to our installation documentation: https://kubescape.io/docs/install-cli/")
}

func TestGetUpdateCmd_TextOutput_EmptyNoColorTreatedAsUnset(t *testing.T) {
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

	withVersionCheckHandler(t, &stubVersionCheckHandler{latest: "v3.1.0"})
	withVersionGlobals(t, "v3.0.0", "")

	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	require.NotNil(t, cmd)

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--format", "text"})
	require.NoError(t, cmd.Execute())

	outStr := buf.String()
	assert.Contains(t, outStr, "Version "+gchalk.WithBrightGreen().Bold("v3.1.0")+" is available")
	assert.Contains(t, outStr, "Please refer to our installation documentation: "+gchalk.BrightCyan(installationLink))
}

func TestGetUpdateCmd_TextOutput_RedirectedUnforcedNoANSI(t *testing.T) {
	t.Setenv("FORCE_COLOR", "")
	t.Setenv("NO_COLOR", "")
	os.Unsetenv("FORCE_COLOR")
	os.Unsetenv("NO_COLOR")
	prevLevel := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prevLevel)

	withVersionCheckHandler(t, &stubVersionCheckHandler{latest: "v3.1.0"})
	withVersionGlobals(t, "v3.0.0", "")

	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	require.NotNil(t, cmd)

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--format", "text"})
	require.NoError(t, cmd.Execute())

	outStr := buf.String()
	assert.NotContains(t, outStr, "\x1b[", "redirected text output must have zero ANSI escapes")
	assert.Contains(t, outStr, "Version v3.1.0 is available.")
}

func TestGetUpdateCmd_JSON_HasZeroANSI(t *testing.T) {
	t.Setenv("FORCE_COLOR", "1")
	prevLevel := gchalk.GetLevel()
	gchalk.SetLevel(gchalk.LevelAnsi16m)
	defer gchalk.SetLevel(prevLevel)

	withVersionCheckHandler(t, &stubVersionCheckHandler{latest: "v3.1.0"})
	withVersionGlobals(t, "v3.0.0", "")

	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	require.NotNil(t, cmd)

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--format", "json"})
	require.NoError(t, cmd.Execute())

	out, err := io.ReadAll(&buf)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "\x1b[", "JSON output must have zero ANSI codes")
}
