package update

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/meta"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubKubescape is a minimal IKubescape used by update command tests. RunE only
// needs Context(); the remaining methods exist solely to satisfy the interface.
type stubKubescape struct {
	ctx context.Context
}

func (s *stubKubescape) Context() context.Context { return s.ctx }
func (s *stubKubescape) SetContext(ctx context.Context) {
	s.ctx = ctx
}
func (s *stubKubescape) Scan(*cautils.ScanInfo, []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	return nil, nil
}
func (s *stubKubescape) ScanContext(context.Context, *cautils.ScanInfo, []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	return nil, nil
}
func (s *stubKubescape) List(*metav1.ListPolicies) (*metav1.ListResult, error) {
	return nil, nil
}
func (s *stubKubescape) Download(*metav1.DownloadInfo) (*metav1.DownloadResult, error) {
	return nil, nil
}
func (s *stubKubescape) SetCachedConfig(*metav1.SetConfig) error   { return nil }
func (s *stubKubescape) ViewCachedConfig(*metav1.ViewConfig) error { return nil }
func (s *stubKubescape) ValidateCachedConfig(*metav1.ValidateConfig) error {
	return nil
}
func (s *stubKubescape) DeleteCachedConfig(*metav1.DeleteConfig) error {
	return nil
}
func (s *stubKubescape) Fix(*metav1.FixInfo) error { return nil }
func (s *stubKubescape) Diff(*metav1.DiffInfo) (int, error) {
	return 0, nil
}
func (s *stubKubescape) Patch(*metav1.PatchInfo, *cautils.ScanInfo) (bool, error) {
	return false, nil
}
func (s *stubKubescape) ScanImage(*metav1.ImageScanInfo, *cautils.ScanInfo) (bool, error) {
	return false, nil
}
func (s *stubKubescape) ScanImageContext(context.Context, *metav1.ImageScanInfo, *cautils.ScanInfo) (bool, error) {
	return false, nil
}

var _ meta.IKubescape = (*stubKubescape)(nil)

type stubVersionCheckHandler struct {
	latest string
	err    error
}

func (s *stubVersionCheckHandler) CheckLatestVersion(_ context.Context, _ *versioncheck.VersionCheckRequest) error {
	versioncheck.LatestReleaseVersion = s.latest
	return s.err
}

func withVersionCheckHandler(t *testing.T, handler versioncheck.IVersionCheckHandler) {
	t.Helper()
	original := newVersionCheckHandler
	newVersionCheckHandler = func() versioncheck.IVersionCheckHandler { return handler }
	t.Cleanup(func() {
		newVersionCheckHandler = original
	})
}

func withVersionGlobals(t *testing.T, buildNumber, latestRelease string) {
	t.Helper()
	origBuild := versioncheck.BuildNumber
	origLatest := versioncheck.LatestReleaseVersion
	versioncheck.BuildNumber = buildNumber
	versioncheck.LatestReleaseVersion = latestRelease
	t.Cleanup(func() {
		versioncheck.BuildNumber = origBuild
		versioncheck.LatestReleaseVersion = origLatest
	})
}

func TestGetUpdateCmd(t *testing.T) {
	withVersionCheckHandler(t, versioncheck.NewVersionCheckHandlerMock())
	withVersionGlobals(t, "v3.0.0", "")

	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	require.NotNil(t, cmd)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
}

func TestGetUpdateCmd_CheckLatestVersionError(t *testing.T) {
	wantErr := errors.New("version lookup failed")
	withVersionCheckHandler(t, &stubVersionCheckHandler{err: wantErr})
	withVersionGlobals(t, "v3.0.0", "")

	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	require.NotNil(t, cmd)

	err := cmd.RunE(cmd, []string{})
	assert.ErrorIs(t, err, wantErr)
}

func TestGetUpdateCmd_ReportsAvailableUpdate(t *testing.T) {
	withVersionCheckHandler(t, &stubVersionCheckHandler{latest: "v3.1.0"})
	withVersionGlobals(t, "v3.0.0", "")

	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	require.NotNil(t, cmd)

	var buf bytes.Buffer
	cmd.SetOut(&buf)

	assert.NoError(t, cmd.RunE(cmd, []string{}))
	assert.Equal(t, "v3.1.0", versioncheck.LatestReleaseVersion)
	assert.Contains(t, buf.String(), "Version v3.1.0 is available.")
}

func TestGetUpdateCmd_UnsupportedFormat(t *testing.T) {
	withVersionCheckHandler(t, versioncheck.NewVersionCheckHandlerMock())
	withVersionGlobals(t, "v3.0.0", "")

	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	require.NotNil(t, cmd)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--format", "yaml"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported format \"yaml\"")
}

func TestGetUpdateCmd_JSON_ReportsAvailableUpdate(t *testing.T) {
	withVersionCheckHandler(t, &stubVersionCheckHandler{latest: "v3.1.0"})
	withVersionGlobals(t, "v3.0.0", "")

	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	require.NotNil(t, cmd)

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--format", "json"})

	assert.NoError(t, cmd.Execute())
	assert.Equal(t, "v3.1.0", versioncheck.LatestReleaseVersion)
	assert.Contains(t, buf.String(), `"latestVersion":"v3.1.0"`)
	assert.Contains(t, buf.String(), `"installationLink":"https://kubescape.io/docs/install-cli/"`)
}

func TestGetUpdateCmd_JSON_NothingToUpdate(t *testing.T) {
	withVersionCheckHandler(t, &stubVersionCheckHandler{latest: "v3.0.0"})
	withVersionGlobals(t, "v3.0.0", "")

	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	require.NotNil(t, cmd)

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--format", "json"})

	assert.NoError(t, cmd.Execute())
	assert.Equal(t, "v3.0.0", versioncheck.LatestReleaseVersion)
	assert.Contains(t, buf.String(), `"message":"Nothing to update: you are running the latest version"`)
}

func TestUpdateCommandDoesNotHonorSkipUpdateCheckEnv(t *testing.T) {
	// KS_SKIP_UPDATE_CHECK must not turn the update command into a no-op.
	// NewIVersionCheckHandler would return VersionCheckHandlerMock here; the
	// update seam must keep constructing the real VersionCheckHandler.
	t.Setenv("KS_SKIP_UPDATE_CHECK", "true")
	t.Setenv("KUBESCAPE_SKIP_UPDATE_CHECK", "true")

	handler := newVersionCheckHandler()
	_, isReal := handler.(*versioncheck.VersionCheckHandler)
	_, isMock := handler.(*versioncheck.VersionCheckHandlerMock)

	assert.True(t, isReal, "update command must use the real version-check handler at runtime")
	assert.False(t, isMock, "update command must not use the skip-check mock when KS_SKIP_UPDATE_CHECK is set")
}

func TestGetUpdateCmd_DevelopmentVersion(t *testing.T) {
	devVersions := []string{"", "dev", "v3.0.0-rc.1"}

	for _, buildNum := range devVersions {
		testName := buildNum
		if testName == "" {
			testName = "empty_build_number"
		}

		t.Run("text_"+testName, func(t *testing.T) {
			withVersionCheckHandler(t, versioncheck.NewVersionCheckHandlerMock())
			withVersionGlobals(t, buildNum, "v3.1.0")

			cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
			require.NotNil(t, cmd)

			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetArgs([]string{"--format", "text"})
			require.NoError(t, cmd.Execute())

			assert.Contains(t, buf.String(), "Nothing to update: you are running the development version")
		})

		t.Run("json_"+testName, func(t *testing.T) {
			withVersionCheckHandler(t, versioncheck.NewVersionCheckHandlerMock())
			withVersionGlobals(t, buildNum, "v3.1.0")

			cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
			require.NotNil(t, cmd)

			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetArgs([]string{"--format", "json"})
			require.NoError(t, cmd.Execute())

			var info UpdateInfo
			require.NoError(t, json.Unmarshal(buf.Bytes(), &info))
			assert.Equal(t, "Nothing to update: you are running the development version", info.Message)
			assert.Empty(t, info.LatestVersion)
		})
	}
}

// A release version without the leading "v" is still a release, not a
// development build.
func TestGetUpdateCmd_JSON_ReleaseWithoutVPrefix(t *testing.T) {
	withVersionCheckHandler(t, &stubVersionCheckHandler{latest: "v3.1.0"})
	withVersionGlobals(t, "3.0.0", "")

	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	require.NotNil(t, cmd)

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--format", "json"})
	require.NoError(t, cmd.Execute())

	var info UpdateInfo
	require.NoError(t, json.Unmarshal(buf.Bytes(), &info))
	assert.Equal(t, "v3.1.0", info.LatestVersion)
	assert.Empty(t, info.Message)
}

// The version service names a latest release only when it is newer than the
// running version, so a successful check without one means nothing to update.
func TestGetUpdateCmd_JSON_NoNewerRelease(t *testing.T) {
	withVersionCheckHandler(t, &stubVersionCheckHandler{latest: ""})
	withVersionGlobals(t, "v3.0.0", "")

	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	require.NotNil(t, cmd)

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--format", "json"})
	require.NoError(t, cmd.Execute())

	var info UpdateInfo
	require.NoError(t, json.Unmarshal(buf.Bytes(), &info))
	assert.Equal(t, "Nothing to update: you are running the latest version", info.Message)
	assert.Empty(t, info.LatestVersion)
}

func TestGetUpdateCmd_Text_AlreadyUpToDate(t *testing.T) {
	withVersionCheckHandler(t, &stubVersionCheckHandler{latest: "v3.0.0"})
	withVersionGlobals(t, "v3.0.0", "")

	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	require.NotNil(t, cmd)

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--format", "text"})
	require.NoError(t, cmd.Execute())

	assert.Contains(t, buf.String(), "Nothing to update: you are running the latest version")
}

func TestGetUpdateCmd_Text_NoNewerRelease(t *testing.T) {
	withVersionCheckHandler(t, &stubVersionCheckHandler{latest: ""})
	withVersionGlobals(t, "v3.0.0", "")

	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	require.NotNil(t, cmd)

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--format", "text"})
	require.NoError(t, cmd.Execute())

	assert.Contains(t, buf.String(), "Nothing to update: you are running the latest version")
}

type failingUpdateWriter struct {
	err error
}

func (w failingUpdateWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestGetUpdateCmd_JSON_WriterError(t *testing.T) {
	withVersionCheckHandler(t, &stubVersionCheckHandler{latest: "v3.0.0"})
	withVersionGlobals(t, "v3.0.0", "")

	writeErr := errors.New("cannot write output")
	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--format", "json"})
	cmd.SetOut(failingUpdateWriter{err: writeErr})

	err := cmd.Execute()
	require.ErrorIs(t, err, writeErr)
}

func TestGetUpdateCmd_Text_WriterError(t *testing.T) {
	writeErr := errors.New("cannot write output")

	scenarios := []struct {
		name     string
		buildNum string
		latest   string
	}{
		{"dev_build", "dev", ""},
		{"already_up_to_date", "v3.0.0", "v3.0.0"},
		{"update_available", "v3.0.0", "v3.1.0"},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			withVersionCheckHandler(t, &stubVersionCheckHandler{latest: s.latest})
			withVersionGlobals(t, s.buildNum, "")

			cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			cmd.SetArgs([]string{"--format", "text"})
			cmd.SetOut(failingUpdateWriter{err: writeErr})

			err := cmd.Execute()
			require.ErrorIs(t, err, writeErr)
		})
	}
}

func TestGetUpdateCmd_CaseInsensitiveFormat(t *testing.T) {
	withVersionCheckHandler(t, versioncheck.NewVersionCheckHandlerMock())
	withVersionGlobals(t, "v3.0.0", "")

	formats := []string{"JSON", "Json", "TEXT", "Text", " json ", " text "}
	for _, f := range formats {
		t.Run("format_"+strings.TrimSpace(f), func(t *testing.T) {
			cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetArgs([]string{"--format", f})
			assert.NoError(t, cmd.Execute())
		})
	}
}

func TestGetUpdateCmd_RejectsUnexpectedArgs(t *testing.T) {
	cmd := GetUpdateCmd(&stubKubescape{ctx: context.Background()})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"unexpected"})

	err := cmd.Execute()
	require.Error(t, err)
}
