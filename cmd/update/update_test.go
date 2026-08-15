package update

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/meta"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
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
func (s *stubKubescape) List(*metav1.ListPolicies) (*metav1.ListResult, error) {
	return nil, nil
}
func (s *stubKubescape) Download(*metav1.DownloadInfo) (*metav1.DownloadResult, error) {
	return nil, nil
}
func (s *stubKubescape) SetCachedConfig(*metav1.SetConfig) error   { return nil }
func (s *stubKubescape) ViewCachedConfig(*metav1.ViewConfig) error { return nil }
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

	r, w, err := os.Pipe()
	require.NoError(t, err)
	origStdout := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = origStdout })

	assert.NoError(t, cmd.RunE(cmd, []string{}))
	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)

	assert.Equal(t, "v3.1.0", versioncheck.LatestReleaseVersion)
	assert.Contains(t, string(out), "Version v3.1.0 is available.")
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
