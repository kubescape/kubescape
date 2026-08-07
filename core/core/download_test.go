package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Returns a list of all available download commands when 'DownloadSupportCommands' is called.
func TestDownloadSupportCommands_ReturnsListOfAllAvailableDownloadCommands(t *testing.T) {
	result := DownloadSupportCommands()

	assert.NotNil(t, result)
	assert.Equal(t, len(downloadFunc), len(result))
}

// Returns a non-empty list of download commands when 'DownloadSupportCommands' is called and 'downloadFunc' is not empty.
func TestDownloadSupportCommands_ReturnsNonEmptyListOfDownloadCommandsWhenDownloadFuncNotEmpty(t *testing.T) {
	// Arrange
	downloadFunc = map[string]func(context.Context, *metav1.DownloadInfo) error{
		"controls-inputs": downloadConfigInputs,
		"exceptions":      downloadExceptions,
		"framework":       downloadFramework,
		"attack-tracks":   downloadAttackTracks,
	}

	// Act
	result := DownloadSupportCommands()

	// Assert
	assert.NotNil(t, result)
	assert.NotEmpty(t, result)
}

// Returns a list of strings when 'DownloadSupportCommands' is called.
func TestDownloadSupportCommands_ReturnsListOfStrings(t *testing.T) {
	result := DownloadSupportCommands()

	// Assert
	assert.NotNil(t, result)
	for _, command := range result {
		assert.IsType(t, "", command)
	}
}

// Returns an empty list when 'DownloadSupportCommands' is called and 'downloadFunc' is empty.
func TestDownloadSupportCommands_ReturnsEmptyListWhenDownloadFuncEmpty(t *testing.T) {
	// Arrange
	downloadFunc = map[string]func(context.Context, *metav1.DownloadInfo) error{}

	// Act
	result := DownloadSupportCommands()

	// Assert
	assert.NotNil(t, result)
	assert.Empty(t, result)
}

// Returns an empty list when 'DownloadSupportCommands' is called and 'downloadFunc' is nil.
func TestDownloadSupportCommands_ReturnsEmptyListWhenDownloadFuncNil(t *testing.T) {
	// Arrange
	downloadFunc = nil

	// Act
	result := DownloadSupportCommands()

	// Assert
	assert.NotNil(t, result)
	assert.Empty(t, result)
}

func TestDownloadArtifact(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		downloadInfo         *metav1.DownloadInfo
		downloadArtifactFunc map[string]func(context.Context, *metav1.DownloadInfo) error
		err                  error
	}{
		{
			downloadInfo: &metav1.DownloadInfo{
				Target: "controls-inputs",
				Path:   filepath.Join("path", "to", "download"),
			},
			downloadArtifactFunc: map[string]func(context.Context, *metav1.DownloadInfo) error{
				"controls-inputs": func(ctx context.Context, downloadInfo *metav1.DownloadInfo) error {
					return nil
				},
			},
			err: nil,
		},
		{
			downloadInfo: &metav1.DownloadInfo{
				Target: "unknown",
				Path:   filepath.Join("path", "to", "download"),
			},
			downloadArtifactFunc: map[string]func(context.Context, *metav1.DownloadInfo) error{},
			err:                  fmt.Errorf("unknown command to download"),
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			err := downloadArtifact(ctx, tt.downloadInfo, tt.downloadArtifactFunc)
			assert.Equal(t, tt.err, err)
		})
	}
}

func TestSetPathAndFilename(t *testing.T) {
	tests := []struct {
		downloadInfo     *metav1.DownloadInfo
		expectedPath     string
		expectedFilename string
	}{
		{
			downloadInfo: &metav1.DownloadInfo{
				Path: filepath.Join("test-path", "to", "file.txt"),
			},
			expectedPath:     filepath.Join("test-path", "to", "file.txt"),
			expectedFilename: "",
		},
		{
			downloadInfo: &metav1.DownloadInfo{
				Path: filepath.Join("path", "to", "path.json"),
			},
			expectedPath:     filepath.Join("path", "to"),
			expectedFilename: "path.json",
		},
		{
			downloadInfo: &metav1.DownloadInfo{
				Path: filepath.Join("path", "to"),
			},
			expectedPath:     filepath.Join("path", "to"),
			expectedFilename: "",
		},
		{
			downloadInfo: &metav1.DownloadInfo{
				Path: "",
			},
			expectedPath:     getter.GetDefaultPath(""),
			expectedFilename: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.expectedFilename, func(t *testing.T) {
			setPathAndFilename(tt.downloadInfo)
			assert.Equal(t, tt.expectedPath, tt.downloadInfo.Path)
			assert.Equal(t, tt.expectedFilename, tt.downloadInfo.FileName)
		})
	}
}

// TestDownload_UnknownTargetReturnsError verifies Kubescape.Download surfaces unknown targets.
func TestDownload_UnknownTargetReturnsError(t *testing.T) {
	ks := NewKubescape(context.Background())
	err := ks.Download(&metav1.DownloadInfo{
		Target: "unknown",
		Path:   t.TempDir(),
	})
	require.Error(t, err)
	assert.EqualError(t, err, "unknown command to download")
}

// TestDownload_CreatesOutputDirectoryWithRestrictivePermissions guards
// against a regression back to os.ModePerm (0777, world-writable), and
// against Download() drifting from the 0700 policy customerloader.go's
// updateConfigFile() already enforces on ~/.kubescape - which is where
// Download() writes by default (setPathAndFilename falls back to
// getter.GetDefaultPath("") when no --output path is given), and which
// holds config.json's AccessKey. Download() applies that same 0700 to every
// path it creates, not just the default one, so this holds even though the
// test passes an explicit custom Path. Download() creates downloadInfo.Path
// before dispatching to the target-specific downloader, so an unknown
// target (which fails after directory creation) is enough to exercise the
// MkdirAll call in isolation.
//
// The 0-bits-outside-0700 assertion below is a meaningful guard only when
// the process umask doesn't already mask those bits out (see the identical
// caveat on printer.assertDirNotMorePermissiveThan0750); CI's default umask
// (022) makes it effective.
func TestDownload_CreatesOutputDirectoryWithRestrictivePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "download-dir")

	ks := NewKubescape(context.Background())
	err := ks.Download(&metav1.DownloadInfo{
		Target: "unknown",
		Path:   path,
	})
	require.Error(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	mode := info.Mode().Perm()
	assert.Zerof(t, mode&0o077, "directory %s has mode %o, more permissive than 0700", path, mode)
}

// ---------------------------------------------------------------------------
// Fakes for the getter interfaces, used together with the policyGetterFunc /
// exceptionsGetterFunc / attackTracksGetterFunc / configInputsGetterFunc /
// tenantConfigFunc seams so the download* functions below can be exercised
// without a network or cluster dependency.
// ---------------------------------------------------------------------------

type fakePolicyGetter struct {
	frameworks    []reporthandling.Framework
	frameworksErr error
	framework     *reporthandling.Framework
	frameworkErr  error
	control       *reporthandling.Control
	controlErr    error
}

func (f *fakePolicyGetter) GetFramework(string) (*reporthandling.Framework, error) {
	return f.framework, f.frameworkErr
}
func (f *fakePolicyGetter) GetFrameworks() ([]reporthandling.Framework, error) {
	return f.frameworks, f.frameworksErr
}
func (f *fakePolicyGetter) GetControl(string) (*reporthandling.Control, error) {
	return f.control, f.controlErr
}
func (f *fakePolicyGetter) ListFrameworks() ([]string, error) { return nil, nil }
func (f *fakePolicyGetter) ListControls() ([]string, error)   { return nil, nil }

type fakeExceptionsGetter struct {
	exceptions []armotypes.PostureExceptionPolicy
	err        error
}

func (f *fakeExceptionsGetter) GetExceptions(ctx context.Context, clusterName string) ([]armotypes.PostureExceptionPolicy, error) {
	return f.exceptions, f.err
}

type fakeAttackTracksGetter struct {
	tracks []v1alpha1.AttackTrack
	err    error
}

func (f *fakeAttackTracksGetter) GetAttackTracks() ([]v1alpha1.AttackTrack, error) {
	return f.tracks, f.err
}

type fakeControlsInputsGetter struct {
	inputs map[string][]string
	err    error
}

func (f *fakeControlsInputsGetter) GetControlsInputs(ctx context.Context, clusterName string) (map[string][]string, error) {
	return f.inputs, f.err
}

// fakeTenantConfig is a minimal cautils.ITenantConfig that never touches disk,
// the network, or a Kubernetes cluster.
type fakeTenantConfig struct {
	accountID   string
	contextName string
}

var _ cautils.ITenantConfig = &fakeTenantConfig{}

func (f *fakeTenantConfig) UpdateCachedConfig() error                { return nil }
func (f *fakeTenantConfig) DeleteCachedConfig(context.Context) error { return nil }
func (f *fakeTenantConfig) GenerateAccountID() (string, error)       { return f.accountID, nil }
func (f *fakeTenantConfig) DeleteCredentials() error                 { return nil }
func (f *fakeTenantConfig) GetContextName() string                   { return f.contextName }
func (f *fakeTenantConfig) GetAccountID() string                     { return f.accountID }
func (f *fakeTenantConfig) GetAccessKey() string                     { return "" }
func (f *fakeTenantConfig) GetConfigObj() *cautils.ConfigObj         { return &cautils.ConfigObj{} }
func (f *fakeTenantConfig) GetCloudReportURL() string                { return "" }
func (f *fakeTenantConfig) GetCloudAPIURL() string                   { return "" }

// blockedDir returns a path that cannot be used as a directory (it is a
// regular file), so a getter.SaveInFile call underneath it fails with a
// non-NotExist error instead of silently mkdir-ing its way to success. The
// resulting *fs.PathError includes this file's name ("blocker") in its
// message, which the "SaveInFile fails" subtests below assert on.
func blockedDir(t *testing.T) string {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	return blocker
}

// ---------------------------------------------------------------------------
// Seam helpers. None of these are safe to use from a subtest that also calls
// t.Parallel(): they mutate the package-level *Func vars for the duration of
// the (sub)test and restore them on cleanup, so concurrent subtests would
// race on and clobber each other's stubs.
// ---------------------------------------------------------------------------

func withConfigInputsGetter(t *testing.T, g getter.IControlsInputsGetter, err error) {
	t.Helper()
	orig := configInputsGetterFunc
	configInputsGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool, bool) (getter.IControlsInputsGetter, bool, error) {
		return g, false, err
	}
	t.Cleanup(func() { configInputsGetterFunc = orig })
}

func withExceptionsGetter(t *testing.T, g getter.IExceptionsGetter, err error) {
	t.Helper()
	orig := exceptionsGetterFunc
	exceptionsGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool) (getter.IExceptionsGetter, error) {
		return g, err
	}
	t.Cleanup(func() { exceptionsGetterFunc = orig })
}

func withAttackTracksGetter(t *testing.T, g getter.IAttackTracksGetter, err error) {
	t.Helper()
	orig := attackTracksGetterFunc
	attackTracksGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool) (getter.IAttackTracksGetter, error) {
		return g, err
	}
	t.Cleanup(func() { attackTracksGetterFunc = orig })
}

func withPolicyGetter(t *testing.T, g getter.IPolicyGetter, err error) {
	t.Helper()
	orig := policyGetterFunc
	policyGetterFunc = func(context.Context, []string, string, bool, *getter.DownloadReleasedPolicy, bool) (getter.IPolicyGetter, error) {
		return g, err
	}
	t.Cleanup(func() { policyGetterFunc = orig })
}

// withTenantConfig stubs tenantConfigFunc AND kubernetesAPIFunc so the
// download* functions never reach cautils.GetTenantConfig or
// getKubernetesApi. Both must be stubbed together: kubernetesAPIFunc() is
// evaluated eagerly as an argument to tenantConfigFunc(...), so leaving it
// real still probes a configured cluster (via discovery's
// ServerPreferredResources) even with tenantConfigFunc faked - reproduced
// locally by pointing KUBECONFIG at an unroutable address, which hangs
// TestDownloadConfigInputs for minutes without this stub. With no
// kubeconfig configured getKubernetesApi() already returns nil, but that's
// an accident of the test environment, not something these tests should
// depend on.
func withTenantConfig(t *testing.T, tc cautils.ITenantConfig) {
	t.Helper()
	origTenant := tenantConfigFunc
	tenantConfigFunc = func(context.Context, string, string, string, string, *k8sinterface.KubernetesApi) cautils.ITenantConfig {
		return tc
	}
	t.Cleanup(func() { tenantConfigFunc = origTenant })

	origK8s := kubernetesAPIFunc
	kubernetesAPIFunc = func() *k8sinterface.KubernetesApi { return nil }
	t.Cleanup(func() { kubernetesAPIFunc = origK8s })
}

func TestDownloadConfigInputs(t *testing.T) {
	t.Run("returns error from the getter constructor", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withConfigInputsGetter(t, nil, errors.New("boom"))

		err := downloadConfigInputs(context.Background(), &metav1.DownloadInfo{Target: TargetControlsInputs, Path: t.TempDir()})
		require.EqualError(t, err, "boom")
	})

	t.Run("returns error from GetControlsInputs", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withConfigInputsGetter(t, &fakeControlsInputsGetter{err: errors.New("fetch failed")}, nil)

		err := downloadConfigInputs(context.Background(), &metav1.DownloadInfo{Target: TargetControlsInputs, Path: t.TempDir()})
		require.EqualError(t, err, "fetch failed")
	})

	t.Run("returns error when controlInputs is nil", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withConfigInputsGetter(t, &fakeControlsInputsGetter{inputs: nil}, nil)

		err := downloadConfigInputs(context.Background(), &metav1.DownloadInfo{Target: TargetControlsInputs, Path: t.TempDir()})
		require.EqualError(t, err, "failed to download controlInputs - received empty objects")
	})

	t.Run("returns error when SaveInFile fails", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withConfigInputsGetter(t, &fakeControlsInputsGetter{inputs: map[string][]string{"a": {"b"}}}, nil)

		err := downloadConfigInputs(context.Background(), &metav1.DownloadInfo{Target: TargetControlsInputs, Path: blockedDir(t)})
		require.ErrorContains(t, err, "blocker")
	})

	t.Run("succeeds and defaults the filename", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		want := map[string][]string{"alpha": {"1", "2"}}
		withConfigInputsGetter(t, &fakeControlsInputsGetter{inputs: want}, nil)

		dir := t.TempDir()
		info := &metav1.DownloadInfo{Target: TargetControlsInputs, Path: dir}
		require.NoError(t, downloadConfigInputs(context.Background(), info))
		assert.Equal(t, "controls-inputs.json", info.FileName)

		var got map[string][]string
		readJSONFile(t, filepath.Join(dir, info.FileName), &got)
		assert.Equal(t, want, got)
	})
}

func TestDownloadExceptions(t *testing.T) {
	t.Run("returns error from the getter constructor", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withExceptionsGetter(t, nil, errors.New("boom"))

		err := downloadExceptions(context.Background(), &metav1.DownloadInfo{Target: TargetExceptions, Path: t.TempDir()})
		require.EqualError(t, err, "boom")
	})

	t.Run("returns error from GetExceptions", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withExceptionsGetter(t, &fakeExceptionsGetter{err: errors.New("fetch failed")}, nil)

		err := downloadExceptions(context.Background(), &metav1.DownloadInfo{Target: TargetExceptions, Path: t.TempDir()})
		require.EqualError(t, err, "fetch failed")
	})

	t.Run("returns error when SaveInFile fails", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withExceptionsGetter(t, &fakeExceptionsGetter{}, nil)

		err := downloadExceptions(context.Background(), &metav1.DownloadInfo{Target: TargetExceptions, Path: blockedDir(t)})
		require.ErrorContains(t, err, "blocker")
	})

	t.Run("succeeds and preserves an explicit filename", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		want := []armotypes.PostureExceptionPolicy{{PolicyType: "exception"}}
		withExceptionsGetter(t, &fakeExceptionsGetter{exceptions: want}, nil)

		dir := t.TempDir()
		info := &metav1.DownloadInfo{Target: TargetExceptions, Path: dir, FileName: "custom-exceptions.json"}
		require.NoError(t, downloadExceptions(context.Background(), info))
		assert.Equal(t, "custom-exceptions.json", info.FileName)

		var got []armotypes.PostureExceptionPolicy
		readJSONFile(t, filepath.Join(dir, info.FileName), &got)
		assert.Equal(t, want, got)
	})
}

func TestDownloadAttackTracks(t *testing.T) {
	t.Run("returns error from the getter constructor", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withAttackTracksGetter(t, nil, errors.New("boom"))

		err := downloadAttackTracks(context.Background(), &metav1.DownloadInfo{Target: TargetAttackTracks, Path: t.TempDir()})
		require.EqualError(t, err, "boom")
	})

	t.Run("returns error from GetAttackTracks", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withAttackTracksGetter(t, &fakeAttackTracksGetter{err: errors.New("fetch failed")}, nil)

		err := downloadAttackTracks(context.Background(), &metav1.DownloadInfo{Target: TargetAttackTracks, Path: t.TempDir()})
		require.EqualError(t, err, "fetch failed")
	})

	t.Run("returns error when SaveInFile fails", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withAttackTracksGetter(t, &fakeAttackTracksGetter{}, nil)

		err := downloadAttackTracks(context.Background(), &metav1.DownloadInfo{Target: TargetAttackTracks, Path: blockedDir(t)})
		require.ErrorContains(t, err, "blocker")
	})

	t.Run("succeeds and defaults the filename", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		want := []v1alpha1.AttackTrack{{ApiVersion: "v1"}}
		withAttackTracksGetter(t, &fakeAttackTracksGetter{tracks: want}, nil)

		dir := t.TempDir()
		info := &metav1.DownloadInfo{Target: TargetAttackTracks, Path: dir}
		require.NoError(t, downloadAttackTracks(context.Background(), info))
		assert.Equal(t, "attack-tracks.json", info.FileName)

		var got []v1alpha1.AttackTrack
		readJSONFile(t, filepath.Join(dir, info.FileName), &got)
		assert.Equal(t, want, got)
	})
}

func TestDownloadFramework(t *testing.T) {
	t.Run("returns error from the getter constructor", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withPolicyGetter(t, nil, errors.New("boom"))

		err := downloadFramework(context.Background(), &metav1.DownloadInfo{Target: TargetFramework, Path: t.TempDir()})
		require.EqualError(t, err, "boom")
	})

	t.Run("no identifier: returns error from GetFrameworks", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withPolicyGetter(t, &fakePolicyGetter{frameworksErr: errors.New("fetch failed")}, nil)

		err := downloadFramework(context.Background(), &metav1.DownloadInfo{Target: TargetFramework, Path: t.TempDir()})
		require.EqualError(t, err, "fetch failed")
	})

	t.Run("no identifier: skips a framework with an empty name and saves the rest", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withPolicyGetter(t, &fakePolicyGetter{frameworks: []reporthandling.Framework{
			{PortalBase: armotypes.PortalBase{Name: ""}},
			{PortalBase: armotypes.PortalBase{Name: "nsa"}},
		}}, nil)

		dir := t.TempDir()
		err := downloadFramework(context.Background(), &metav1.DownloadInfo{Target: TargetFramework, Path: dir})
		require.NoError(t, err)

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, "nsa.json", entries[0].Name())
	})

	t.Run("no identifier: returns error when SaveInFile fails", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withPolicyGetter(t, &fakePolicyGetter{frameworks: []reporthandling.Framework{
			{PortalBase: armotypes.PortalBase{Name: "nsa"}},
		}}, nil)

		err := downloadFramework(context.Background(), &metav1.DownloadInfo{Target: TargetFramework, Path: blockedDir(t)})
		require.ErrorContains(t, err, "blocker")
	})

	t.Run("with identifier: returns error from PolicyCacheFilename", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withPolicyGetter(t, &fakePolicyGetter{}, nil)

		err := downloadFramework(context.Background(), &metav1.DownloadInfo{Target: TargetFramework, Path: t.TempDir(), Identifier: "a/b"})
		require.ErrorContains(t, err, "path separators")
	})

	t.Run("with identifier: returns error from GetFramework", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withPolicyGetter(t, &fakePolicyGetter{frameworkErr: errors.New("fetch failed")}, nil)

		err := downloadFramework(context.Background(), &metav1.DownloadInfo{Target: TargetFramework, Path: t.TempDir(), Identifier: "nsa"})
		require.EqualError(t, err, "fetch failed")
	})

	t.Run("with identifier: returns error when the framework is nil", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withPolicyGetter(t, &fakePolicyGetter{framework: nil}, nil)

		err := downloadFramework(context.Background(), &metav1.DownloadInfo{Target: TargetFramework, Path: t.TempDir(), Identifier: "nsa"})
		require.EqualError(t, err, "failed to download framework - received empty objects")
	})

	t.Run("with identifier: succeeds and derives the filename", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		want := &reporthandling.Framework{PortalBase: armotypes.PortalBase{Name: "nsa"}}
		withPolicyGetter(t, &fakePolicyGetter{framework: want}, nil)

		dir := t.TempDir()
		info := &metav1.DownloadInfo{Target: TargetFramework, Path: dir, Identifier: "nsa"}
		require.NoError(t, downloadFramework(context.Background(), info))
		assert.Equal(t, "nsa.json", info.FileName)

		var got reporthandling.Framework
		readJSONFile(t, filepath.Join(dir, info.FileName), &got)
		assert.Equal(t, want.Name, got.Name)
	})

	t.Run("with identifier: returns error when SaveInFile fails", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withPolicyGetter(t, &fakePolicyGetter{framework: &reporthandling.Framework{PortalBase: armotypes.PortalBase{Name: "nsa"}}}, nil)

		err := downloadFramework(context.Background(), &metav1.DownloadInfo{Target: TargetFramework, Path: blockedDir(t), Identifier: "nsa"})
		require.ErrorContains(t, err, "blocker")
	})
}

func TestDownloadControl(t *testing.T) {
	t.Run("returns error from the getter constructor", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withPolicyGetter(t, nil, errors.New("boom"))

		err := downloadControl(context.Background(), &metav1.DownloadInfo{Target: TargetControl, Path: t.TempDir(), Identifier: "C-0001"})
		require.EqualError(t, err, "boom")
	})

	t.Run("returns error when the identifier is missing", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withPolicyGetter(t, &fakePolicyGetter{}, nil)

		err := downloadControl(context.Background(), &metav1.DownloadInfo{Target: TargetControl, Path: t.TempDir()})
		require.EqualError(t, err, "missing control ID")
	})

	t.Run("returns error from PolicyCacheFilename", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withPolicyGetter(t, &fakePolicyGetter{}, nil)

		err := downloadControl(context.Background(), &metav1.DownloadInfo{Target: TargetControl, Path: t.TempDir(), Identifier: "a/b"})
		require.ErrorContains(t, err, "path separators")
	})

	t.Run("returns a wrapped error from GetControl", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withPolicyGetter(t, &fakePolicyGetter{controlErr: errors.New("fetch failed")}, nil)

		err := downloadControl(context.Background(), &metav1.DownloadInfo{Target: TargetControl, Path: t.TempDir(), Identifier: "C-0001"})
		require.ErrorContains(t, err, "C-0001")
		require.ErrorContains(t, err, "fetch failed")
	})

	t.Run("returns error when the control is nil", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withPolicyGetter(t, &fakePolicyGetter{control: nil}, nil)

		err := downloadControl(context.Background(), &metav1.DownloadInfo{Target: TargetControl, Path: t.TempDir(), Identifier: "C-0001"})
		require.ErrorContains(t, err, "C-0001")
		require.ErrorContains(t, err, "received empty objects")
	})

	t.Run("returns error when SaveInFile fails", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withPolicyGetter(t, &fakePolicyGetter{control: &reporthandling.Control{}}, nil)

		err := downloadControl(context.Background(), &metav1.DownloadInfo{Target: TargetControl, Path: blockedDir(t), Identifier: "C-0001"})
		require.ErrorContains(t, err, "blocker")
	})

	t.Run("succeeds and derives the filename", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		want := &reporthandling.Control{ControlID: "C-0001"}
		withPolicyGetter(t, &fakePolicyGetter{control: want}, nil)

		dir := t.TempDir()
		info := &metav1.DownloadInfo{Target: TargetControl, Path: dir, Identifier: "C-0001"}
		require.NoError(t, downloadControl(context.Background(), info))
		assert.Equal(t, "c-0001.json", info.FileName)

		var got reporthandling.Control
		readJSONFile(t, filepath.Join(dir, info.FileName), &got)
		assert.Equal(t, want.ControlID, got.ControlID)
	})
}

func TestDownloadArtifacts(t *testing.T) {
	t.Run("saves every artifact and always returns nil", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withConfigInputsGetter(t, &fakeControlsInputsGetter{inputs: map[string][]string{"a": {"1"}}}, nil)
		withExceptionsGetter(t, &fakeExceptionsGetter{exceptions: []armotypes.PostureExceptionPolicy{{}}}, nil)
		withAttackTracksGetter(t, &fakeAttackTracksGetter{tracks: []v1alpha1.AttackTrack{{}}}, nil)
		withPolicyGetter(t, &fakePolicyGetter{frameworks: []reporthandling.Framework{{PortalBase: armotypes.PortalBase{Name: "nsa"}}}}, nil)

		dir := t.TempDir()
		err := downloadArtifacts(context.Background(), &metav1.DownloadInfo{Target: TargetArtifacts, Path: dir})
		require.NoError(t, err)

		for _, want := range []string{"controls-inputs.json", "exceptions.json", "nsa.json", "attack-tracks.json"} {
			_, statErr := os.Stat(filepath.Join(dir, want))
			assert.NoError(t, statErr, "expected %s to have been written", want)
		}
	})

	t.Run("continues after one artifact fails", func(t *testing.T) {
		withTenantConfig(t, &fakeTenantConfig{})
		withConfigInputsGetter(t, &fakeControlsInputsGetter{inputs: map[string][]string{"a": {"1"}}}, nil)
		withExceptionsGetter(t, nil, errors.New("boom"))
		withAttackTracksGetter(t, &fakeAttackTracksGetter{tracks: []v1alpha1.AttackTrack{{}}}, nil)
		withPolicyGetter(t, &fakePolicyGetter{frameworks: []reporthandling.Framework{{PortalBase: armotypes.PortalBase{Name: "nsa"}}}}, nil)

		dir := t.TempDir()
		err := downloadArtifacts(context.Background(), &metav1.DownloadInfo{Target: TargetArtifacts, Path: dir})
		require.NoError(t, err)

		_, statErr := os.Stat(filepath.Join(dir, "exceptions.json"))
		assert.True(t, os.IsNotExist(statErr), "exceptions.json should not have been written")
		_, statErr = os.Stat(filepath.Join(dir, "nsa.json"))
		assert.NoError(t, statErr, "nsa.json should still have been written")
	})
}

// readJSONFile reads and unmarshals a JSON file, failing the test on error.
func readJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, v))
}
