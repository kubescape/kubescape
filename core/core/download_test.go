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

// ---------------------------------------------------------------------------
// Fakes for the getter interfaces, used together with the policyGetterFunc /
// exceptionsGetterFunc / attackTracksGetterFunc / configInputsGetterFunc
// seams so the download* functions below can be exercised without a network
// or cluster dependency.
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

func (f *fakeExceptionsGetter) GetExceptions(string) ([]armotypes.PostureExceptionPolicy, error) {
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

func (f *fakeControlsInputsGetter) GetControlsInputs(string) (map[string][]string, error) {
	return f.inputs, f.err
}

// blockedDir returns a path that cannot be used as a directory (it is a
// regular file), so a getter.SaveInFile call underneath it fails with a
// non-NotExist error instead of silently mkdir-ing its way to success.
func blockedDir(t *testing.T) string {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	return blocker
}

func TestDownloadConfigInputs(t *testing.T) {
	t.Run("returns error from the getter constructor", func(t *testing.T) {
		orig := configInputsGetterFunc
		configInputsGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool, bool) (getter.IControlsInputsGetter, bool, error) {
			return nil, false, errors.New("boom")
		}
		t.Cleanup(func() { configInputsGetterFunc = orig })

		err := downloadConfigInputs(context.Background(), &metav1.DownloadInfo{Target: TargetControlsInputs, Path: t.TempDir()})
		require.EqualError(t, err, "boom")
	})

	t.Run("returns error from GetControlsInputs", func(t *testing.T) {
		orig := configInputsGetterFunc
		configInputsGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool, bool) (getter.IControlsInputsGetter, bool, error) {
			return &fakeControlsInputsGetter{err: errors.New("fetch failed")}, false, nil
		}
		t.Cleanup(func() { configInputsGetterFunc = orig })

		err := downloadConfigInputs(context.Background(), &metav1.DownloadInfo{Target: TargetControlsInputs, Path: t.TempDir()})
		require.EqualError(t, err, "fetch failed")
	})

	t.Run("returns error when controlInputs is nil", func(t *testing.T) {
		orig := configInputsGetterFunc
		configInputsGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool, bool) (getter.IControlsInputsGetter, bool, error) {
			return &fakeControlsInputsGetter{inputs: nil}, false, nil
		}
		t.Cleanup(func() { configInputsGetterFunc = orig })

		err := downloadConfigInputs(context.Background(), &metav1.DownloadInfo{Target: TargetControlsInputs, Path: t.TempDir()})
		require.EqualError(t, err, "failed to download controlInputs - received an empty objects")
	})

	t.Run("returns error when SaveInFile fails", func(t *testing.T) {
		orig := configInputsGetterFunc
		configInputsGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool, bool) (getter.IControlsInputsGetter, bool, error) {
			return &fakeControlsInputsGetter{inputs: map[string][]string{"a": {"b"}}}, false, nil
		}
		t.Cleanup(func() { configInputsGetterFunc = orig })

		err := downloadConfigInputs(context.Background(), &metav1.DownloadInfo{Target: TargetControlsInputs, Path: blockedDir(t)})
		require.Error(t, err)
	})

	t.Run("succeeds and defaults the filename", func(t *testing.T) {
		orig := configInputsGetterFunc
		want := map[string][]string{"alpha": {"1", "2"}}
		configInputsGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool, bool) (getter.IControlsInputsGetter, bool, error) {
			return &fakeControlsInputsGetter{inputs: want}, false, nil
		}
		t.Cleanup(func() { configInputsGetterFunc = orig })

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
		orig := exceptionsGetterFunc
		exceptionsGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool) (getter.IExceptionsGetter, error) {
			return nil, errors.New("boom")
		}
		t.Cleanup(func() { exceptionsGetterFunc = orig })

		err := downloadExceptions(context.Background(), &metav1.DownloadInfo{Target: TargetExceptions, Path: t.TempDir()})
		require.EqualError(t, err, "boom")
	})

	t.Run("returns error from GetExceptions", func(t *testing.T) {
		orig := exceptionsGetterFunc
		exceptionsGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool) (getter.IExceptionsGetter, error) {
			return &fakeExceptionsGetter{err: errors.New("fetch failed")}, nil
		}
		t.Cleanup(func() { exceptionsGetterFunc = orig })

		err := downloadExceptions(context.Background(), &metav1.DownloadInfo{Target: TargetExceptions, Path: t.TempDir()})
		require.EqualError(t, err, "fetch failed")
	})

	t.Run("returns error when SaveInFile fails", func(t *testing.T) {
		orig := exceptionsGetterFunc
		exceptionsGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool) (getter.IExceptionsGetter, error) {
			return &fakeExceptionsGetter{}, nil
		}
		t.Cleanup(func() { exceptionsGetterFunc = orig })

		err := downloadExceptions(context.Background(), &metav1.DownloadInfo{Target: TargetExceptions, Path: blockedDir(t)})
		require.Error(t, err)
	})

	t.Run("succeeds and preserves an explicit filename", func(t *testing.T) {
		orig := exceptionsGetterFunc
		want := []armotypes.PostureExceptionPolicy{{PolicyType: "exception"}}
		exceptionsGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool) (getter.IExceptionsGetter, error) {
			return &fakeExceptionsGetter{exceptions: want}, nil
		}
		t.Cleanup(func() { exceptionsGetterFunc = orig })

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
		orig := attackTracksGetterFunc
		attackTracksGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool) (getter.IAttackTracksGetter, error) {
			return nil, errors.New("boom")
		}
		t.Cleanup(func() { attackTracksGetterFunc = orig })

		err := downloadAttackTracks(context.Background(), &metav1.DownloadInfo{Target: TargetAttackTracks, Path: t.TempDir()})
		require.EqualError(t, err, "boom")
	})

	t.Run("returns error from GetAttackTracks", func(t *testing.T) {
		orig := attackTracksGetterFunc
		attackTracksGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool) (getter.IAttackTracksGetter, error) {
			return &fakeAttackTracksGetter{err: errors.New("fetch failed")}, nil
		}
		t.Cleanup(func() { attackTracksGetterFunc = orig })

		err := downloadAttackTracks(context.Background(), &metav1.DownloadInfo{Target: TargetAttackTracks, Path: t.TempDir()})
		require.EqualError(t, err, "fetch failed")
	})

	t.Run("returns error when SaveInFile fails", func(t *testing.T) {
		orig := attackTracksGetterFunc
		attackTracksGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool) (getter.IAttackTracksGetter, error) {
			return &fakeAttackTracksGetter{}, nil
		}
		t.Cleanup(func() { attackTracksGetterFunc = orig })

		err := downloadAttackTracks(context.Background(), &metav1.DownloadInfo{Target: TargetAttackTracks, Path: blockedDir(t)})
		require.Error(t, err)
	})

	t.Run("succeeds and defaults the filename", func(t *testing.T) {
		orig := attackTracksGetterFunc
		want := []v1alpha1.AttackTrack{{ApiVersion: "v1"}}
		attackTracksGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool) (getter.IAttackTracksGetter, error) {
			return &fakeAttackTracksGetter{tracks: want}, nil
		}
		t.Cleanup(func() { attackTracksGetterFunc = orig })

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
		orig := policyGetterFunc
		policyGetterFunc = func(context.Context, []string, string, bool, *getter.DownloadReleasedPolicy, bool) (getter.IPolicyGetter, error) {
			return nil, errors.New("boom")
		}
		t.Cleanup(func() { policyGetterFunc = orig })

		err := downloadFramework(context.Background(), &metav1.DownloadInfo{Target: TargetFramework, Path: t.TempDir()})
		require.EqualError(t, err, "boom")
	})

	t.Run("no identifier: returns error from GetFrameworks", func(t *testing.T) {
		orig := policyGetterFunc
		policyGetterFunc = func(context.Context, []string, string, bool, *getter.DownloadReleasedPolicy, bool) (getter.IPolicyGetter, error) {
			return &fakePolicyGetter{frameworksErr: errors.New("fetch failed")}, nil
		}
		t.Cleanup(func() { policyGetterFunc = orig })

		err := downloadFramework(context.Background(), &metav1.DownloadInfo{Target: TargetFramework, Path: t.TempDir()})
		require.EqualError(t, err, "fetch failed")
	})

	t.Run("no identifier: skips a framework with an empty name and saves the rest", func(t *testing.T) {
		orig := policyGetterFunc
		policyGetterFunc = func(context.Context, []string, string, bool, *getter.DownloadReleasedPolicy, bool) (getter.IPolicyGetter, error) {
			return &fakePolicyGetter{frameworks: []reporthandling.Framework{
				{PortalBase: armotypes.PortalBase{Name: ""}},
				{PortalBase: armotypes.PortalBase{Name: "nsa"}},
			}}, nil
		}
		t.Cleanup(func() { policyGetterFunc = orig })

		dir := t.TempDir()
		err := downloadFramework(context.Background(), &metav1.DownloadInfo{Target: TargetFramework, Path: dir})
		require.NoError(t, err)

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, "nsa.json", entries[0].Name())
	})

	t.Run("no identifier: returns error when SaveInFile fails", func(t *testing.T) {
		orig := policyGetterFunc
		policyGetterFunc = func(context.Context, []string, string, bool, *getter.DownloadReleasedPolicy, bool) (getter.IPolicyGetter, error) {
			return &fakePolicyGetter{frameworks: []reporthandling.Framework{
				{PortalBase: armotypes.PortalBase{Name: "nsa"}},
			}}, nil
		}
		t.Cleanup(func() { policyGetterFunc = orig })

		err := downloadFramework(context.Background(), &metav1.DownloadInfo{Target: TargetFramework, Path: blockedDir(t)})
		require.Error(t, err)
	})

	t.Run("with identifier: returns error from PolicyCacheFilename", func(t *testing.T) {
		orig := policyGetterFunc
		policyGetterFunc = func(context.Context, []string, string, bool, *getter.DownloadReleasedPolicy, bool) (getter.IPolicyGetter, error) {
			return &fakePolicyGetter{}, nil
		}
		t.Cleanup(func() { policyGetterFunc = orig })

		err := downloadFramework(context.Background(), &metav1.DownloadInfo{Target: TargetFramework, Path: t.TempDir(), Identifier: "a/b"})
		require.Error(t, err)
	})

	t.Run("with identifier: returns error from GetFramework", func(t *testing.T) {
		orig := policyGetterFunc
		policyGetterFunc = func(context.Context, []string, string, bool, *getter.DownloadReleasedPolicy, bool) (getter.IPolicyGetter, error) {
			return &fakePolicyGetter{frameworkErr: errors.New("fetch failed")}, nil
		}
		t.Cleanup(func() { policyGetterFunc = orig })

		err := downloadFramework(context.Background(), &metav1.DownloadInfo{Target: TargetFramework, Path: t.TempDir(), Identifier: "nsa"})
		require.EqualError(t, err, "fetch failed")
	})

	t.Run("with identifier: returns error when the framework is nil", func(t *testing.T) {
		orig := policyGetterFunc
		policyGetterFunc = func(context.Context, []string, string, bool, *getter.DownloadReleasedPolicy, bool) (getter.IPolicyGetter, error) {
			return &fakePolicyGetter{framework: nil}, nil
		}
		t.Cleanup(func() { policyGetterFunc = orig })

		err := downloadFramework(context.Background(), &metav1.DownloadInfo{Target: TargetFramework, Path: t.TempDir(), Identifier: "nsa"})
		require.EqualError(t, err, "failed to download framework - received an empty objects")
	})

	t.Run("with identifier: succeeds and derives the filename", func(t *testing.T) {
		orig := policyGetterFunc
		want := &reporthandling.Framework{PortalBase: armotypes.PortalBase{Name: "nsa"}}
		policyGetterFunc = func(context.Context, []string, string, bool, *getter.DownloadReleasedPolicy, bool) (getter.IPolicyGetter, error) {
			return &fakePolicyGetter{framework: want}, nil
		}
		t.Cleanup(func() { policyGetterFunc = orig })

		dir := t.TempDir()
		info := &metav1.DownloadInfo{Target: TargetFramework, Path: dir, Identifier: "nsa"}
		require.NoError(t, downloadFramework(context.Background(), info))
		assert.Equal(t, "nsa.json", info.FileName)

		var got reporthandling.Framework
		readJSONFile(t, filepath.Join(dir, info.FileName), &got)
		assert.Equal(t, want.Name, got.Name)
	})

	t.Run("with identifier: returns error when SaveInFile fails", func(t *testing.T) {
		orig := policyGetterFunc
		policyGetterFunc = func(context.Context, []string, string, bool, *getter.DownloadReleasedPolicy, bool) (getter.IPolicyGetter, error) {
			return &fakePolicyGetter{framework: &reporthandling.Framework{PortalBase: armotypes.PortalBase{Name: "nsa"}}}, nil
		}
		t.Cleanup(func() { policyGetterFunc = orig })

		err := downloadFramework(context.Background(), &metav1.DownloadInfo{Target: TargetFramework, Path: blockedDir(t), Identifier: "nsa"})
		require.Error(t, err)
	})
}

func TestDownloadControl(t *testing.T) {
	t.Run("returns error from the getter constructor", func(t *testing.T) {
		orig := policyGetterFunc
		policyGetterFunc = func(context.Context, []string, string, bool, *getter.DownloadReleasedPolicy, bool) (getter.IPolicyGetter, error) {
			return nil, errors.New("boom")
		}
		t.Cleanup(func() { policyGetterFunc = orig })

		err := downloadControl(context.Background(), &metav1.DownloadInfo{Target: TargetControl, Path: t.TempDir(), Identifier: "C-0001"})
		require.EqualError(t, err, "boom")
	})

	t.Run("returns error when the identifier is missing", func(t *testing.T) {
		orig := policyGetterFunc
		policyGetterFunc = func(context.Context, []string, string, bool, *getter.DownloadReleasedPolicy, bool) (getter.IPolicyGetter, error) {
			return &fakePolicyGetter{}, nil
		}
		t.Cleanup(func() { policyGetterFunc = orig })

		err := downloadControl(context.Background(), &metav1.DownloadInfo{Target: TargetControl, Path: t.TempDir()})
		require.EqualError(t, err, "missing control ID")
	})

	t.Run("returns error from PolicyCacheFilename", func(t *testing.T) {
		orig := policyGetterFunc
		policyGetterFunc = func(context.Context, []string, string, bool, *getter.DownloadReleasedPolicy, bool) (getter.IPolicyGetter, error) {
			return &fakePolicyGetter{}, nil
		}
		t.Cleanup(func() { policyGetterFunc = orig })

		err := downloadControl(context.Background(), &metav1.DownloadInfo{Target: TargetControl, Path: t.TempDir(), Identifier: "a/b"})
		require.Error(t, err)
	})

	t.Run("returns a wrapped error from GetControl", func(t *testing.T) {
		orig := policyGetterFunc
		policyGetterFunc = func(context.Context, []string, string, bool, *getter.DownloadReleasedPolicy, bool) (getter.IPolicyGetter, error) {
			return &fakePolicyGetter{controlErr: errors.New("fetch failed")}, nil
		}
		t.Cleanup(func() { policyGetterFunc = orig })

		err := downloadControl(context.Background(), &metav1.DownloadInfo{Target: TargetControl, Path: t.TempDir(), Identifier: "C-0001"})
		require.ErrorContains(t, err, "C-0001")
		require.ErrorContains(t, err, "fetch failed")
	})

	t.Run("returns error when the control is nil", func(t *testing.T) {
		orig := policyGetterFunc
		policyGetterFunc = func(context.Context, []string, string, bool, *getter.DownloadReleasedPolicy, bool) (getter.IPolicyGetter, error) {
			return &fakePolicyGetter{control: nil}, nil
		}
		t.Cleanup(func() { policyGetterFunc = orig })

		err := downloadControl(context.Background(), &metav1.DownloadInfo{Target: TargetControl, Path: t.TempDir(), Identifier: "C-0001"})
		require.ErrorContains(t, err, "C-0001")
		require.ErrorContains(t, err, "received an empty objects")
	})

	t.Run("returns error when SaveInFile fails", func(t *testing.T) {
		orig := policyGetterFunc
		policyGetterFunc = func(context.Context, []string, string, bool, *getter.DownloadReleasedPolicy, bool) (getter.IPolicyGetter, error) {
			return &fakePolicyGetter{control: &reporthandling.Control{}}, nil
		}
		t.Cleanup(func() { policyGetterFunc = orig })

		err := downloadControl(context.Background(), &metav1.DownloadInfo{Target: TargetControl, Path: blockedDir(t), Identifier: "C-0001"})
		require.Error(t, err)
	})

	t.Run("succeeds and derives the filename", func(t *testing.T) {
		orig := policyGetterFunc
		want := &reporthandling.Control{ControlID: "C-0001"}
		policyGetterFunc = func(context.Context, []string, string, bool, *getter.DownloadReleasedPolicy, bool) (getter.IPolicyGetter, error) {
			return &fakePolicyGetter{control: want}, nil
		}
		t.Cleanup(func() { policyGetterFunc = orig })

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
		origConfig, origExceptions, origAttack, origPolicy := configInputsGetterFunc, exceptionsGetterFunc, attackTracksGetterFunc, policyGetterFunc
		configInputsGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool, bool) (getter.IControlsInputsGetter, bool, error) {
			return &fakeControlsInputsGetter{inputs: map[string][]string{"a": {"1"}}}, false, nil
		}
		exceptionsGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool) (getter.IExceptionsGetter, error) {
			return &fakeExceptionsGetter{exceptions: []armotypes.PostureExceptionPolicy{{}}}, nil
		}
		attackTracksGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool) (getter.IAttackTracksGetter, error) {
			return &fakeAttackTracksGetter{tracks: []v1alpha1.AttackTrack{{}}}, nil
		}
		policyGetterFunc = func(context.Context, []string, string, bool, *getter.DownloadReleasedPolicy, bool) (getter.IPolicyGetter, error) {
			return &fakePolicyGetter{frameworks: []reporthandling.Framework{{PortalBase: armotypes.PortalBase{Name: "nsa"}}}}, nil
		}
		t.Cleanup(func() {
			configInputsGetterFunc, exceptionsGetterFunc, attackTracksGetterFunc, policyGetterFunc = origConfig, origExceptions, origAttack, origPolicy
		})

		dir := t.TempDir()
		err := downloadArtifacts(context.Background(), &metav1.DownloadInfo{Target: TargetArtifacts, Path: dir})
		require.NoError(t, err)

		for _, want := range []string{"controls-inputs.json", "exceptions.json", "nsa.json", "attack-tracks.json"} {
			_, statErr := os.Stat(filepath.Join(dir, want))
			assert.NoError(t, statErr, "expected %s to have been written", want)
		}
	})

	t.Run("logs a warning and continues when one artifact fails", func(t *testing.T) {
		origConfig, origExceptions, origAttack, origPolicy := configInputsGetterFunc, exceptionsGetterFunc, attackTracksGetterFunc, policyGetterFunc
		configInputsGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool, bool) (getter.IControlsInputsGetter, bool, error) {
			return &fakeControlsInputsGetter{inputs: map[string][]string{"a": {"1"}}}, false, nil
		}
		exceptionsGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool) (getter.IExceptionsGetter, error) {
			return nil, errors.New("boom")
		}
		attackTracksGetterFunc = func(context.Context, string, string, *getter.DownloadReleasedPolicy, bool) (getter.IAttackTracksGetter, error) {
			return &fakeAttackTracksGetter{tracks: []v1alpha1.AttackTrack{{}}}, nil
		}
		policyGetterFunc = func(context.Context, []string, string, bool, *getter.DownloadReleasedPolicy, bool) (getter.IPolicyGetter, error) {
			return &fakePolicyGetter{frameworks: []reporthandling.Framework{{PortalBase: armotypes.PortalBase{Name: "nsa"}}}}, nil
		}
		t.Cleanup(func() {
			configInputsGetterFunc, exceptionsGetterFunc, attackTracksGetterFunc, policyGetterFunc = origConfig, origExceptions, origAttack, origPolicy
		})

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
