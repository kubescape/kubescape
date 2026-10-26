package download

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/kubescape/v4/core/meta"
	v1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingDownloadKS records the DownloadInfo handed to Download so tests
// can assert what the CLI actually passes down.
type recordingDownloadKS struct {
	meta.IKubescape
	captured *v1.DownloadInfo
	err      error
}

func (r *recordingDownloadKS) Download(info *v1.DownloadInfo) (*v1.DownloadResult, error) {
	r.captured = info
	if r.err != nil {
		return nil, r.err
	}
	return &v1.DownloadResult{}, nil
}

// TestGetDownloadCmd verifies the download command metadata and default properties.
func TestGetDownloadCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	// Call the GetDownloadCmd function
	downloadCmd := GetDownloadCmd(mockKubescape)

	assert.Equal(t, "download <policy> <policy name>", downloadCmd.Use)
}

// TestGetDownloadCmd_Args tests command argument validation with valid, invalid, plural, and alias target names.
func TestGetDownloadCmd_Args(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	// Call the GetDownloadCmd function
	downloadCmd := GetDownloadCmd(mockKubescape)

	assert.Equal(t, "download <policy> <policy name>", downloadCmd.Use)

	err := downloadCmd.RunE(&cobra.Command{}, []string{"artifacts"})
	assert.Nil(t, err)

	err = downloadCmd.Args(&cobra.Command{}, []string{})
	expectedErrorMessage := "policy type required, supported: artifacts,attack-tracks,control,controls-inputs,exceptions,framework"
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = downloadCmd.Args(&cobra.Command{}, []string{"invalid"})
	expectedErrorMessage = "invalid parameter 'invalid'. Supported parameters: artifacts,attack-tracks,control,controls-inputs,exceptions,framework"
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = downloadCmd.Args(&cobra.Command{}, []string{"attack-tracks"})
	assert.Nil(t, err)

	err = downloadCmd.Args(&cobra.Command{}, []string{"control", "random.json"})
	assert.Nil(t, err)

	err = downloadCmd.Args(&cobra.Command{}, []string{"control", "C-0001"})
	assert.Nil(t, err)

	err = downloadCmd.Args(&cobra.Command{}, []string{"controls", "C-0001"})
	assert.Nil(t, err)

	err = downloadCmd.Args(&cobra.Command{}, []string{"frameworks", "nsa"})
	assert.Nil(t, err)

	err = downloadCmd.Args(&cobra.Command{}, []string{"controls-config"})
	assert.Nil(t, err)

	err = downloadCmd.Args(&cobra.Command{}, []string{"exception"})
	assert.Nil(t, err)

	err = downloadCmd.Args(&cobra.Command{}, []string{"artifact"})
	assert.Nil(t, err)

	err = downloadCmd.Args(&cobra.Command{}, []string{"attack-track"})
	assert.Nil(t, err)

	err = downloadCmd.Args(&cobra.Command{}, []string{"control", "C-0001", "C-0002"})
	assert.Nil(t, err)

	err = downloadCmd.RunE(&cobra.Command{}, []string{"control", "C-0001", "C-0002"})
	assert.Nil(t, err)
}

// TestNormalizeDownloadTarget tests normalization of target aliases and plurals to canonical targets.
func TestNormalizeDownloadTarget(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"control", core.TargetControl},
		{"controls", core.TargetControl},
		{"framework", core.TargetFramework},
		{"frameworks", core.TargetFramework},
		{"controls-inputs", core.TargetControlsInputs},
		{"controls-input", core.TargetControlsInputs},
		{"control-inputs", core.TargetControlsInputs},
		{"control-input", core.TargetControlsInputs},
		{"controls-config", core.TargetControlsInputs},
		{"control-config", core.TargetControlsInputs},
		{"exceptions", core.TargetExceptions},
		{"exception", core.TargetExceptions},
		{"artifacts", core.TargetArtifacts},
		{"artifact", core.TargetArtifacts},
		{"attack-tracks", core.TargetAttackTracks},
		{"attack-track", core.TargetAttackTracks},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeDownloadTarget(tt.input))
		})
	}
}

// TestDownloadCmd_TargetNormalization verifies that plural and alias targets
// are normalized to their canonical values before calling Kubescape.Download.
func TestDownloadCmd_TargetNormalization(t *testing.T) {
	tests := []struct {
		args       []string
		wantTarget string
		wantID     string
	}{
		{args: []string{"controls", "C-0001"}, wantTarget: core.TargetControl, wantID: "C-0001"},
		{args: []string{"frameworks", "nsa"}, wantTarget: core.TargetFramework, wantID: "nsa"},
		{args: []string{"controls-config"}, wantTarget: core.TargetControlsInputs, wantID: ""},
		{args: []string{"exception"}, wantTarget: core.TargetExceptions, wantID: ""},
		{args: []string{"artifact"}, wantTarget: core.TargetArtifacts, wantID: ""},
		{args: []string{"attack-track"}, wantTarget: core.TargetAttackTracks, wantID: ""},
	}

	for _, tt := range tests {
		t.Run(strings.Join(tt.args, "_"), func(t *testing.T) {
			ks := &recordingDownloadKS{}
			cmd := GetDownloadCmd(ks)
			require.NoError(t, cmd.RunE(cmd, tt.args))
			require.NotNil(t, ks.captured)
			assert.Equal(t, tt.wantTarget, ks.captured.Target)
			assert.Equal(t, tt.wantID, ks.captured.Identifier)
		})
	}
}

// TestDownloadCmd_JSONOutputPathPreSplit pins the CLI half of the
// --output <file>.json contract: the flag value is pre-split into
// (Path="", FileName="nsa.json") before it reaches Kubescape.Download.
// The core half (Path="" + FileName resolves to the current directory) is
// covered by TestDownload_BareJSONOutputPathIsRespected in core/core.
func TestDownloadCmd_JSONOutputPathPreSplit(t *testing.T) {
	ks := &recordingDownloadKS{}
	cmd := GetDownloadCmd(ks)
	require.NoError(t, cmd.Flags().Set("output", "nsa.json"))

	require.NoError(t, cmd.RunE(cmd, []string{"framework", "nsa"}))

	require.NotNil(t, ks.captured)
	assert.Equal(t, "", ks.captured.Path)
	assert.Equal(t, "nsa.json", ks.captured.FileName)
}

// TestDownloadCmd_UpperCaseJSONOutputPathPreSplit verifies the .json
// extension of --output is matched case-insensitively.
func TestDownloadCmd_UpperCaseJSONOutputPathPreSplit(t *testing.T) {
	ks := &recordingDownloadKS{}
	cmd := GetDownloadCmd(ks)
	require.NoError(t, cmd.Flags().Set("output", "NSA.JSON"))

	require.NoError(t, cmd.RunE(cmd, []string{"framework", "nsa"}))

	require.NotNil(t, ks.captured)
	assert.Equal(t, "", ks.captured.Path)
	assert.Equal(t, "NSA.JSON", ks.captured.FileName)
}

// TestDownloadCmd_NonJSONExtensionOutputPathNotSplit verifies that an
// --output path whose final extension is not .json is passed through as a
// directory, even when the name contains an upper-case .JSON.
func TestDownloadCmd_NonJSONExtensionOutputPathNotSplit(t *testing.T) {
	for _, output := range []string{
		filepath.Join("out", "report.JSON.bak"),
		filepath.Join("out", "report.JSONL"),
	} {
		t.Run(output, func(t *testing.T) {
			ks := &recordingDownloadKS{}
			cmd := GetDownloadCmd(ks)
			require.NoError(t, cmd.Flags().Set("output", output))

			require.NoError(t, cmd.RunE(cmd, []string{"framework", "nsa"}))

			require.NotNil(t, ks.captured)
			assert.Equal(t, output, ks.captured.Path)
			assert.Equal(t, "", ks.captured.FileName)
		})
	}
}

func TestFlagValidationDownload_NoError(t *testing.T) {
	downloadInfo := v1.DownloadInfo{
		AccessKey: "",
		AccountID: "",
	}
	assert.Equal(t, nil, flagValidationDownload(&downloadInfo))
}

func TestFlagValidationDownload_Error(t *testing.T) {
	tests := []struct {
		downloadInfo v1.DownloadInfo
	}{
		{
			downloadInfo: v1.DownloadInfo{
				AccountID: "12345678",
			},
		},
		{
			downloadInfo: v1.DownloadInfo{
				AccountID: "New",
			},
		},
	}
	want := "bad argument: account ID must be a valid UUID"
	for _, tt := range tests {
		t.Run(tt.downloadInfo.AccountID, func(t *testing.T) {
			assert.Equal(t, want, flagValidationDownload(&tt.downloadInfo).Error())
		})
	}
}

// TestDownloadCmd_EmptyIdentifierValidation verifies that empty policy names
// are rejected for framework and control downloads, but permitted for targets
// that do not require an identifier.
func TestDownloadCmd_EmptyIdentifierValidation(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantErr     bool
		expectedErr string
		wantTarget  string
		wantID      string
	}{
		{
			name:        "framework with empty name",
			args:        []string{"framework", ""},
			wantErr:     true,
			expectedErr: "name cannot be empty for framework download",
		},
		{
			name:        "frameworks alias with empty name",
			args:        []string{"frameworks", ""},
			wantErr:     true,
			expectedErr: "name cannot be empty for framework download",
		},
		{
			name:        "control with empty name",
			args:        []string{"control", ""},
			wantErr:     true,
			expectedErr: "name cannot be empty for control download",
		},
		{
			name:        "controls alias with empty name",
			args:        []string{"controls", ""},
			wantErr:     true,
			expectedErr: "name cannot be empty for control download",
		},
		{
			name:       "artifacts with empty identifier",
			args:       []string{"artifacts", ""},
			wantErr:    false,
			wantTarget: core.TargetArtifacts,
			wantID:     "",
		},
		{
			name:       "exceptions with empty identifier",
			args:       []string{"exceptions", ""},
			wantErr:    false,
			wantTarget: core.TargetExceptions,
			wantID:     "",
		},
		{
			name:       "controls-inputs with empty identifier",
			args:       []string{"controls-inputs", ""},
			wantErr:    false,
			wantTarget: core.TargetControlsInputs,
			wantID:     "",
		},
		{
			name:       "attack-tracks with empty identifier",
			args:       []string{"attack-tracks", ""},
			wantErr:    false,
			wantTarget: core.TargetAttackTracks,
			wantID:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := &recordingDownloadKS{}
			cmd := GetDownloadCmd(ks)

			err := cmd.RunE(cmd, tt.args)
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.expectedErr, err.Error())
				assert.Nil(t, ks.captured, "Download should not be called when validation fails")
			} else {
				require.NoError(t, err)
				require.NotNil(t, ks.captured)
				assert.Equal(t, tt.wantTarget, ks.captured.Target)
				assert.Equal(t, tt.wantID, ks.captured.Identifier)
			}
		})
	}
}

// TestDownloadCmd_DownloadErrorPropagation verifies that errors returned by
// the Kubescape interface are propagated back by the download command Execute.
func TestDownloadCmd_DownloadErrorPropagation(t *testing.T) {
	expectedErr := errors.New("simulated network error during download")
	ks := &recordingDownloadKS{err: expectedErr}
	cmd := GetDownloadCmd(ks)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"framework", "nsa"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.ErrorIs(t, err, expectedErr)
}

// TestDownloadCmd_FlagValidationErrorPropagation verifies that flag validation
// errors (such as an invalid account UUID) halt execution and return the error.
func TestDownloadCmd_FlagValidationErrorPropagation(t *testing.T) {
	ks := &recordingDownloadKS{}
	cmd := GetDownloadCmd(ks)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"framework", "nsa", "--account", "invalid-uuid"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "account ID must be a valid UUID")
	assert.Nil(t, ks.captured, "Download should not be called when flag validation fails")
}
