package download

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v3/core/core"
	"github.com/kubescape/kubescape/v3/core/meta"
	v1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingDownloadKS records the DownloadInfo handed to Download so tests
// can assert what the CLI actually passes down.
type recordingDownloadKS struct {
	meta.IKubescape
	captured *v1.DownloadInfo
}

func (r *recordingDownloadKS) Download(info *v1.DownloadInfo) (*v1.DownloadResult, error) {
	r.captured = info
	return &v1.DownloadResult{}, nil
}

func TestGetViewCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	// Call the GetConfigCmd function
	configCmd := GetDownloadCmd(mockKubescape)

	// Verify the command name and short description
	assert.Equal(t, "download <policy> <policy name>", configCmd.Use)
	assert.Equal(t, fmt.Sprintf("Download %s", strings.Join(core.DownloadSupportCommands(), ",")), configCmd.Short)
	assert.Equal(t, "", configCmd.Long)
	assert.Equal(t, downloadExample, configCmd.Example)
}

func TestGetViewCmd_Args(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	// Call the GetConfigCmd function
	downloadCmd := GetDownloadCmd(mockKubescape)

	// Verify the command name and short description
	assert.Equal(t, "download <policy> <policy name>", downloadCmd.Use)
	assert.Equal(t, fmt.Sprintf("Download %s", strings.Join(core.DownloadSupportCommands(), ",")), downloadCmd.Short)
	assert.Equal(t, "", downloadCmd.Long)
	assert.Equal(t, downloadExample, downloadCmd.Example)

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

	err = downloadCmd.Args(&cobra.Command{}, []string{"control", "C-0001", "C-0002"})
	assert.Nil(t, err)

	err = downloadCmd.RunE(&cobra.Command{}, []string{"control", "C-0001", "C-0002"})
	assert.Nil(t, err)
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
	want := "bad argument: accound ID must be a valid UUID"
	for _, tt := range tests {
		t.Run(tt.downloadInfo.AccountID, func(t *testing.T) {
			assert.Equal(t, want, flagValidationDownload(&tt.downloadInfo).Error())
		})
	}
}
