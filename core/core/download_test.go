package core

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/stretchr/testify/assert"
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

// ========================= Unstable tests =========================

// func TestDownloadConfigInputs(t *testing.T) {
// 	ctx := context.Background()
// 	tests := []struct {
// 		downloadInfo *metav1.DownloadInfo
// 	}{
// 		{
// 			downloadInfo: &metav1.DownloadInfo{
// 				AccountID:  "Test-Id",
// 				AccessKey:  "Random-value",
// 				Identifier: "Unique-Id",
// 				FileName:   "",
// 				Target:     "Temp",
// 				Path:       filepath.Join("path", "to"),
// 			},
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.downloadInfo.Path, func(t *testing.T) {
// 			err := downloadConfigInputs(ctx, tt.downloadInfo)
// 			assert.NotNil(t, err)
// 		})
// 	}
// }

// func TestDownloadExceptions(t *testing.T) {
// 	ctx := context.Background()
// 	tests := []struct {
// 		downloadInfo *metav1.DownloadInfo
// 	}{
// 		{
// 			downloadInfo: &metav1.DownloadInfo{
// 				AccountID:  "Test-Id",
// 				AccessKey:  "Random-value",
// 				Identifier: "Unique-Id",
// 				FileName:   "",
// 				Target:     "Temp",
// 				Path:       filepath.Join("path", "to"),
// 			},
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.downloadInfo.Path, func(t *testing.T) {
// 			err := downloadExceptions(ctx, tt.downloadInfo)
// 			assert.NotNil(t, err)
// 		})
// 	}
// }

// func TestDownloadAttackTracks(t *testing.T) {
// 	ctx := context.Background()
// 	tests := []struct {
// 		downloadInfo *metav1.DownloadInfo
// 		isErrNil     bool
// 	}{
// 		{
// 			downloadInfo: &metav1.DownloadInfo{
// 				AccountID:  "00000000-0000-0000-0000-000000000000",
// 				AccessKey:  "00000000-0000-0000-0000-000000000000",
// 				Identifier: "id",
// 				FileName:   "",
// 				Target:     "temp",
// 				Path:       filepath.Join("path", "to"),
// 			},
// 			isErrNil: false,
// 		},
// 		{
// 			downloadInfo: &metav1.DownloadInfo{
// 				AccountID:  "",
// 				AccessKey:  "",
// 				Identifier: "",
// 				FileName:   "",
// 				Target:     "temp",
// 				Path:       filepath.Join("path", "to"),
// 			},
// 			isErrNil: false,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.downloadInfo.Path, func(t *testing.T) {
// 			err := downloadAttackTracks(ctx, tt.downloadInfo)
// 			if tt.isErrNil {
// 				assert.Nil(t, err)
// 			} else {
// 				assert.NotNil(t, err)
// 				t.Error(err)
// 			}
// 		})
// 	}
// }

// func TestDownloadFramework(t *testing.T) {
// 	ctx := context.Background()
// 	tests := []struct {
// 		downloadInfo *metav1.DownloadInfo
// 		isErrNil     bool
// 	}{
// 		{
// 			downloadInfo: &metav1.DownloadInfo{
// 				AccountID:  "Test-Id",
// 				AccessKey:  "Random-value",
// 				Identifier: "Id",
// 				FileName:   "",
// 				Target:     "Temp",
// 				Path:       filepath.Join("path", "to"),
// 			},
// 			isErrNil: false,
// 		},
// 		{
// 			downloadInfo: &metav1.DownloadInfo{
// 				AccountID:  "",
// 				AccessKey:  "",
// 				Identifier: "",
// 				FileName:   "",
// 				Target:     "Temp",
// 				Path:       filepath.Join("path", "to"),
// 			},
// 			isErrNil: false,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.downloadInfo.Path, func(t *testing.T) {
// 			err := downloadFramework(ctx, tt.downloadInfo)
// 			if tt.isErrNil {
// 				assert.Nil(t, err)
// 			} else {

// 				assert.NotNil(t, err)
// 			}
// 		})
// 	}
// }

// func TestDownloadControl(t *testing.T) {
// 	ctx := context.Background()
// 	tests := []struct {
// 		downloadInfo *metav1.DownloadInfo
// 		isErrNil     bool
// 	}{
// 		{
// 			downloadInfo: &metav1.DownloadInfo{
// 				AccountID:  "Test-Id",
// 				AccessKey:  "Random-value",
// 				Identifier: "Id",
// 				FileName:   "",
// 				Target:     "Temp",
// 				Path:       filepath.Join("path", "to"),
// 			},
// 			isErrNil: false,
// 		},
// 		{
// 			downloadInfo: &metav1.DownloadInfo{
// 				AccountID:  "",
// 				AccessKey:  "",
// 				Identifier: "",
// 				FileName:   "",
// 				Target:     "Temp",
// 				Path:       filepath.Join("path", "to"),
// 			},
// 			isErrNil: false,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.downloadInfo.Path, func(t *testing.T) {
// 			err := downloadControl(ctx, tt.downloadInfo)
// 			if tt.isErrNil {
// 				assert.Nil(t, err)
// 			} else {

// 				assert.NotNil(t, err)
// 			}
// 		})
// 	}
// }
