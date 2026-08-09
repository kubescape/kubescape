package scan

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v3/cmd/shared"
	"github.com/kubescape/kubescape/v3/core/cautils"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

type imageScanCaptureKubescape struct {
	mocks.MockIKubescape
	imgScanInfo *metav1.ImageScanInfo
	scanInfo    *cautils.ScanInfo
}

func (m *imageScanCaptureKubescape) ScanImage(imgScanInfo *metav1.ImageScanInfo, scanInfo *cautils.ScanInfo) (bool, error) {
	m.imgScanInfo = imgScanInfo
	m.scanInfo = scanInfo
	return false, nil
}

func TestGetImageCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}
	scanInfo := cautils.ScanInfo{
		AccountID: "new",
	}

	cmd := getImageCmd(mockKubescape, &scanInfo)
	parentCmd := &cobra.Command{Use: "scan"}
	parentCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", `Output file format. Supported formats: "pretty-printer", "json", "junit", "prometheus", "pdf", "html", "sarif"`)
	parentCmd.AddCommand(cmd)

	// Verify the command name and short description
	assert.Equal(t, "image <image>:<tag> [flags]", cmd.Use)
	assert.Equal(t, "Scan an image for vulnerabilities", cmd.Short)
	assert.Equal(t, imageExample, cmd.Example)

	err := cmd.Args(&cobra.Command{}, []string{})
	expectedErrorMessage := "the command takes exactly one image name as an argument"
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = cmd.Args(&cobra.Command{}, []string{"nginx"})
	assert.Nil(t, err)

	err = cmd.RunE(&cobra.Command{}, []string{})
	assert.Equal(t, expectedErrorMessage, err.Error())

	formatFlag := cmd.InheritedFlags().Lookup("format")
	assert.NotNil(t, formatFlag)
	assert.False(t, formatFlag.Changed)

	err = cmd.RunE(cmd, []string{"nginx"})
	assert.NoError(t, err)
}

func TestGetImageCmd_RunE_InvalidSeverity(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}
	scanInfo := cautils.ScanInfo{FailThresholdSeverity: "unknown"}

	cmd := getImageCmd(mockKubescape, &scanInfo)

	err := cmd.RunE(cmd, []string{"nginx"})
	assert.Equal(t, shared.ErrUnknownSeverity, err)
}

func TestGetImageCmd_RunE_FormatFlagEmpty(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}
	scanInfo := cautils.ScanInfo{}

	cmd := getImageCmd(mockKubescape, &scanInfo)
	parent := &cobra.Command{}
	parent.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "", "")
	parent.AddCommand(cmd)
	assert.NoError(t, parent.PersistentFlags().Set("format", ""))

	err := cmd.RunE(cmd, []string{"nginx"})
	assert.Equal(t, fmt.Sprintf("format cannot be empty, supported formats: %s", strings.Join(shared.ImageScanFormats, ", ")), err.Error())
}

func TestGetImageCmd_RunE_FormatFlagInvalid(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}
	scanInfo := cautils.ScanInfo{}

	cmd := getImageCmd(mockKubescape, &scanInfo)
	parent := &cobra.Command{}
	parent.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "", "")
	parent.AddCommand(cmd)
	assert.NoError(t, parent.PersistentFlags().Set("format", "xml"))

	err := cmd.RunE(cmd, []string{"nginx"})
	assert.EqualError(t, err, `invalid format "xml", supported formats: pretty-printer, json, junit, prometheus, pdf, html, sarif, gitlab-sast, yaml`)
}

func TestGetImageCmd_RunE_Success(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}
	scanInfo := cautils.ScanInfo{}

	cmd := getImageCmd(mockKubescape, &scanInfo)
	parentCmd := &cobra.Command{Use: "scan"}
	parentCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", `Output file format. Supported formats: "pretty-printer", "json", "junit", "prometheus", "pdf", "html", "sarif"`)
	parentCmd.AddCommand(cmd)

	err := cmd.RunE(cmd, []string{"nginx"})
	assert.NoError(t, err)
}

func TestGetImageCmd_RunE_ForwardsRegistryTokenCredentials(t *testing.T) {
	mockKubescape := &imageScanCaptureKubescape{}
	scanInfo := cautils.ScanInfo{}

	cmd := getImageCmd(mockKubescape, &scanInfo)
	parentCmd := &cobra.Command{Use: "scan"}
	parentCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", "")
	parentCmd.PersistentFlags().StringVar(&scanInfo.RegistryToken, "registry-token", "", "")
	parentCmd.PersistentFlags().StringVar(&scanInfo.RegistryAuthority, "registry-authority", "", "")
	parentCmd.AddCommand(cmd)

	assert.NoError(t, parentCmd.PersistentFlags().Set("registry-token", "token"))
	assert.NoError(t, parentCmd.PersistentFlags().Set("registry-authority", "registry.example.com"))

	err := cmd.RunE(cmd, []string{"registry.example.com/app:tag"})
	assert.NoError(t, err)
	assert.Equal(t, "registry.example.com", mockKubescape.imgScanInfo.Authority)
	assert.Equal(t, "token", mockKubescape.imgScanInfo.Token)
	assert.Equal(t, "registry.example.com/app:tag", mockKubescape.imgScanInfo.Image)
}

func TestGetImageCmd_RunE_ForwardsInheritedRegistryBasicCredentials(t *testing.T) {
	mockKubescape := &imageScanCaptureKubescape{}
	scanInfo := cautils.ScanInfo{}

	cmd := getImageCmd(mockKubescape, &scanInfo)
	parentCmd := &cobra.Command{Use: "scan"}
	parentCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", "")
	parentCmd.PersistentFlags().StringVar(&scanInfo.RegistryUsername, "registry-username", "", "")
	parentCmd.PersistentFlags().StringVar(&scanInfo.RegistryPassword, "registry-password", "", "")
	parentCmd.PersistentFlags().StringVar(&scanInfo.RegistryAuthority, "registry-authority", "", "")
	parentCmd.AddCommand(cmd)

	assert.NoError(t, parentCmd.PersistentFlags().Set("registry-username", "user"))
	assert.NoError(t, parentCmd.PersistentFlags().Set("registry-password", "pass"))
	assert.NoError(t, parentCmd.PersistentFlags().Set("registry-authority", "registry.example.com"))

	err := cmd.RunE(cmd, []string{"registry.example.com/app:tag"})
	assert.NoError(t, err)
	assert.Equal(t, "registry.example.com", mockKubescape.imgScanInfo.Authority)
	assert.Equal(t, "user", mockKubescape.imgScanInfo.Username)
	assert.Equal(t, "pass", mockKubescape.imgScanInfo.Password)
}

func TestGetImageCmd_RunE_AcceptsMixedRegistryCredentialFlagFamilies(t *testing.T) {
	testCases := []struct {
		name     string
		setFlags func(t *testing.T, parentCmd, imageCmd *cobra.Command)
	}{
		{
			name: "registry username with legacy password",
			setFlags: func(t *testing.T, parentCmd, imageCmd *cobra.Command) {
				assert.NoError(t, parentCmd.PersistentFlags().Set("registry-username", "user"))
				assert.NoError(t, imageCmd.PersistentFlags().Set("password", "pass"))
			},
		},
		{
			name: "legacy username with registry password",
			setFlags: func(t *testing.T, parentCmd, imageCmd *cobra.Command) {
				assert.NoError(t, imageCmd.PersistentFlags().Set("username", "user"))
				assert.NoError(t, parentCmd.PersistentFlags().Set("registry-password", "pass"))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockKubescape := &imageScanCaptureKubescape{}
			scanInfo := cautils.ScanInfo{}

			cmd := getImageCmd(mockKubescape, &scanInfo)
			parentCmd := &cobra.Command{Use: "scan"}
			parentCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", "")
			parentCmd.PersistentFlags().StringVar(&scanInfo.RegistryUsername, "registry-username", "", "")
			parentCmd.PersistentFlags().StringVar(&scanInfo.RegistryPassword, "registry-password", "", "")
			parentCmd.AddCommand(cmd)

			tc.setFlags(t, parentCmd, cmd)

			err := cmd.RunE(cmd, []string{"registry.example.com/app:tag"})
			assert.NoError(t, err)
			assert.Equal(t, "user", mockKubescape.imgScanInfo.Username)
			assert.Equal(t, "pass", mockKubescape.imgScanInfo.Password)
		})
	}
}

func TestGetImageCmd_RunE_RejectsConflictingRegistryCredentials(t *testing.T) {
	mockKubescape := &imageScanCaptureKubescape{}
	scanInfo := cautils.ScanInfo{}

	cmd := getImageCmd(mockKubescape, &scanInfo)
	parentCmd := &cobra.Command{Use: "scan"}
	parentCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", "")
	parentCmd.PersistentFlags().StringVar(&scanInfo.RegistryToken, "registry-token", "", "")
	parentCmd.AddCommand(cmd)

	assert.NoError(t, cmd.PersistentFlags().Set("username", "user"))
	assert.NoError(t, cmd.PersistentFlags().Set("password", "pass"))
	assert.NoError(t, parentCmd.PersistentFlags().Set("registry-token", "token"))

	err := cmd.RunE(cmd, []string{"registry.example.com/app:tag"})
	assert.Equal(t, shared.ErrRegistryAuthConflict, err)
	assert.Nil(t, mockKubescape.imgScanInfo)
}

func TestGetImageCmd_RegistryTokenAndAuthorityAreInherited(t *testing.T) {
	scanCmd := GetScanCommand(&mocks.MockIKubescape{})
	imageCmd, _, err := scanCmd.Find([]string{"image"})
	assert.NoError(t, err)

	assert.Nil(t, imageCmd.PersistentFlags().Lookup("registry-token"))
	assert.Nil(t, imageCmd.PersistentFlags().Lookup("registry-authority"))
	assert.NotNil(t, imageCmd.InheritedFlags().Lookup("registry-token"))
	assert.NotNil(t, imageCmd.InheritedFlags().Lookup("registry-authority"))
}

func TestGetScanCommand_ImageRegistryTokenAndAuthorityReachImageScan(t *testing.T) {
	mockKubescape := &imageScanCaptureKubescape{}
	cmd := GetScanCommand(mockKubescape)
	cmd.SetArgs([]string{
		"image",
		"--registry-token", "token",
		"--registry-authority", "registry.example.com",
		"registry.example.com/app:tag",
	})

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Equal(t, "registry.example.com", mockKubescape.imgScanInfo.Authority)
	assert.Equal(t, "token", mockKubescape.imgScanInfo.Token)
	assert.Equal(t, "registry.example.com/app:tag", mockKubescape.imgScanInfo.Image)
}
