package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/cautils"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type imageScanCaptureKubescape struct {
	mocks.MockIKubescape
	imgScanInfo      *metav1.ImageScanInfo
	scanInfo         *cautils.ScanInfo
	scanCalledWith   context.Context
	setContextCalled bool
}

func (m *imageScanCaptureKubescape) SetContext(_ context.Context) {
	m.setContextCalled = true
}

func (m *imageScanCaptureKubescape) ScanImage(imgScanInfo *metav1.ImageScanInfo, scanInfo *cautils.ScanInfo) (bool, error) {
	m.imgScanInfo = imgScanInfo
	m.scanInfo = scanInfo
	return false, nil
}

func (m *imageScanCaptureKubescape) ScanImageContext(ctx context.Context, imgScanInfo *metav1.ImageScanInfo, scanInfo *cautils.ScanInfo) (bool, error) {
	m.scanCalledWith = ctx
	return m.ScanImage(imgScanInfo, scanInfo)
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

	assert.Equal(t, "image <image>:<tag> [<image>:<tag>...] [flags]", cmd.Use)

	err := cmd.Args(&cobra.Command{}, []string{})
	expectedErrorMessage := "the command takes at least one image name as an argument"
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

func TestGetImageCmdAcceptsNotify(t *testing.T) {
	mockKubescape := &imageScanCaptureKubescape{}
	scanInfo := cautils.ScanInfo{NotifyURLs: []string{"https://example.com/webhook"}}
	cmd := getImageCmd(mockKubescape, &scanInfo)
	err := cmd.RunE(cmd, []string{"nginx"})
	assert.NoError(t, err)
	assert.NotNil(t, mockKubescape.imgScanInfo)
	assert.Equal(t, []string{"https://example.com/webhook"}, scanInfo.NotifyURLs)
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
	assert.EqualError(t, err, `invalid format "xml", supported formats: pretty-printer, json, junit, prometheus, pdf, html, sarif, gitlab-sast, yaml, markdown, cyclonedx-json, spdx-json`)
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

// TestGetImageCmd_RunE_TimeoutDeadlineActiveForScan and
// TestGetImageCmd_RunE_TimeoutDoesNotMutateSharedContext are regression tests
// mirroring securityScan's own #3237 coverage (TestSecurityScan_
// TimeoutDeadlineActiveForScan / TestSecurityScan_TimeoutDoesNotMutateShared
// Context): now that `scan image` uses ScanImageContext instead of the old
// applyTimeout(scanInfo, ks)()+ScanImage() pattern, --scan-timeout must still
// produce a deadline context, and the shared *Kubescape's own context must
// never be mutated via SetContext to get it there.
func TestGetImageCmd_RunE_TimeoutDeadlineActiveForScan(t *testing.T) {
	mockKubescape := &imageScanCaptureKubescape{}
	scanInfo := cautils.ScanInfo{ScanTimeout: time.Minute}

	cmd := getImageCmd(mockKubescape, &scanInfo)
	parentCmd := &cobra.Command{Use: "scan"}
	parentCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", "")
	parentCmd.AddCommand(cmd)

	require.NoError(t, cmd.RunE(cmd, []string{"nginx"}))

	require.NotNil(t, mockKubescape.scanCalledWith)
	_, hasDeadline := mockKubescape.scanCalledWith.Deadline()
	assert.True(t, hasDeadline, "ScanImageContext must receive a context with a deadline when --scan-timeout is set")
}

func TestGetImageCmd_RunE_TimeoutDoesNotMutateSharedContext(t *testing.T) {
	mockKubescape := &imageScanCaptureKubescape{}
	scanInfo := cautils.ScanInfo{ScanTimeout: time.Minute}

	cmd := getImageCmd(mockKubescape, &scanInfo)
	parentCmd := &cobra.Command{Use: "scan"}
	parentCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", "")
	parentCmd.AddCommand(cmd)

	require.NoError(t, cmd.RunE(cmd, []string{"nginx"}))

	assert.False(t, mockKubescape.setContextCalled, "scan image must not call SetContext on the shared Kubescape instance")
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
	assert.Equal(t, []string{"registry.example.com/app:tag"}, mockKubescape.imgScanInfo.Images)
}

func TestGetImageCmd_RunE_ForwardsCanonicalPlatform(t *testing.T) {
	mockKubescape := &imageScanCaptureKubescape{}
	scanInfo := cautils.ScanInfo{}
	cmd := getImageCmd(mockKubescape, &scanInfo)
	parentCmd := &cobra.Command{Use: "scan"}
	parentCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", "")
	parentCmd.AddCommand(cmd)

	require.NotNil(t, cmd.PersistentFlags().Lookup("platform"))
	require.NoError(t, cmd.PersistentFlags().Set("platform", "x86_64"))

	err := cmd.RunE(cmd, []string{"registry.example.com/app:tag"})
	require.NoError(t, err)
	require.NotNil(t, mockKubescape.imgScanInfo)
	assert.Equal(t, "linux/amd64", mockKubescape.imgScanInfo.Platform)
	assert.Equal(t, "linux/amd64", mockKubescape.scanInfo.ImagePlatform)
}

func TestGetImageCmd_RunE_ForwardsPlatformVariant(t *testing.T) {
	mockKubescape := &imageScanCaptureKubescape{}
	scanInfo := cautils.ScanInfo{}
	cmd := getImageCmd(mockKubescape, &scanInfo)
	parentCmd := &cobra.Command{Use: "scan"}
	parentCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", "")
	parentCmd.AddCommand(cmd)
	require.NoError(t, cmd.PersistentFlags().Set("platform", "linux/arm/v7"))

	err := cmd.RunE(cmd, []string{"registry.example.com/app:tag"})
	require.NoError(t, err)
	assert.Equal(t, "linux/arm/v7", mockKubescape.imgScanInfo.Platform)
}

func TestGetImageCmd_RunE_RejectsInvalidPlatformBeforeScanning(t *testing.T) {
	mockKubescape := &imageScanCaptureKubescape{}
	scanInfo := cautils.ScanInfo{}
	cmd := getImageCmd(mockKubescape, &scanInfo)
	parentCmd := &cobra.Command{Use: "scan"}
	parentCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", "")
	parentCmd.AddCommand(cmd)
	require.NoError(t, cmd.PersistentFlags().Set("platform", "linux/toaster"))

	err := cmd.RunE(cmd, []string{"registry.example.com/app:tag"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid image platform")
	assert.Nil(t, mockKubescape.imgScanInfo, "scanner must not run with an invalid platform")
}

func TestGetImageCmd_RunE_RejectsIncompletePlatformBeforeScanning(t *testing.T) {
	mockKubescape := &imageScanCaptureKubescape{}
	scanInfo := cautils.ScanInfo{}
	cmd := getImageCmd(mockKubescape, &scanInfo)
	parentCmd := &cobra.Command{Use: "scan"}
	parentCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", "")
	parentCmd.AddCommand(cmd)
	require.NoError(t, cmd.PersistentFlags().Set("platform", "linux"))

	err := cmd.RunE(cmd, []string{"registry.example.com/app:tag"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "both operating system and architecture are required")
	assert.Nil(t, mockKubescape.imgScanInfo)
}

func TestGetImageCmd_PlatformHelpIsSpecific(t *testing.T) {
	scanInfo := cautils.ScanInfo{}
	cmd := getImageCmd(&mocks.MockIKubescape{}, &scanInfo)

	flag := cmd.PersistentFlags().Lookup("platform")
	require.NotNil(t, flag)
	assert.Empty(t, flag.DefValue)
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
	assert.Equal(t, []string{"registry.example.com/app:tag"}, mockKubescape.imgScanInfo.Images)
}

func TestGetScanCommand_ImageScanSetsInputPatterns(t *testing.T) {
	mockKubescape := &imageScanCaptureKubescape{}
	cmd := GetScanCommand(mockKubescape)
	cmd.SetArgs([]string{
		"image",
		"nginx:1.27",
		"redis:7",
	})

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Equal(t, []string{"nginx:1.27", "redis:7"}, mockKubescape.scanInfo.InputPatterns)
}

func TestGetImageCmd_RunE_ForwardsLocalTarball(t *testing.T) {
	mockKubescape := &imageScanCaptureKubescape{}
	scanInfo := cautils.ScanInfo{}

	cmd := getImageCmd(mockKubescape, &scanInfo)
	parentCmd := &cobra.Command{Use: "scan"}
	parentCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", "")
	parentCmd.AddCommand(cmd)

	// Create a dummy tarball file
	tmpFile, err := os.CreateTemp("", "dummy-*.tar")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	err = cmd.RunE(cmd, []string{tmpFile.Name()})
	assert.NoError(t, err)
	assert.Equal(t, []string{"docker-archive:" + tmpFile.Name()}, mockKubescape.imgScanInfo.Images)
	assert.Equal(t, []string{"docker-archive:" + tmpFile.Name()}, mockKubescape.scanInfo.InputPatterns)
}

func TestGetImageCmd_RunE_ArchivesPreservedInInputPatterns(t *testing.T) {
	mockKubescape := &imageScanCaptureKubescape{}
	scanInfo := cautils.ScanInfo{}

	cmd := getImageCmd(mockKubescape, &scanInfo)
	parentCmd := &cobra.Command{Use: "scan"}
	parentCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", "")
	parentCmd.AddCommand(cmd)

	tmpDir := t.TempDir()
	dockerTar := filepath.Join(tmpDir, "docker-img.tar")
	require.NoError(t, os.WriteFile(dockerTar, []byte("dummy-docker-tar"), 0o600))
	ociTar := filepath.Join(tmpDir, "oci-img.tar")
	require.NoError(t, os.WriteFile(ociTar, []byte("dummy-oci-tar"), 0o600))

	err := cmd.RunE(cmd, []string{"docker-archive:" + dockerTar, "oci-archive:" + ociTar})
	require.NoError(t, err)
	assert.Equal(t, []string{"docker-archive:" + dockerTar, "oci-archive:" + ociTar}, mockKubescape.imgScanInfo.Images)
	assert.Equal(t, []string{"docker-archive:" + dockerTar, "oci-archive:" + ociTar}, mockKubescape.scanInfo.InputPatterns)
}

func TestGetImageCmd_ArgsAcceptsSeveralImages(t *testing.T) {
	cmd := getImageCmd(&mocks.MockIKubescape{}, &cautils.ScanInfo{})

	assert.NoError(t, cmd.Args(cmd, []string{"nginx:1.27", "redis:7", "postgres:16"}))
	assert.EqualError(t, cmd.Args(cmd, []string{}), "the command takes at least one image name as an argument")
	assert.EqualError(t, cmd.Args(cmd, []string{"nginx", "  "}), "image name cannot be empty")
}

func TestGetImageCmd_RunE_ForwardsEveryImageInOrder(t *testing.T) {
	mockKubescape := &imageScanCaptureKubescape{}
	scanInfo := cautils.ScanInfo{}

	cmd := getImageCmd(mockKubescape, &scanInfo)
	parentCmd := &cobra.Command{Use: "scan"}
	parentCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", "")
	parentCmd.AddCommand(cmd)

	err := cmd.RunE(cmd, []string{"nginx:1.27", "redis:7", "postgres:16"})
	assert.NoError(t, err)
	assert.Equal(t, []string{"nginx:1.27", "redis:7", "postgres:16"}, mockKubescape.imgScanInfo.Images)
}

func TestGetImageCmd_RunE_ScansRepeatedImageOnce(t *testing.T) {
	mockKubescape := &imageScanCaptureKubescape{}
	scanInfo := cautils.ScanInfo{}

	cmd := getImageCmd(mockKubescape, &scanInfo)
	parentCmd := &cobra.Command{Use: "scan"}
	parentCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", "")
	parentCmd.AddCommand(cmd)

	err := cmd.RunE(cmd, []string{"nginx:1.27", " nginx:1.27 ", "redis:7"})
	assert.NoError(t, err)
	assert.Equal(t, []string{"nginx:1.27", "redis:7"}, mockKubescape.imgScanInfo.Images)
}

func TestGetImageCmd_RunE_ForwardsMixedTarballAndRegistryImages(t *testing.T) {
	mockKubescape := &imageScanCaptureKubescape{}
	scanInfo := cautils.ScanInfo{}

	cmd := getImageCmd(mockKubescape, &scanInfo)
	parentCmd := &cobra.Command{Use: "scan"}
	parentCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", "")
	parentCmd.AddCommand(cmd)

	tmpFile, err := os.CreateTemp("", "dummy-*.tar")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	err = cmd.RunE(cmd, []string{tmpFile.Name(), "nginx:1.27"})
	assert.NoError(t, err)
	assert.Equal(t, []string{"docker-archive:" + tmpFile.Name(), "nginx:1.27"}, mockKubescape.imgScanInfo.Images)
}

func TestGetImageCmd_RunE_RejectsPostureFlags(t *testing.T) {
	testCases := []struct {
		name     string
		scanInfo cautils.ScanInfo
		wantErr  string
	}{
		{
			name:     "exclude-controls is rejected",
			scanInfo: cautils.ScanInfo{ExcludeControls: []string{"C-0001"}},
			wantErr:  "--exclude-controls is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls",
		},
		{
			name:     "skip-controls is rejected",
			scanInfo: cautils.ScanInfo{SkipControls: "C-0001"},
			wantErr:  "--skip-controls is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls",
		},
		{
			name:     "include-controls is rejected",
			scanInfo: cautils.ScanInfo{IncludeControls: "C-0001"},
			wantErr:  "--include-controls is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls",
		},
		{
			name:     "custom-rules is rejected",
			scanInfo: cautils.ScanInfo{CustomRules: "/path/to/rules"},
			wantErr:  "--custom-rules is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls",
		},
		{
			name:     "control-timeout is rejected",
			scanInfo: cautils.ScanInfo{ControlTimeout: 10 * time.Second},
			wantErr:  "--control-timeout is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls",
		},
		{
			name:     "controls-version is rejected",
			scanInfo: cautils.ScanInfo{ControlsVersion: "v1.0.0"},
			wantErr:  "--controls-version is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls",
		},
		{
			name:     "baseline is rejected",
			scanInfo: cautils.ScanInfo{Baseline: "base.json"},
			wantErr:  "--baseline is not supported for image scans: an image scan evaluates vulnerabilities, not posture baseline drift (use 'kubescape diff' to compare image scan reports)",
		},
		{
			name:     "baseline-fail-on-new is rejected",
			scanInfo: cautils.ScanInfo{BaselineFailOnNew: true},
			wantErr:  "--baseline-fail-on-new is not supported for image scans: an image scan evaluates vulnerabilities, not posture baseline drift (use 'kubescape diff' to compare image scan reports)",
		},
		{
			name:     "baseline-severity-threshold is rejected",
			scanInfo: cautils.ScanInfo{BaselineSeverityThreshold: "high"},
			wantErr:  "--baseline-severity-threshold is not supported for image scans: an image scan evaluates vulnerabilities, not posture baseline drift (use 'kubescape diff' to compare image scan reports)",
		},
		{
			name:     "compliance-threshold is rejected",
			scanInfo: cautils.ScanInfo{ComplianceThreshold: 80},
			wantErr:  "--compliance-threshold is not supported for image scans: an image scan evaluates vulnerabilities, not posture compliance scores (use --severity-threshold instead)",
		},
		{
			name:     "baseline-granularity is rejected",
			scanInfo: cautils.ScanInfo{BaselineGranularity: "control"},
			wantErr:  "--baseline-granularity is not supported for image scans: an image scan evaluates vulnerabilities, not posture baseline drift (use 'kubescape diff' to compare image scan reports)",
		},
		{
			name:     "fail-coverage-below is rejected",
			scanInfo: cautils.ScanInfo{FailCoverageThreshold: 80},
			wantErr:  "--fail-coverage-below is not supported for image scans: an image scan evaluates vulnerabilities, not posture control coverage (use --severity-threshold instead)",
		},
		{
			name:     "fail-on-degraded-config is rejected",
			scanInfo: cautils.ScanInfo{FailOnDegradedConfig: true},
			wantErr:  "--fail-on-degraded-config is not supported for image scans: an image scan evaluates vulnerabilities, not posture control configurations",
		},
		{
			name:     "controls-config is rejected",
			scanInfo: cautils.ScanInfo{ControlsInputs: "/path/to/controls.json"},
			wantErr:  "--controls-config is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls",
		},
		{
			name:     "include-namespaces is rejected",
			scanInfo: cautils.ScanInfo{IncludeNamespaces: "default"},
			wantErr:  "--include-namespaces is not supported for image scans: an image scan evaluates vulnerabilities, not Kubernetes namespaces",
		},
		{
			name:     "exclude-namespaces is rejected",
			scanInfo: cautils.ScanInfo{ExcludedNamespaces: "kube-system"},
			wantErr:  "--exclude-namespaces is not supported for image scans: an image scan evaluates vulnerabilities, not Kubernetes namespaces",
		},
		{
			name:     "include-kinds is rejected",
			scanInfo: cautils.ScanInfo{IncludeKinds: "Deployment"},
			wantErr:  "--include-kinds is not supported for image scans: an image scan evaluates vulnerabilities, not Kubernetes resource kinds",
		},
		{
			name:     "exclude-kinds is rejected",
			scanInfo: cautils.ScanInfo{ExcludeKinds: "Pod"},
			wantErr:  "--exclude-kinds is not supported for image scans: an image scan evaluates vulnerabilities, not Kubernetes resource kinds",
		},
		{
			name:     "label-selector is rejected",
			scanInfo: cautils.ScanInfo{LabelSelector: "app=nginx"},
			wantErr:  "--label-selector is not supported for image scans: an image scan evaluates vulnerabilities, not Kubernetes resource labels",
		},
		{
			name:     "incremental is rejected",
			scanInfo: cautils.ScanInfo{Incremental: true},
			wantErr:  "--incremental is not supported for image scans: an image scan evaluates vulnerabilities, not cached resource manifests",
		},
		{
			name:     "dry-run is rejected",
			scanInfo: cautils.ScanInfo{DryRun: true},
			wantErr:  "--dry-run is not supported for image scans: an image scan evaluates vulnerabilities, not cluster resource permissions",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockKubescape := &imageScanCaptureKubescape{}
			cmd := getImageCmd(mockKubescape, &tc.scanInfo)
			parentCmd := &cobra.Command{Use: "scan"}
			parentCmd.PersistentFlags().StringVarP(&tc.scanInfo.Format, "format", "f", "pretty-printer", "")
			parentCmd.AddCommand(cmd)

			err := cmd.RunE(cmd, []string{"nginx:1.27"})
			require.EqualError(t, err, tc.wantErr)
			assert.Nil(t, mockKubescape.imgScanInfo, "image scanner must not be invoked when posture flags are passed")
		})
	}
}

func TestGetScanCommand_RejectsPostureFlagsOnImageScan(t *testing.T) {
	testCases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "exclude-controls flag",
			args:    []string{"image", "--exclude-controls", "C-0001", "nginx:1.27"},
			wantErr: "--exclude-controls is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls",
		},
		{
			name:    "skip-controls flag",
			args:    []string{"image", "--skip-controls", "C-0001", "nginx:1.27"},
			wantErr: "--skip-controls is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls",
		},
		{
			name:    "include-controls flag",
			args:    []string{"image", "--include-controls", "C-0001", "nginx:1.27"},
			wantErr: "--include-controls is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls",
		},
		{
			name:    "custom-rules flag",
			args:    []string{"image", "--custom-rules", "./rules", "nginx:1.27"},
			wantErr: "--custom-rules is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls",
		},
		{
			name:    "control-timeout flag",
			args:    []string{"image", "--control-timeout", "10s", "nginx:1.27"},
			wantErr: "--control-timeout is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls",
		},
		{
			name:    "controls-version flag",
			args:    []string{"image", "--controls-version", "v1.0.0", "nginx:1.27"},
			wantErr: "--controls-version is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls",
		},
		{
			name:    "baseline flag",
			args:    []string{"image", "--baseline", "base.json", "nginx:1.27"},
			wantErr: "--baseline is not supported for image scans: an image scan evaluates vulnerabilities, not posture baseline drift (use 'kubescape diff' to compare image scan reports)",
		},
		{
			name:    "baseline-fail-on-new flag",
			args:    []string{"image", "--baseline-fail-on-new", "nginx:1.27"},
			wantErr: "--baseline-fail-on-new is not supported for image scans: an image scan evaluates vulnerabilities, not posture baseline drift (use 'kubescape diff' to compare image scan reports)",
		},
		{
			name:    "baseline-severity-threshold flag",
			args:    []string{"image", "--baseline-severity-threshold", "high", "nginx:1.27"},
			wantErr: "--baseline-severity-threshold is not supported for image scans: an image scan evaluates vulnerabilities, not posture baseline drift (use 'kubescape diff' to compare image scan reports)",
		},
		{
			name:    "compliance-threshold flag",
			args:    []string{"image", "--compliance-threshold", "80", "nginx:1.27"},
			wantErr: "--compliance-threshold is not supported for image scans: an image scan evaluates vulnerabilities, not posture compliance scores (use --severity-threshold instead)",
		},
		{
			name:    "baseline-granularity flag",
			args:    []string{"image", "--baseline-granularity", "control", "nginx:1.27"},
			wantErr: "--baseline-granularity is not supported for image scans: an image scan evaluates vulnerabilities, not posture baseline drift (use 'kubescape diff' to compare image scan reports)",
		},
		{
			name:    "baseline-granularity flag with default value",
			args:    []string{"image", "--baseline-granularity", "evidence", "nginx:1.27"},
			wantErr: "--baseline-granularity is not supported for image scans: an image scan evaluates vulnerabilities, not posture baseline drift (use 'kubescape diff' to compare image scan reports)",
		},
		{
			name:    "fail-coverage-below flag",
			args:    []string{"image", "--fail-coverage-below", "80", "nginx:1.27"},
			wantErr: "--fail-coverage-below is not supported for image scans: an image scan evaluates vulnerabilities, not posture control coverage (use --severity-threshold instead)",
		},
		{
			name:    "fail-on-degraded-config flag",
			args:    []string{"image", "--fail-on-degraded-config", "nginx:1.27"},
			wantErr: "--fail-on-degraded-config is not supported for image scans: an image scan evaluates vulnerabilities, not posture control configurations",
		},
		{
			name:    "controls-config flag",
			args:    []string{"image", "--controls-config", "./controls.json", "nginx:1.27"},
			wantErr: "--controls-config is not supported for image scans: an image scan evaluates vulnerabilities, not posture controls",
		},
		{
			name:    "include-namespaces flag",
			args:    []string{"image", "--include-namespaces", "default", "nginx:1.27"},
			wantErr: "--include-namespaces is not supported for image scans: an image scan evaluates vulnerabilities, not Kubernetes namespaces",
		},
		{
			name:    "exclude-namespaces flag",
			args:    []string{"image", "--exclude-namespaces", "kube-system", "nginx:1.27"},
			wantErr: "--exclude-namespaces is not supported for image scans: an image scan evaluates vulnerabilities, not Kubernetes namespaces",
		},
		{
			name:    "include-kinds flag",
			args:    []string{"image", "--include-kinds", "Deployment", "nginx:1.27"},
			wantErr: "--include-kinds is not supported for image scans: an image scan evaluates vulnerabilities, not Kubernetes resource kinds",
		},
		{
			name:    "exclude-kinds flag",
			args:    []string{"image", "--exclude-kinds", "Pod", "nginx:1.27"},
			wantErr: "--exclude-kinds is not supported for image scans: an image scan evaluates vulnerabilities, not Kubernetes resource kinds",
		},
		{
			name:    "label-selector flag",
			args:    []string{"image", "--label-selector", "app=nginx", "nginx:1.27"},
			wantErr: "--label-selector is not supported for image scans: an image scan evaluates vulnerabilities, not Kubernetes resource labels",
		},
		{
			name:    "incremental flag",
			args:    []string{"image", "--incremental", "nginx:1.27"},
			wantErr: "--incremental is not supported for image scans: an image scan evaluates vulnerabilities, not cached resource manifests",
		},
		{
			name:    "dry-run flag",
			args:    []string{"image", "--dry-run", "nginx:1.27"},
			wantErr: "--dry-run is not supported for image scans: an image scan evaluates vulnerabilities, not cluster resource permissions",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockKubescape := &imageScanCaptureKubescape{}
			cmd := GetScanCommand(mockKubescape)
			cmd.SetArgs(tc.args)

			err := cmd.Execute()
			require.EqualError(t, err, tc.wantErr)
			assert.Nil(t, mockKubescape.imgScanInfo, "image scanner must not be invoked when posture flags are passed")
		})
	}
}

func TestGetImageCmd_RunE_RejectsViewFlag(t *testing.T) {
	mockKubescape := &imageScanCaptureKubescape{}
	scanInfo := cautils.ScanInfo{}

	cmd := getImageCmd(mockKubescape, &scanInfo)
	parentCmd := &cobra.Command{Use: "scan"}
	parentCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "pretty-printer", "")
	parentCmd.PersistentFlags().StringVar(&scanInfo.View, "view", "security", "")
	parentCmd.AddCommand(cmd)

	err := parentCmd.ParseFlags([]string{"--view", "resource"})
	require.NoError(t, err)

	err = cmd.RunE(cmd, []string{"nginx:1.27"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--view is not supported for image scans: an image scan evaluates vulnerabilities, not posture views")
}
