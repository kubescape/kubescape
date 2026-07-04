package patch

import (
	"testing"

	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"

	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPatchCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	cmd := GetPatchCmd(mockKubescape)

	// Verify the command name and short description
	assert.Equal(t, "patch --image <image>:<tag> [flags]", cmd.Use)
	assert.Equal(t, "Patch container images to fix known OS-level vulnerabilities", cmd.Short)
	assert.Equal(t, "Automatically patch container images to remediate known OS-level vulnerabilities using Copa and BuildKit.", cmd.Long)
	assert.Equal(t, patchCmdExamples, cmd.Example)

	err := cmd.Args(&cobra.Command{}, []string{})
	assert.Nil(t, err)

	err = cmd.Args(&cobra.Command{}, []string{"test"})
	expectedErrorMessage := "the command takes no arguments"
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = cmd.RunE(&cobra.Command{}, []string{})
	expectedErrorMessage = "image tag is required"
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = cmd.RunE(&cobra.Command{}, []string{"patch", "--image", "docker.io/library/nginx:1.22"})
	assert.Equal(t, expectedErrorMessage, err.Error())
}

func TestGetPatchCmdWithNonExistentImage(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	// Call the GetPatchCmd function
	cmd := GetPatchCmd(mockKubescape)

	// Run the command with a non-existent image argument
	err := cmd.RunE(&cobra.Command{}, []string{"patch", "--image", "non-existent-image"})

	// Check that there is an error and the error message is as expected
	expectedErrorMessage := "image tag is required"
	assert.Error(t, err)
	assert.Equal(t, expectedErrorMessage, err.Error())
}

func Test_validateImagePatchInfo_EmptyImage(t *testing.T) {
	patchInfo := &metav1.PatchInfo{}
	err := validateImagePatchInfo(patchInfo)
	assert.NotNil(t, err)
	assert.Equal(t, "image tag is required", err.Error())
}

func Test_validateImagePatchInfo_Image(t *testing.T) {
	patchInfo := &metav1.PatchInfo{
		Image:      "testing",
		OutputMode: "docker",
	}
	err := validateImagePatchInfo(patchInfo)
	assert.Nil(t, err)
}

// TestPatchCmd_OutputModeFlags verifies the --output-mode and --output-path flags exist, default correctly, and
// are wired into PatchInfo. Guards against accidental regression of the output mode behavior.
func TestPatchCmd_OutputModeFlags(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}
	cmd := GetPatchCmd(mockKubescape)

	outputModeFlag := cmd.PersistentFlags().Lookup("output-mode")
	assert.NotNil(t, outputModeFlag, "--output-mode flag must be registered")
	assert.Equal(t, "docker", outputModeFlag.DefValue, "--output-mode must default to docker")

	outputPathFlag := cmd.PersistentFlags().Lookup("output-path")
	assert.NotNil(t, outputPathFlag, "--output-path flag must be registered")
	assert.Equal(t, "", outputPathFlag.DefValue, "--output-path must default to empty")

	// Default value: parsing without flags leaves output-mode as docker
	require.NoError(t, cmd.PersistentFlags().Parse([]string{"--image", "nginx:1.23"}))
	assert.False(t, outputModeFlag.Changed)

	// Explicit --output-mode sets the flag
	cmd2 := GetPatchCmd(mockKubescape)
	require.NoError(t, cmd2.PersistentFlags().Parse([]string{"--image", "nginx:1.23", "--output-mode", "image"}))
	outputModeFlag2 := cmd2.PersistentFlags().Lookup("output-mode")
	assert.True(t, outputModeFlag2.Changed)
	assert.Equal(t, "image", outputModeFlag2.Value.String())
}

func Test_validateImagePatchInfo_DefaultsTagAndPatchedTag(t *testing.T) {
	patchInfo := &metav1.PatchInfo{
		Image:      "nginx",
		OutputMode: "docker",
	}

	err := validateImagePatchInfo(patchInfo)

	assert.NoError(t, err)
	assert.Equal(t, "docker.io/library/nginx:latest", patchInfo.Image)
	assert.Equal(t, "latest", patchInfo.ImageTag)
	assert.Equal(t, "latest-patched", patchInfo.PatchedImageTag)
	assert.Equal(t, "nginx", patchInfo.ImageName)
}

func Test_validateImagePatchInfo_DigestOnlyReturnsError(t *testing.T) {
	patchInfo := &metav1.PatchInfo{
		Image:      "nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		OutputMode: "docker",
	}

	err := validateImagePatchInfo(patchInfo)

	assert.Error(t, err)
	assert.Equal(t, "unexpected error while parsing image tag", err.Error())
}

func Test_validateImagePatchInfo_OutputModeValidation(t *testing.T) {
	// Invalid output mode
	patchInfoInvalid := &metav1.PatchInfo{
		Image:      "nginx",
		OutputMode: "invalid-mode",
	}
	err := validateImagePatchInfo(patchInfoInvalid)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid output mode")

	// Missing output-path for oci
	patchInfoOciNoPath := &metav1.PatchInfo{
		Image:      "nginx",
		OutputMode: "oci",
	}
	err = validateImagePatchInfo(patchInfoOciNoPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "output-path is required when output-mode is oci")

	// Push overrides to image
	patchInfoPush := &metav1.PatchInfo{
		Image:      "nginx",
		OutputMode: "docker", // should be overridden
		Push:       true,
	}
	err = validateImagePatchInfo(patchInfoPush)
	assert.NoError(t, err)
	assert.Equal(t, "image", patchInfoPush.OutputMode)
}
