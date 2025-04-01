package patch

import (
	"testing"

	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"

	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestGetPatchCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	cmd := GetPatchCmd(mockKubescape)

	// Verify the command name and short description
	assert.Equal(t, "patch --image <image>:<tag> [flags]", cmd.Use)
	assert.Equal(t, "Patch container images with vulnerabilities", cmd.Short)
	assert.Equal(t, "Patch command is for automatically patching images with vulnerabilities.", cmd.Long)
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
		Image: "testing",
	}
	err := validateImagePatchInfo(patchInfo)
	assert.Nil(t, err)
}
