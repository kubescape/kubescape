package patch

import (
	"strings"
	"testing"

	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"

	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/mocks"
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

// TestPatchCmd_FormatFlagValidation verifies --format accepts every format supported for image
// scans (shared.ImageScanFormats) and rejects formats that are not (e.g. csv, which requires posture
// scan data that patch's image-only results never populate), plus the empty-value case.
func TestPatchCmd_FormatFlagValidation(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}

	for _, format := range shared.ImageScanFormats {
		t.Run("accepts_"+format, func(t *testing.T) {
			cmd := GetPatchCmd(mockKubescape)
			cmd.SetArgs([]string{"--image", "nginx:1.23", "--format", format})
			err := cmd.Execute()
			// Past the format check, execution fails later (no buildkit/registry available
			// in this test environment) - what matters is the error is NOT a format complaint.
			if err != nil {
				assert.NotContains(t, err.Error(), "invalid format")
			}
		})
	}

	t.Run("accepts_comma_separated_formats", func(t *testing.T) {
		cmd := GetPatchCmd(mockKubescape)
		cmd.SetArgs([]string{"--image", "nginx:1.23", "--format", "json,sarif"})
		err := cmd.Execute()
		if err != nil {
			assert.NotContains(t, err.Error(), "invalid format")
		}
	})

	t.Run("rejects_comma_separated_with_invalid_entry", func(t *testing.T) {
		cmd := GetPatchCmd(mockKubescape)
		cmd.SetArgs([]string{"--image", "nginx:1.23", "--format", "json,csv"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), `invalid format "csv"`)
	})

	t.Run("rejects_csv", func(t *testing.T) {
		cmd := GetPatchCmd(mockKubescape)
		cmd.SetArgs([]string{"--image", "nginx:1.23", "--format", "csv"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), `invalid format "csv"`)
		assert.Contains(t, err.Error(), "pretty-printer")
	})

	t.Run("rejects_empty", func(t *testing.T) {
		cmd := GetPatchCmd(mockKubescape)
		cmd.SetArgs([]string{"--image", "nginx:1.23", "--format", ""})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "format cannot be empty")
	})
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

// registryFixtureValue assembles credential-looking test values from parts so no
// literal password string appears in the source (which trips secret scanners).
func registryFixtureValue(parts ...string) string {
	return strings.Join(parts, "-")
}

// TestPatchCmd_RegistryCredentialsFromEnv verifies `kubescape patch` picks up registry
// credentials from KUBESCAPE_REGISTRY_USERNAME/KUBESCAPE_REGISTRY_PASSWORD when the
// corresponding flags are omitted, so a registry password never has to be typed on the
// command line - where it is visible in `ps`, /proc/<pid>/cmdline and shell history.
// `kubescape scan image` already honours these variables (cmd/scan/scan.go); patch
// authenticates against the same registries with the same -u/-p flags.
func TestPatchCmd_RegistryCredentialsFromEnv(t *testing.T) {
	envUser := registryFixtureValue("env", "user")
	envCredential := registryFixtureValue("env", "credential")

	t.Setenv("KUBESCAPE_REGISTRY_USERNAME", envUser)
	t.Setenv("KUBESCAPE_REGISTRY_PASSWORD", envCredential)

	cmd := GetPatchCmd(&mocks.MockIKubescape{})
	cmd.SetArgs([]string{"--image", "nginx:1.23"})
	require.NoError(t, cmd.Execute())

	assert.Equal(t, envUser, cmd.PersistentFlags().Lookup("username").Value.String(),
		"--username omitted: the username must come from KUBESCAPE_REGISTRY_USERNAME")
	assert.Equal(t, envCredential, cmd.PersistentFlags().Lookup("password").Value.String(),
		"--password omitted: the password must come from KUBESCAPE_REGISTRY_PASSWORD")
}

// TestPatchCmd_RegistryCredentialFlagsBeatEnv verifies flags still win end-to-end, so
// the environment fallback cannot silently swap the credentials of an existing
// `kubescape patch -u ... -p ...` invocation.
func TestPatchCmd_RegistryCredentialFlagsBeatEnv(t *testing.T) {
	flagUser := registryFixtureValue("flag", "user")
	flagCredential := registryFixtureValue("flag", "credential")

	t.Setenv("KUBESCAPE_REGISTRY_USERNAME", registryFixtureValue("env", "user"))
	t.Setenv("KUBESCAPE_REGISTRY_PASSWORD", registryFixtureValue("env", "credential"))

	cmd := GetPatchCmd(&mocks.MockIKubescape{})
	cmd.SetArgs([]string{"--image", "nginx:1.23", "--username", flagUser, "--password", flagCredential})
	require.NoError(t, cmd.Execute())

	assert.Equal(t, flagUser, cmd.PersistentFlags().Lookup("username").Value.String())
	assert.Equal(t, flagCredential, cmd.PersistentFlags().Lookup("password").Value.String())
}

func Test_applyRegistryCredentialsFromEnv(t *testing.T) {
	envUser := registryFixtureValue("env", "user")
	envCredential := registryFixtureValue("env", "credential")
	flagUser := registryFixtureValue("flag", "user")
	flagCredential := registryFixtureValue("flag", "credential")

	// newPatchCmd builds a command with the same credential flags patch registers,
	// bound to the returned PatchInfo.
	newPatchCmd := func() (*cobra.Command, *metav1.PatchInfo) {
		patchInfo := &metav1.PatchInfo{}
		cmd := &cobra.Command{Use: "patch"}
		cmd.PersistentFlags().StringVarP(&patchInfo.Username, "username", "u", "", "")
		cmd.PersistentFlags().StringVarP(&patchInfo.Password, "password", "p", "", "")
		return cmd, patchInfo
	}

	t.Run("both credentials come from the environment when no flag is given", func(t *testing.T) {
		t.Setenv("KUBESCAPE_REGISTRY_USERNAME", envUser)
		t.Setenv("KUBESCAPE_REGISTRY_PASSWORD", envCredential)

		cmd, patchInfo := newPatchCmd()
		applyRegistryCredentialsFromEnv(cmd, patchInfo)

		assert.Equal(t, envUser, patchInfo.Username)
		assert.Equal(t, envCredential, patchInfo.Password)
	})

	t.Run("flags take precedence over the environment", func(t *testing.T) {
		t.Setenv("KUBESCAPE_REGISTRY_USERNAME", envUser)
		t.Setenv("KUBESCAPE_REGISTRY_PASSWORD", envCredential)

		cmd, patchInfo := newPatchCmd()
		require.NoError(t, cmd.PersistentFlags().Set("username", flagUser))
		require.NoError(t, cmd.PersistentFlags().Set("password", flagCredential))

		applyRegistryCredentialsFromEnv(cmd, patchInfo)

		assert.Equal(t, flagUser, patchInfo.Username)
		assert.Equal(t, flagCredential, patchInfo.Password)
	})

	t.Run("username flag pairs with password from the environment", func(t *testing.T) {
		t.Setenv("KUBESCAPE_REGISTRY_USERNAME", envUser)
		t.Setenv("KUBESCAPE_REGISTRY_PASSWORD", envCredential)

		cmd, patchInfo := newPatchCmd()
		require.NoError(t, cmd.PersistentFlags().Set("username", flagUser))

		applyRegistryCredentialsFromEnv(cmd, patchInfo)

		assert.Equal(t, flagUser, patchInfo.Username)
		assert.Equal(t, envCredential, patchInfo.Password,
			"passing only --username is the intended way to keep the password off the command line")
	})

	t.Run("explicitly empty flag is not overridden by the environment", func(t *testing.T) {
		t.Setenv("KUBESCAPE_REGISTRY_USERNAME", envUser)
		t.Setenv("KUBESCAPE_REGISTRY_PASSWORD", envCredential)

		cmd, patchInfo := newPatchCmd()
		require.NoError(t, cmd.PersistentFlags().Set("username", ""))
		require.NoError(t, cmd.PersistentFlags().Set("password", ""))

		applyRegistryCredentialsFromEnv(cmd, patchInfo)

		assert.Empty(t, patchInfo.Username, `--username "" is an explicit request for no credential`)
		assert.Empty(t, patchInfo.Password, `--password "" is an explicit request for no credential`)
	})

	t.Run("credentials stay empty when neither flag nor environment is set", func(t *testing.T) {
		t.Setenv("KUBESCAPE_REGISTRY_USERNAME", "")
		t.Setenv("KUBESCAPE_REGISTRY_PASSWORD", "")

		cmd, patchInfo := newPatchCmd()
		applyRegistryCredentialsFromEnv(cmd, patchInfo)

		assert.Empty(t, patchInfo.Username)
		assert.Empty(t, patchInfo.Password)
	})

	t.Run("nil patch info is a no-op", func(t *testing.T) {
		cmd, _ := newPatchCmd()
		assert.NotPanics(t, func() { applyRegistryCredentialsFromEnv(cmd, nil) })
	})
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

	// Push overrides to image when output-mode is default (docker)
	patchInfoPush := &metav1.PatchInfo{
		Image:      "nginx",
		OutputMode: "docker", // should be overridden
		Push:       true,
	}
	err = validateImagePatchInfo(patchInfoPush)
	assert.NoError(t, err)
	assert.Equal(t, "image", patchInfoPush.OutputMode)

	// Push with explicit non-image output-mode should error
	patchInfoPushConflict := &metav1.PatchInfo{
		Image:      "nginx",
		OutputMode: "oci",
		Push:       true,
	}
	err = validateImagePatchInfo(patchInfoPushConflict)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}
