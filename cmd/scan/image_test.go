package scan

import (
	"testing"

	"github.com/kubescape/kubescape/v3/cmd/shared"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestGetImageCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}
	scanInfo := cautils.ScanInfo{
		AccountID: "new",
	}

	cmd := getImageCmd(mockKubescape, &scanInfo)

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
	assert.Equal(t, "format cannot be empty, supported formats: pretty-printer, json, sarif", err.Error())
}

func TestGetImageCmd_RunE_Success(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}
	scanInfo := cautils.ScanInfo{}

	cmd := getImageCmd(mockKubescape, &scanInfo)

	err := cmd.RunE(cmd, []string{"nginx"})
	assert.NoError(t, err)
}
