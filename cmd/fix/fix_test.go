package fix

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestGetFixCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	// Call the GetFixCmd function
	fixCmd := GetFixCmd(mockKubescape)

	// Verify the command name and short description
	assert.Equal(t, "fix <report output file>", fixCmd.Use)
	assert.Equal(t, "Propose a fix for the misconfiguration found when scanning Kubernetes manifest files", fixCmd.Short)
	assert.Equal(t, "", fixCmd.Long)
	assert.Equal(t, fixCmdExamples, fixCmd.Example)

	err := fixCmd.RunE(&cobra.Command{}, []string{})
	expectedErrorMessage := "report output file is required"
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = fixCmd.RunE(&cobra.Command{}, []string{"random-file.json"})
	assert.Nil(t, err)
}
