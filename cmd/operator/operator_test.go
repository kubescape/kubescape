package operator

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestGetOperatorCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	cmd := GetOperatorCmd(mockKubescape)

	// Verify the command name and short description
	assert.Equal(t, "operator", cmd.Use)
	assert.Equal(t, "The operator is used to communicate with the Kubescape Operator within the cluster components.", cmd.Short)
	assert.Equal(t, "", cmd.Long)
	assert.Equal(t, operatorExamples, cmd.Example)

	err := cmd.Args(&cobra.Command{}, []string{})
	expectedErrorMessage := "For the operator sub-command, you need to provide at least one additional sub-command. Refer to the examples above."
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = cmd.Args(&cobra.Command{}, []string{"scan", "configurations"})
	assert.Nil(t, err)

	err = cmd.RunE(&cobra.Command{}, []string{})
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = cmd.RunE(&cobra.Command{}, []string{"scan", "configurations"})
	assert.Nil(t, err)

	err = cmd.RunE(&cobra.Command{}, []string{"scan"})
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = cmd.RunE(&cobra.Command{}, []string{"random-subcommand", "random-config"})
	expectedErrorMessage = "For the operator sub-command, only " + scanSubCommand + " is supported. Refer to the examples above."
	assert.Equal(t, expectedErrorMessage, err.Error())
}
