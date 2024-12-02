package operator

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestGetOperatorScanCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}
	operatorInfo := cautils.OperatorInfo{
		Namespace: "namespace",
	}

	cmd := getOperatorScanCmd(mockKubescape, operatorInfo)

	// Verify the command name and short description
	assert.Equal(t, "scan", cmd.Use)
	assert.Equal(t, "Scan your cluster using the Kubescape-operator within the cluster components", cmd.Short)
	assert.Equal(t, "", cmd.Long)
	assert.Equal(t, operatorExamples, cmd.Example)

	err := cmd.Args(&cobra.Command{}, []string{})
	expectedErrorMessage := "for operator scan sub command, you must pass at least 1 more sub commands, see above examples"
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = cmd.Args(&cobra.Command{}, []string{"operator"})
	assert.Nil(t, err)

	err = cmd.RunE(&cobra.Command{}, []string{})
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = cmd.RunE(&cobra.Command{}, []string{"configurations"})
	assert.Nil(t, err)

	err = cmd.RunE(&cobra.Command{}, []string{"vulnerabilities"})
	assert.Nil(t, err)

	err = cmd.RunE(&cobra.Command{}, []string{"random"})
	expectedErrorMessage = "For the operator sub-command, only " + vulnerabilitiesSubCommand + " and " + configurationsSubCommand + " are supported. Refer to the examples above."
	assert.Equal(t, expectedErrorMessage, err.Error())
}
