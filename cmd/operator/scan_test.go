package operator

import (
	"io"
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

	cmd := getOperatorScanCmd(mockKubescape, &operatorInfo)

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
	expectedErrorMessage = "for the operator sub-command, only " + vulnerabilitiesSubCommand + " and " + configurationsSubCommand + " are supported. Refer to the examples above"
	assert.Equal(t, expectedErrorMessage, err.Error())
}

// TestOperatorScanCmd_NamespaceFlagPropagatesToChildCommands guards against a
// regression where operatorInfo was passed by value into the "configurations"
// and "vulnerabilities" child commands: the child received a copy frozen at
// the flag's default value, so a user-supplied --namespace was silently
// ignored by the command that actually reads it.
func TestOperatorScanCmd_NamespaceFlagPropagatesToChildCommands(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}
	operatorInfo := &cautils.OperatorInfo{}

	cmd := getOperatorScanCmd(mockKubescape, operatorInfo)
	cmd.SetArgs([]string{"configurations", "--namespace", "custom-ns"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	// Execution itself fails without a live cluster connection; we only care
	// that flag parsing wrote through to the same OperatorInfo the child
	// command's RunE reads from.
	_ = cmd.Execute()

	assert.Equal(t, "custom-ns", operatorInfo.Namespace)
}
