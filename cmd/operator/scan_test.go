package operator

import (
	"errors"
	"io"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/core"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
//
// It substitutes newOperatorAdapter instead of calling into core.NewOperatorAdapter,
// both to avoid touching a real cluster (which can hang or os.Exit via
// logger.L().Fatal on an unusable kubeconfig) and to assert on the exact
// (scanInfo, namespace) pair the child hands to it — the parent's
// operatorInfo.Namespace alone doesn't prove the child read it.
func TestOperatorScanCmd_NamespaceFlagPropagatesToChildCommands(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}
	operatorInfo := &cautils.OperatorInfo{}

	var gotScanInfo cautils.OperatorScanInfo
	var gotNamespace string
	prevAdapter := newOperatorAdapter
	newOperatorAdapter = func(scanInfo cautils.OperatorScanInfo, ns string) (*core.OperatorAdapter, error) {
		gotScanInfo = scanInfo
		gotNamespace = ns
		return nil, errors.New("stub: no real cluster in unit tests")
	}
	t.Cleanup(func() { newOperatorAdapter = prevAdapter })

	cmd := getOperatorScanCmd(mockKubescape, operatorInfo)
	cmd.SetArgs([]string{"configurations", "--namespace", "custom-ns"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()
	require.Error(t, err) // the stub always errors; we only care what it was called with

	assert.Equal(t, "custom-ns", operatorInfo.Namespace)
	assert.Equal(t, "custom-ns", gotNamespace)
	assert.IsType(t, &cautils.ConfigScanInfo{}, gotScanInfo)
}
