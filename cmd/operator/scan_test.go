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
	assert.Equal(t, operatorScanExamples, cmd.Example)
	// `operator scan` must not advertise the parent's `operator remediate` example.
	assert.NotContains(t, cmd.Example, "operator remediate")

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

// TestOperatorScanConfigCmd_FrameworksDefaultsToAll guards the flag-level
// default: with no --frameworks passed, the scan info received by the operator
// adapter must carry ["all"], not an empty slice. The default lives at the
// flag boundary (cmd/operator/configscan.go), not inside GetRequestPayload.
func TestOperatorScanConfigCmd_FrameworksDefaultsToAll(t *testing.T) {
	var gotScanInfo cautils.OperatorScanInfo
	prev := newOperatorAdapter
	newOperatorAdapter = func(si cautils.OperatorScanInfo, _ string) (*core.OperatorAdapter, error) {
		gotScanInfo = si
		return nil, errors.New("stub")
	}
	t.Cleanup(func() { newOperatorAdapter = prev })

	cmd := getOperatorScanCmd(&mocks.MockIKubescape{}, &cautils.OperatorInfo{})
	cmd.SetArgs([]string{"configurations"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	_ = cmd.Execute()

	cfg, ok := gotScanInfo.(*cautils.ConfigScanInfo)
	require.True(t, ok)
	assert.Equal(t, []string{"all"}, cfg.Frameworks)
}

// TestOperatorScanConfigCmd_ExplicitFrameworksReplacesDefault guards pflag's
// replace-on-first-set semantics: an explicit --frameworks value must replace
// the ["all"] default, not append to it (pflag v1.0.10 string_slice.go Set()).
func TestOperatorScanConfigCmd_ExplicitFrameworksReplacesDefault(t *testing.T) {
	var gotScanInfo cautils.OperatorScanInfo
	prev := newOperatorAdapter
	newOperatorAdapter = func(si cautils.OperatorScanInfo, _ string) (*core.OperatorAdapter, error) {
		gotScanInfo = si
		return nil, errors.New("stub")
	}
	t.Cleanup(func() { newOperatorAdapter = prev })

	cmd := getOperatorScanCmd(&mocks.MockIKubescape{}, &cautils.OperatorInfo{})
	cmd.SetArgs([]string{"configurations", "--frameworks", "nsa,mitre"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	_ = cmd.Execute()

	cfg, ok := gotScanInfo.(*cautils.ConfigScanInfo)
	require.True(t, ok)
	assert.Equal(t, []string{"nsa", "mitre"}, cfg.Frameworks)
}
