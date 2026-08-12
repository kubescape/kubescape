package operator

import (
	"errors"
	"io"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/core"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetOperatorScanVulnerabilitiesCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}
	operatorInfo := cautils.OperatorInfo{
		Namespace: "namespace",
	}

	cmd := getOperatorScanVulnerabilitiesCmd(mockKubescape, &operatorInfo)

	// Verify the command name and short description
	assert.Equal(t, "vulnerabilities", cmd.Use)
	assert.Equal(t, "Scan your cluster for vulnerabilities using the Kubescape Operator in-cluster components", cmd.Short)
	assert.Equal(t, "", cmd.Long)
	assert.Equal(t, operatorScanVulnerabilitiesExamples, cmd.Example)

	err := cmd.Args(&cobra.Command{}, []string{"random-arg"})
	assert.Nil(t, err)
}

func TestOperatorScanVulnerabilitiesCmd_ResolvesClusterNameAfterRootPreRun(t *testing.T) {
	previousContext := k8sinterface.GetContextName()
	k8sinterface.SetClusterContextName("construction-context")
	t.Cleanup(func() { k8sinterface.SetClusterContextName(previousContext) })

	previousAdapter := newOperatorAdapter
	var gotScanInfo cautils.OperatorScanInfo
	newOperatorAdapter = func(scanInfo cautils.OperatorScanInfo, _ string) (*core.OperatorAdapter, error) {
		gotScanInfo = scanInfo
		return nil, errors.New("stub: no real cluster in unit tests")
	}
	t.Cleanup(func() { newOperatorAdapter = previousAdapter })

	var kubeContext string
	rootCmd := &cobra.Command{
		Use: "kubescape",
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			k8sinterface.SetClusterContextName(kubeContext)
			return nil
		},
	}
	rootCmd.PersistentFlags().StringVar(&kubeContext, "kube-context", "", "")
	rootCmd.AddCommand(getOperatorScanVulnerabilitiesCmd(&mocks.MockIKubescape{}, &cautils.OperatorInfo{}))
	rootCmd.SetArgs([]string{"vulnerabilities", "--kube-context", "selected-context"})
	rootCmd.SetOut(io.Discard)
	rootCmd.SetErr(io.Discard)

	err := rootCmd.Execute()
	require.ErrorContains(t, err, "stub: no real cluster in unit tests")

	vulnerabilitiesScanInfo, ok := gotScanInfo.(*cautils.VulnerabilitiesScanInfo)
	require.True(t, ok)
	assert.Equal(t, "selected-context", vulnerabilitiesScanInfo.ClusterName)

	payload := vulnerabilitiesScanInfo.GetRequestPayload()
	require.Len(t, payload.Commands, 1)
	assert.Equal(t, "wlid://cluster-selected-context/namespace-", payload.Commands[0].WildWlid)
}
