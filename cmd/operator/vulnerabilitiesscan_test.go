package operator

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestGetOperatorScanVulnerabilitiesCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}
	operatorInfo := cautils.OperatorInfo{
		Namespace: "namespace",
	}

	cmd := getOperatorScanVulnerabilitiesCmd(mockKubescape, operatorInfo)

	// Verify the command name and short description
	assert.Equal(t, "vulnerabilities", cmd.Use)
	assert.Equal(t, "Vulnerabilities use for scan your cluster vulnerabilities using Kubescape operator in the in cluster components", cmd.Short)
	assert.Equal(t, "", cmd.Long)
	assert.Equal(t, operatorScanVulnerabilitiesExamples, cmd.Example)

	err := cmd.Args(&cobra.Command{}, []string{"random-arg"})
	assert.Nil(t, err)
}
