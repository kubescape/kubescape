package operator

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestGetOperatorScanConfigCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}
	operatorInfo := cautils.OperatorInfo{
		Namespace: "namespace",
	}

	cmd := getOperatorScanConfigCmd(mockKubescape, operatorInfo)

	// Verify the command name and short description
	assert.Equal(t, "configurations", cmd.Use)
	assert.Equal(t, "Trigger configuration scanning from the Kubescape Operator microservice", cmd.Short)
	assert.Equal(t, "", cmd.Long)
	assert.Equal(t, operatorScanConfigExamples, cmd.Example)

	err := cmd.Args(&cobra.Command{}, []string{})
	assert.Nil(t, err)

	err = cmd.Args(&cobra.Command{}, []string{"configurations"})
	assert.Nil(t, err)
}
