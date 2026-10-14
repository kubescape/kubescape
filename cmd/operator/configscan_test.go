package operator

import (
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestGetOperatorScanConfigCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}
	operatorInfo := cautils.OperatorInfo{
		Namespace: "namespace",
	}

	cmd := getOperatorScanConfigCmd(mockKubescape, &operatorInfo)

	assert.Equal(t, "configurations", cmd.Use)

	err := cmd.Args(&cobra.Command{}, []string{})
	assert.Nil(t, err)

	err = cmd.Args(&cobra.Command{}, []string{"configurations"})
	assert.Nil(t, err)
}
