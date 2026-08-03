package prerequisites

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/stretchr/testify/assert"
)

func TestGetPreReqCmd(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}

	cmd := GetPreReqCmd(mockKubescape)

	assert.NotNil(t, cmd)
	assert.Equal(t, "prerequisites", cmd.Use)
	assert.Equal(t, "Check prerequisites for installing Kubescape Operator", cmd.Short)
	assert.NotNil(t, cmd.Run)
}

func TestGetPreReqCmdKubeconfigFlag(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}

	cmd := GetPreReqCmd(mockKubescape)

	flag := cmd.PersistentFlags().Lookup("kubeconfig")
	assert.NotNil(t, flag)
	assert.Equal(t, "", flag.DefValue)
	assert.Equal(t, "Path to the kubeconfig file. If not set, in-cluster config is used or $HOME/.kube/config if outside a cluster.", flag.Usage)
}
