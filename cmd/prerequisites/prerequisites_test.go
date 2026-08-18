package prerequisites

import (
	"context"
	"errors"
	"testing"

	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/kubescape/sizing-checker/pkg/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
)

func TestGetPreReqCmd(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}

	cmd := GetPreReqCmd(mockKubescape)

	assert.NotNil(t, cmd)
	assert.Equal(t, "prerequisites", cmd.Use)
	assert.Equal(t, "Check prerequisites for installing Kubescape Operator", cmd.Short)
	assert.NotNil(t, cmd.RunE)
}

func TestGetPreReqCmdKubeconfigFlag(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}

	cmd := GetPreReqCmd(mockKubescape)

	flag := cmd.PersistentFlags().Lookup("kubeconfig")
	assert.NotNil(t, flag)
	assert.Equal(t, "", flag.DefValue)
	assert.Equal(t, "Path to the kubeconfig file. If not set, in-cluster config is used or $HOME/.kube/config if outside a cluster.", flag.Usage)
}

func TestRunPrerequisites_NilClientReturnsError(t *testing.T) {
	origBuild := buildKubeClient
	t.Cleanup(func() { buildKubeClient = origBuild })

	buildKubeClient = func(string) (*kubernetes.Clientset, bool) {
		return nil, false
	}

	err := runPrerequisites(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not create kube client")
}

func TestRunPrerequisites_CollectClusterDataErrorAborts(t *testing.T) {
	origBuild := buildKubeClient
	origCollect := collectClusterData
	t.Cleanup(func() {
		buildKubeClient = origBuild
		collectClusterData = origCollect
	})

	buildKubeClient = func(string) (*kubernetes.Clientset, bool) {
		// Non-nil sentinel is enough: collectClusterData is stubbed and never uses it.
		return &kubernetes.Clientset{}, false
	}

	collectCalled := false
	collectClusterData = func(context.Context, *kubernetes.Clientset) (*common.ClusterData, error) {
		collectCalled = true
		return &common.ClusterData{}, errors.New("pods is forbidden")
	}

	err := runPrerequisites(context.Background(), "/tmp/restricted.kubeconfig")
	require.Error(t, err)
	assert.True(t, collectCalled)
	assert.ErrorContains(t, err, "failed to collect cluster data")
	assert.ErrorContains(t, err, "pods is forbidden")
}
