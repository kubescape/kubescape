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
	assert.NotEmpty(t, cmd.Example)
	assert.NotNil(t, cmd.Args)
	assert.NotNil(t, cmd.RunE)
}

func TestGetPreReqCmdKubeconfigFlag(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}

	cmd := GetPreReqCmd(mockKubescape)

	flag := cmd.PersistentFlags().Lookup("kubeconfig")
	require.NotNil(t, flag)
	assert.Equal(t, "", flag.DefValue)
	assert.Contains(t, flag.Usage, "Path to the kubeconfig file")
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

func TestGetPreReqCmd_RejectsUnexpectedArgs(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		errContains string
	}{
		{
			name:        "single unexpected positional argument",
			args:        []string{"unexpected"},
			errContains: `unknown command "unexpected"`,
		},
		{
			name:        "multiple unexpected positional arguments",
			args:        []string{"arg1", "arg2"},
			errContains: `unknown command "arg1"`,
		},
		{
			name:        "flag followed by unexpected positional argument",
			args:        []string{"--kubeconfig", "/path/to/config", "extra"},
			errContains: `unknown command "extra"`,
		},
		{
			name:        "unknown flag",
			args:        []string{"--unknown-flag"},
			errContains: `unknown flag: --unknown-flag`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockKubescape := &mocks.MockIKubescape{}
			cmd := GetPreReqCmd(mockKubescape)
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestGetPreReqCmd_Execute_DefaultKubeconfig(t *testing.T) {
	origBuild := buildKubeClient
	origCollect := collectClusterData
	t.Cleanup(func() {
		buildKubeClient = origBuild
		collectClusterData = origCollect
	})

	var capturedPath string
	buildKubeClient = func(path string) (*kubernetes.Clientset, bool) {
		capturedPath = path
		return &kubernetes.Clientset{}, false
	}

	collectCalled := false
	collectClusterData = func(context.Context, *kubernetes.Clientset) (*common.ClusterData, error) {
		collectCalled = true
		return &common.ClusterData{}, errors.New("abort early for test")
	}

	mockKubescape := &mocks.MockIKubescape{}
	cmd := GetPreReqCmd(mockKubescape)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.Error(t, err)
	assert.ErrorContains(t, err, "abort early for test")
	assert.True(t, collectCalled)
	assert.Equal(t, "", capturedPath)
}

func TestGetPreReqCmd_Execute_KubeconfigPassed(t *testing.T) {
	origBuild := buildKubeClient
	origCollect := collectClusterData
	t.Cleanup(func() {
		buildKubeClient = origBuild
		collectClusterData = origCollect
	})

	var capturedPath string
	buildKubeClient = func(path string) (*kubernetes.Clientset, bool) {
		capturedPath = path
		return &kubernetes.Clientset{}, false
	}

	collectCalled := false
	collectClusterData = func(context.Context, *kubernetes.Clientset) (*common.ClusterData, error) {
		collectCalled = true
		return &common.ClusterData{}, errors.New("abort early for test")
	}

	mockKubescape := &mocks.MockIKubescape{}
	cmd := GetPreReqCmd(mockKubescape)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--kubeconfig", "/path/to/custom/kubeconfig"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.ErrorContains(t, err, "abort early for test")
	assert.True(t, collectCalled)
	assert.Equal(t, "/path/to/custom/kubeconfig", capturedPath)
}

func TestGetPreReqCmd_NilKubescape(t *testing.T) {
	origBuild := buildKubeClient
	t.Cleanup(func() { buildKubeClient = origBuild })

	buildKubeClient = func(string) (*kubernetes.Clientset, bool) {
		return nil, false
	}

	cmd := GetPreReqCmd(nil)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not create kube client")
}

func TestGetPreReqCmd_NilKubescape_UsesCommandContext(t *testing.T) {
	origBuild := buildKubeClient
	origCollect := collectClusterData
	t.Cleanup(func() {
		buildKubeClient = origBuild
		collectClusterData = origCollect
	})

	buildKubeClient = func(string) (*kubernetes.Clientset, bool) {
		return &kubernetes.Clientset{}, false
	}

	var capturedCtx context.Context
	collectClusterData = func(ctx context.Context, _ *kubernetes.Clientset) (*common.ClusterData, error) {
		capturedCtx = ctx
		return &common.ClusterData{}, errors.New("abort early for test")
	}

	type testContextKey string
	ctx := context.WithValue(context.Background(), testContextKey("test-key"), "test-val")

	cmd := GetPreReqCmd(nil)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{})

	err := cmd.ExecuteContext(ctx)
	require.Error(t, err)
	assert.ErrorContains(t, err, "abort early for test")
	assert.Equal(t, ctx, capturedCtx)
}
