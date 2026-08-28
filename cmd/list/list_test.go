package list

import (
	"context"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/kubescape/v4/core/meta"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingListKubescape struct {
	meta.IKubescape
	received *metav1.ListPolicies
}

func (r *recordingListKubescape) Context() context.Context {
	return context.Background()
}

func (r *recordingListKubescape) List(listPolicies *metav1.ListPolicies) (*metav1.ListResult, error) {
	copy := *listPolicies
	r.received = &copy
	return &metav1.ListResult{}, nil
}

func TestGetListCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	// Call the GetListCmd function
	listCmd := GetListCmd(mockKubescape)

	// Verify the command name and short description
	assert.Equal(t, "list <policy> [flags]", listCmd.Use)
	assert.Equal(t, "List the supported frameworks, controls and control configuration", listCmd.Short)
	assert.Equal(t, "", listCmd.Long)
	assert.Equal(t, listExample, listCmd.Example)
	supported := strings.Join(core.ListSupportActions(), ",")

	err := listCmd.Args(&cobra.Command{}, []string{})
	expectedErrorMessage := "policy type required, supported: " + supported
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = listCmd.Args(&cobra.Command{}, []string{"not-frameworks"})
	expectedErrorMessage = "invalid parameter 'not-frameworks'. Supported parameters: " + supported
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = listCmd.Args(&cobra.Command{}, []string{"frameworks"})
	assert.Nil(t, err)

	err = listCmd.RunE(&cobra.Command{}, []string{"some-value"})
	assert.ErrorContains(t, err, "invalid target")
}

func TestGetListCmd_ControlFilterFlags(t *testing.T) {
	recorder := &recordingListKubescape{}
	listCmd := GetListCmd(recorder)
	listCmd.SetArgs([]string{"controls", "--framework", "NSA", "--search", "container", "--format", "json"})

	require.NoError(t, listCmd.Execute())
	require.NotNil(t, recorder.received)
	assert.Equal(t, "controls", recorder.received.Target)
	assert.Equal(t, "json", recorder.received.Format)
	assert.Equal(t, "NSA", recorder.received.ControlFilters.Framework)
	assert.Equal(t, "container", recorder.received.ControlFilters.Search)
}

func TestGetListCmd_ControlFilterFlagsRejectNonControlsTarget(t *testing.T) {
	listCmd := GetListCmd(&recordingListKubescape{})
	listCmd.SilenceUsage = true
	listCmd.SilenceErrors = true
	listCmd.SetArgs([]string{"frameworks", "--framework", "NSA"})

	err := listCmd.Execute()
	require.Error(t, err)
	assert.EqualError(t, err, "--framework and --search can only be used with 'list controls'")
}

func TestGetListCmd_ControlFilterFlagMetadata(t *testing.T) {
	listCmd := GetListCmd(&mocks.MockIKubescape{})

	frameworkFlag := listCmd.PersistentFlags().Lookup("framework")
	require.NotNil(t, frameworkFlag)
	assert.Equal(t, "", frameworkFlag.DefValue)
	assert.Contains(t, frameworkFlag.Usage, "Only applies to 'controls'")

	searchFlag := listCmd.PersistentFlags().Lookup("search")
	require.NotNil(t, searchFlag)
	assert.Equal(t, "", searchFlag.DefValue)
	assert.Contains(t, searchFlag.Usage, "Case-insensitive")
}
