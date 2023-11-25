package list

import (
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v3/core/core"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestGetListCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	// Call the GetListCmd function
	listCmd := GetListCmd(mockKubescape)

	// Verify the command name and short description
	assert.Equal(t, "list <policy> [flags]", listCmd.Use)
	assert.Equal(t, "List frameworks/controls will list the supported frameworks and controls", listCmd.Short)
	assert.Equal(t, "", listCmd.Long)
	assert.Equal(t, listExample, listCmd.Example)
	supported := strings.Join(core.ListSupportActions(), ",")

	err := listCmd.Args(&cobra.Command{}, []string{})
	expectedErrorMessage := "policy type requeued, supported: " + supported
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = listCmd.Args(&cobra.Command{}, []string{"not-frameworks"})
	expectedErrorMessage = "invalid parameter 'not-frameworks'. Supported parameters: " + supported
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = listCmd.Args(&cobra.Command{}, []string{"frameworks"})
	assert.Nil(t, err)

	err = listCmd.RunE(&cobra.Command{}, []string{})
	expectedErrorMessage = "no arguements provided"
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = listCmd.RunE(&cobra.Command{}, []string{"some-value"})
	assert.Nil(t, err)
}
