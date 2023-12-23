package scan

import (
	"fmt"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestGetControlCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}
	scanInfo := cautils.ScanInfo{
		AccountID: "new",
	}

	cmd := getControlCmd(mockKubescape, &scanInfo)

	// Verify the command name and short description
	assert.Equal(t, "control <control names list>/<control ids list>", cmd.Use)
	assert.Equal(t, fmt.Sprintf("The controls you wish to use. Run '%[1]s list controls' for the list of supported controls", cautils.ExecName()), cmd.Short)
	assert.Equal(t, controlExample, cmd.Example)

	err := cmd.Args(&cobra.Command{}, []string{})
	expectedErrorMessage := "requires at least one control name"
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = cmd.Args(&cobra.Command{}, []string{"C-0001,C-0002"})
	assert.Nil(t, err)

	err = cmd.Args(&cobra.Command{}, []string{"C-0001,C-0002,"})
	expectedErrorMessage = "usage: <control-0>,<control-1>"
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = cmd.RunE(&cobra.Command{}, []string{})
	expectedErrorMessage = "bad argument: accound ID must be a valid UUID"
	assert.Equal(t, expectedErrorMessage, err.Error())
}

func TestGetControlCmdWithNonExistentControl(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}
	scanInfo := cautils.ScanInfo{
		AccountID: "new",
	}

	// Call the GetControlCmd function
	cmd := getControlCmd(mockKubescape, &scanInfo)

	// Run the command with a non-existent control argument
	err := cmd.RunE(&cobra.Command{}, []string{"control", "C-0001,C-0002"})

	// Check that there is an error and the error message is as expected
	expectedErrorMessage := "bad argument: accound ID must be a valid UUID"
	assert.Error(t, err)
	assert.Equal(t, expectedErrorMessage, err.Error())
}
