package scan

import (
	"fmt"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestGetFrameworkCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}
	scanInfo := cautils.ScanInfo{
		AccountID: "new",
	}

	cmd := getFrameworkCmd(mockKubescape, &scanInfo)

	// Verify the command name and short description
	assert.Equal(t, "framework <framework names list> [`<glob pattern>`/`-`] [flags]", cmd.Use)
	assert.Equal(t, fmt.Sprintf("The framework you wish to use. Run '%[1]s list frameworks' for the list of supported frameworks", cautils.ExecName()), cmd.Short)
	assert.Equal(t, frameworkExample, cmd.Example)

	err := cmd.Args(&cobra.Command{}, []string{})
	expectedErrorMessage := "requires at least one framework name"
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = cmd.Args(&cobra.Command{}, []string{"nsa,mitre"})
	assert.Nil(t, err)

	err = cmd.Args(&cobra.Command{}, []string{"nsa,mitre,"})
	expectedErrorMessage = "usage: <framework-0>,<framework-1>"
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = cmd.RunE(&cobra.Command{}, []string{})
	expectedErrorMessage = "bad argument: accound ID must be a valid UUID"
	assert.Equal(t, expectedErrorMessage, err.Error())
}

func TestGetFrameworkCmdWithNonExistentFramework(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}
	scanInfo := cautils.ScanInfo{
		AccountID: "new",
	}

	// Call the GetFrameworkCmd function
	cmd := getFrameworkCmd(mockKubescape, &scanInfo)

	// Run the command with a non-existent framework argument
	err := cmd.RunE(&cobra.Command{}, []string{"framework", "nsa,mitre"})

	// Check that there is an error and the error message is as expected
	expectedErrorMessage := "bad argument: accound ID must be a valid UUID"
	assert.Error(t, err)
	assert.Equal(t, expectedErrorMessage, err.Error())
}
