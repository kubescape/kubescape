package config

import (
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/stretchr/testify/assert"
)

func TestGetConfigCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	// Call the GetConfigCmd function
	configCmd := GetConfigCmd(mockKubescape)

	// Verify the command name and short description
	assert.Equal(t, "config", configCmd.Use)
	assert.Equal(t, "Handle cached configurations", configCmd.Short)
	assert.Equal(t, configExample, configCmd.Example)

	// Verify that the subcommands are added correctly
	assert.Equal(t, 3, len(configCmd.Commands()))

	for _, subcmd := range configCmd.Commands() {
		switch subcmd.Name() {
		case "delete":
			// Verify that the delete subcommand is added correctly
			assert.Equal(t, "delete", subcmd.Use)
			assert.Equal(t, "Delete cached configurations", subcmd.Short)
		case "set":
			// Verify that the set subcommand is added correctly
			assert.Equal(t, "set", subcmd.Use)
			assert.Equal(t, "Set configurations, supported: "+strings.Join(stringKeysToSlice(supportConfigSet), "/"), subcmd.Short)
		case "view":
			// Verify that the view subcommand is added correctly
			assert.Equal(t, "view", subcmd.Use)
			assert.Equal(t, "View cached configurations", subcmd.Short)
		default:
			t.Errorf("Unexpected subcommand name: %s", subcmd.Name())
		}
	}
}
