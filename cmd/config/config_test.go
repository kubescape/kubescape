package config

import (
	"testing"

	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/stretchr/testify/assert"
)

func TestGetConfigCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	// Call the GetConfigCmd function
	configCmd := GetConfigCmd(mockKubescape)

	assert.Equal(t, "config", configCmd.Use)

	expectedSubcommands := map[string]string{
		"delete":   "delete [KEY...]",
		"set":      "set",
		"validate": "validate",
		"view":     "view [KEY]",
	}

	for name, wantUse := range expectedSubcommands {
		subcmd, _, err := configCmd.Find([]string{name})
		if assert.NoError(t, err, "subcommand %s must be registered", name) && assert.NotNil(t, subcmd) {
			assert.Equal(t, wantUse, subcmd.Use)
		}
	}
}
