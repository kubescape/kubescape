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

func TestGetConfigCmd_NilKubescape(t *testing.T) {
	configCmd := GetConfigCmd(nil)
	assert.NotNil(t, configCmd)

	tests := []struct {
		name string
		args []string
	}{
		{name: "view", args: []string{"view"}},
		{name: "validate", args: []string{"validate"}},
		{name: "delete", args: []string{"delete"}},
		{name: "set", args: []string{"set", "accountID=6f2c3e1a-9b4d-4c8e-a1f2-3b4c5d6e7f80"}},
	}

	for _, tt := range tests {
		cmd := GetConfigCmd(nil)
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		cmd.SetArgs(tt.args)
		err := cmd.Execute()
		assert.EqualError(t, err, "uninitialized kubescape interface", "subcommand %s should return uninitialized error", tt.name)
	}
}
