package config

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/stretchr/testify/assert"
)

func TestGetViewCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	// Call the GetConfigCmd function
	configCmd := getViewCmd(mockKubescape)

	// Verify the command name and short description
	assert.Equal(t, "view", configCmd.Use)
	assert.Equal(t, "View cached configurations", configCmd.Short)
	assert.Equal(t, "View cached Kubescape configuration in a human-readable text format, or render it as JSON or YAML.", configCmd.Long)

	outputFlag := configCmd.Flag("output")
	if assert.NotNil(t, outputFlag) {
		assert.Equal(t, "text", outputFlag.DefValue)
		assert.Equal(t, "Output format: text, json, or yaml", outputFlag.Usage)
	}

	includeEmptyFlag := configCmd.Flag("include-empty")
	if assert.NotNil(t, includeEmptyFlag) {
		assert.Equal(t, "false", includeEmptyFlag.DefValue)
		assert.Equal(t, "Include empty values in the rendered output", includeEmptyFlag.Usage)
	}
}
