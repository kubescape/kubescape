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
	assert.Equal(t, "", configCmd.Long)
}
