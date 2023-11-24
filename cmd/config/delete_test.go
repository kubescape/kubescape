package config

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/stretchr/testify/assert"
)

func TestGetDeleteCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	// Call the GetConfigCmd function
	configCmd := getDeleteCmd(mockKubescape)

	// Verify the command name and short description
	assert.Equal(t, "delete", configCmd.Use)
	assert.Equal(t, "Delete cached configurations", configCmd.Short)
	assert.Equal(t, "", configCmd.Long)
}
