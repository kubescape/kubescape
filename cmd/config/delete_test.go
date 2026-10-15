package config

import (
	"testing"

	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/stretchr/testify/assert"
)

func TestGetDeleteCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	// Call the GetConfigCmd function
	configCmd := getDeleteCmd(mockKubescape)

	assert.Equal(t, "delete [KEY...]", configCmd.Use)
}
