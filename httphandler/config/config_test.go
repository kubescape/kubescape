package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Loads configuration from file successfully
func TestLoadConfigFromFileSuccessfully(t *testing.T) {
	// Set up test data
	path := "/path/to/config"
	expectedConfig := Config{
		Namespace:             "",
		ClusterName:           "",
		ContinuousPostureScan: false,
	}

	// Call the function under test
	config, err := LoadConfig(path)

	// Check the result
	assert.Equal(t, expectedConfig, config)
	assert.NotNil(t, err)
}
