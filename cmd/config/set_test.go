package config

import (
	"fmt"
	"strings"
	"testing"

	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/stretchr/testify/assert"
)

func TestGetSetCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	// Call the GetConfigCmd function
	configCmd := getSetCmd(mockKubescape)

	// Verify the command name and short description
	assert.Equal(t, "set", configCmd.Use)
	assert.Equal(t, "Set configurations, supported: "+strings.Join(stringKeysToSlice(supportConfigSet), "/"), configCmd.Short)
	assert.Equal(t, setConfigExample, configCmd.Example)
	assert.Equal(t, stringKeysToSlice(supportConfigSet), configCmd.ValidArgs)
}

// Should return a slice of keys when given a non-empty map
func TestStringKeysToSlice(t *testing.T) {
	m := map[string]func(*metav1.SetConfig, string){
		"key1": nil,
		"key2": nil,
		"key3": nil,
	}
	result := stringKeysToSlice(m)
	expected := []string{"key1", "key2", "key3"}
	assert.ElementsMatch(t, expected, result)
}

func TestParseSetArgs_InvalidFormat(t *testing.T) {
	args := []string{"key"}
	setConfig, err := parseSetArgs(args)
	assert.Equal(t, "", setConfig.Account)
	assert.Equal(t, "", setConfig.AccessKey)
	assert.Equal(t, "", setConfig.CloudReportURL)
	assert.Equal(t, "", setConfig.CloudAPIURL)

	expectedErrorMessage := fmt.Sprintf("key '' unknown . supported: %s", strings.Join(stringKeysToSlice(supportConfigSet), "/"))
	assert.Equal(t, expectedErrorMessage, err.Error())
}

func TestParseSetArgs_AccessKey(t *testing.T) {
	args := []string{"accessKey", "value1"}
	setConfig, _ := parseSetArgs(args)
	assert.Equal(t, "", setConfig.Account)
	assert.Equal(t, "value1", setConfig.AccessKey)
	assert.Equal(t, "", setConfig.CloudReportURL)
	assert.Equal(t, "", setConfig.CloudAPIURL)
}

func TestParseSetArgs_Single(t *testing.T) {
	args := []string{"accountID=value1"}
	setConfig, _ := parseSetArgs(args)
	assert.Equal(t, "value1", setConfig.Account)
	assert.Equal(t, "", setConfig.AccessKey)
	assert.Equal(t, "", setConfig.CloudReportURL)
	assert.Equal(t, "", setConfig.CloudAPIURL)
}
