package config

import (
	"fmt"
	"strings"
	"testing"

	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// setCachedConfigErr implements SetCachedConfig failure for RunE error propagation tests.
type setCachedConfigErr struct {
	mocks.MockIKubescape
}

func (setCachedConfigErr) SetCachedConfig(*metav1.SetConfig) error {
	return fmt.Errorf("persist failed")
}

func TestGetSetCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	// Call the GetConfigCmd function
	configSetCmd := getSetCmd(mockKubescape)

	// Verify the command name and short description
	assert.Equal(t, "set", configSetCmd.Use)
	assert.Equal(t, "Set configurations, supported: "+strings.Join(stringKeysToSlice(supportConfigSet), "/"), configSetCmd.Short)
	assert.Equal(t, setConfigExample, configSetCmd.Example)
	assert.Equal(t, stringKeysToSlice(supportConfigSet), configSetCmd.ValidArgs)

	err := configSetCmd.RunE(&cobra.Command{}, []string{"accountID=value1"})
	assert.Nil(t, err)

	err = configSetCmd.RunE(&cobra.Command{}, []string{})
	assert.ErrorContains(t, err, "missing arguments")
	assert.ErrorContains(t, err, "supported keys:")
}

func TestGetSetCmd_SetCachedConfigReturnsError(t *testing.T) {
	cmd := getSetCmd(&setCachedConfigErr{})
	err := cmd.RunE(&cobra.Command{}, []string{"accountID=value1"})
	assert.EqualError(t, err, "persist failed")
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
	assert.Nil(t, setConfig)
	assert.ErrorContains(t, err, "invalid argument")
	assert.ErrorContains(t, err, "key")
	assert.ErrorContains(t, err, "supported keys:")
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

func TestParseSetArgs_InvalidKey(t *testing.T) {
	args := []string{"invalidKey=value1"}
	_, err := parseSetArgs(args)
	assert.EqualError(t, err, `key "invalidKey" unknown; supported: accessKey/accountID/cloudAPIURL/cloudReportURL`)
}

func TestParseSetArgs_TooManyArgs(t *testing.T) {
	_, err := parseSetArgs([]string{"accountID", "v", "extra"})
	assert.ErrorContains(t, err, "too many arguments")
	assert.ErrorContains(t, err, "supported keys:")
}
