package config

import (
	"os"
	"testing"

	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/stretchr/testify/assert"
)

// capturingView records the ViewConfig passed to ViewCachedConfig so tests can
// assert that command flags are wired through.
type capturingView struct {
	mocks.MockIKubescape
	got *metav1.ViewConfig
}

func (c *capturingView) ViewCachedConfig(vc *metav1.ViewConfig) error {
	c.got = vc
	return nil
}

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

func TestGetViewCmd_RunEPassesFlags(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantFormat string
		wantEmpty  bool
	}{
		{name: "defaults", args: []string{}, wantFormat: "text", wantEmpty: false},
		{name: "output json", args: []string{"--output", "json"}, wantFormat: "json", wantEmpty: false},
		{name: "short output yaml", args: []string{"-o", "yaml"}, wantFormat: "yaml", wantEmpty: false},
		{name: "include-empty", args: []string{"--include-empty"}, wantFormat: "text", wantEmpty: true},
		{name: "json with include-empty short flags", args: []string{"-o", "json", "-e"}, wantFormat: "json", wantEmpty: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := &capturingView{}
			cmd := getViewCmd(ks)
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			assert.NoError(t, err)
			if !assert.NotNil(t, ks.got) {
				return
			}
			assert.Equal(t, tt.wantFormat, ks.got.OutputFormat)
			assert.Equal(t, tt.wantEmpty, ks.got.IncludeEmpty)
			assert.Equal(t, os.Stdout, ks.got.Writer)
		})
	}
}
