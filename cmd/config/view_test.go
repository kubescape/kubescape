package config

import (
	"bytes"
	"testing"

	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	assert.Equal(t, "view [KEY]", configCmd.Use)

	formatFlag := configCmd.Flag("format")
	if assert.NotNil(t, formatFlag) {
		assert.Equal(t, "f", formatFlag.Shorthand)
		assert.Equal(t, "text", formatFlag.DefValue)
	}

	outputFlag := configCmd.Flag("output")
	if assert.NotNil(t, outputFlag) {
		assert.Equal(t, "o", outputFlag.Shorthand)
		assert.Equal(t, "text", outputFlag.DefValue)
	}

	includeEmptyFlag := configCmd.Flag("include-empty")
	if assert.NotNil(t, includeEmptyFlag) {
		assert.Equal(t, "e", includeEmptyFlag.Shorthand)
		assert.Equal(t, "false", includeEmptyFlag.DefValue)
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
		{name: "format json", args: []string{"--format", "json"}, wantFormat: "json", wantEmpty: false},
		{name: "short format yaml", args: []string{"-f", "yaml"}, wantFormat: "yaml", wantEmpty: false},
		{name: "output json", args: []string{"--output", "json"}, wantFormat: "json", wantEmpty: false},
		{name: "short output yaml", args: []string{"-o", "yaml"}, wantFormat: "yaml", wantEmpty: false},
		{name: "format takes precedence over output", args: []string{"--format", "yaml", "--output", "json"}, wantFormat: "yaml", wantEmpty: false},
		{name: "include-empty", args: []string{"--include-empty"}, wantFormat: "text", wantEmpty: true},
		{name: "format json with include-empty short flags", args: []string{"-f", "json", "-e"}, wantFormat: "json", wantEmpty: true},
		{name: "output json with include-empty short flags", args: []string{"-o", "json", "-e"}, wantFormat: "json", wantEmpty: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := &capturingView{}
			cmd := getViewCmd(ks)
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			assert.NoError(t, err)
			if !assert.NotNil(t, ks.got) {
				return
			}
			assert.Equal(t, tt.wantFormat, ks.got.OutputFormat)
			assert.Equal(t, tt.wantEmpty, ks.got.IncludeEmpty)
			assert.Equal(t, &buf, ks.got.Writer)
		})
	}
}

func TestGetViewCmd_RejectsUnexpectedArgs(t *testing.T) {
	ks := &capturingView{}
	cmd := getViewCmd(ks)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"key1", "key2"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "accepts at most 1 arg(s), received 2")
	assert.Nil(t, ks.got)
}

func TestGetViewCmd_NilKubescape(t *testing.T) {
	cmd := getViewCmd(nil)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.EqualError(t, err, "uninitialized kubescape interface")

	cmdWithKey := getViewCmd(nil)
	cmdWithKey.SilenceUsage = true
	cmdWithKey.SilenceErrors = true
	cmdWithKey.SetArgs([]string{"accountID"})
	err = cmdWithKey.Execute()
	require.EqualError(t, err, "uninitialized kubescape interface")
}

func TestGetViewCmd_RejectsEmptyFormat(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"empty format flag", []string{"--format", ""}},
		{"whitespace format flag", []string{"--format", "   "}},
		{"empty short format flag", []string{"-f", ""}},
		{"empty output alias", []string{"--output", ""}},
		{"whitespace output alias", []string{"--output", "   "}},
		{"empty short output alias", []string{"-o", ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := &capturingView{}
			cmd := getViewCmd(ks)
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			require.EqualError(t, err, "format cannot be empty, supported formats: text, json, yaml")
			assert.Nil(t, ks.got)
		})
	}
}

func TestGetViewCmd_RejectsUnsupportedFormat(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"unsupported format flag", []string{"--format", "xml"}},
		{"unsupported short format flag", []string{"-f", "csv"}},
		{"unsupported output alias", []string{"--output", "html"}},
		{"unsupported short output alias", []string{"-o", "pdf"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := &capturingView{}
			cmd := getViewCmd(ks)
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unsupported format")
			assert.Contains(t, err.Error(), "supported formats: text, json, yaml")
			assert.Nil(t, ks.got)
		})
	}
}
