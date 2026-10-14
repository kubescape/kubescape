package config

import (
	"fmt"
	"os"
	"testing"

	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type capturingValidate struct {
	mocks.MockIKubescape
	got *metav1.ValidateConfig
}

func (c *capturingValidate) ValidateCachedConfig(vc *metav1.ValidateConfig) error {
	c.got = vc
	return nil
}

type validateCachedConfigErr struct {
	mocks.MockIKubescape
	got *metav1.ValidateConfig
}

func (v *validateCachedConfigErr) ValidateCachedConfig(vc *metav1.ValidateConfig) error {
	v.got = vc
	return fmt.Errorf("validation failed")
}

func TestGetValidateCmd(t *testing.T) {
	cmd := getValidateCmd(&mocks.MockIKubescape{})

	assert.Equal(t, "validate", cmd.Use)

	formatFlag := cmd.Flag("format")
	if assert.NotNil(t, formatFlag) {
		assert.Equal(t, "f", formatFlag.Shorthand)
		assert.Equal(t, "text", formatFlag.DefValue)
	}

	outputFlag := cmd.Flag("output")
	if assert.NotNil(t, outputFlag) {
		assert.Equal(t, "o", outputFlag.Shorthand)
		assert.Equal(t, "text", outputFlag.DefValue)
	}

	includeOKFlag := cmd.Flag("include-ok")
	if assert.NotNil(t, includeOKFlag) {
		assert.Equal(t, "", includeOKFlag.Shorthand)
		assert.Equal(t, "false", includeOKFlag.DefValue)
	}

	profileFlag := cmd.Flag("profile")
	if assert.NotNil(t, profileFlag) {
		assert.Equal(t, "", profileFlag.Shorthand)
		assert.Equal(t, "cloud", profileFlag.DefValue)
	}
}

func TestGetValidateCmd_RunEPassesFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantFormat  string
		wantProfile string
		wantOK      bool
	}{
		{name: "defaults", args: []string{}, wantFormat: "text", wantProfile: "cloud", wantOK: false},
		{name: "format json", args: []string{"--format", "json"}, wantFormat: "json", wantProfile: "cloud", wantOK: false},
		{name: "short format yaml", args: []string{"-f", "yaml"}, wantFormat: "yaml", wantProfile: "cloud", wantOK: false},
		{name: "output json", args: []string{"--output", "json"}, wantFormat: "json", wantProfile: "cloud", wantOK: false},
		{name: "short output yaml", args: []string{"-o", "yaml"}, wantFormat: "yaml", wantProfile: "cloud", wantOK: false},
		{name: "format takes precedence over output", args: []string{"--format", "yaml", "--output", "json"}, wantFormat: "yaml", wantProfile: "cloud", wantOK: false},
		{name: "include ok", args: []string{"--include-ok"}, wantFormat: "text", wantProfile: "cloud", wantOK: true},
		{name: "json include ok", args: []string{"--format", "json", "--include-ok"}, wantFormat: "json", wantProfile: "cloud", wantOK: true},
		{name: "offline profile", args: []string{"--profile", "offline"}, wantFormat: "text", wantProfile: "offline", wantOK: false},
		{name: "offline yaml include ok", args: []string{"--profile", "offline", "--format", "yaml", "--include-ok"}, wantFormat: "yaml", wantProfile: "offline", wantOK: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := &capturingValidate{}
			cmd := getValidateCmd(ks)
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			require.NoError(t, err)
			if !assert.NotNil(t, ks.got) {
				return
			}
			assert.Equal(t, tt.wantFormat, ks.got.Format)
			assert.Equal(t, tt.wantProfile, ks.got.Profile)
			assert.Equal(t, tt.wantOK, ks.got.IncludeOK)
			assert.Equal(t, os.Stdout, ks.got.Writer)
		})
	}
}

func TestGetValidateCmd_RunEReturnsValidationError(t *testing.T) {
	ks := &validateCachedConfigErr{}
	cmd := getValidateCmd(ks)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--format", "json"})

	err := cmd.Execute()

	require.EqualError(t, err, "validation failed")
	require.NotNil(t, ks.got)
	assert.Equal(t, "json", ks.got.Format)
}
