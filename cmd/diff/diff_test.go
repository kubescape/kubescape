package diff

import (
	"strings"
	"testing"

	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/stretchr/testify/assert"
)

// stubKubescape returns a configurable new-failure count from Diff so the
// command's --fail-on-new gate can be exercised without real scan reports.
type stubKubescape struct {
	mocks.MockIKubescape
	newFailures int
	received    *metav1.DiffInfo
}

func (s *stubKubescape) Diff(info *metav1.DiffInfo) (int, error) {
	copy := *info
	s.received = &copy
	return s.newFailures, nil
}

func TestGetDiffCmd_FormatValidation(t *testing.T) {
	tests := []struct {
		name      string
		format    string
		wantError bool
	}{
		{"default pretty-printer", "pretty-printer", false},
		{"json", "json", false},
		{"yaml", "yaml", false},
		{"unsupported format is rejected", "html", true},
		{"scan-only format is rejected", "sarif", true},
		{"comma-separated multi-format is rejected", "json,pretty-printer", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diffCmd := GetDiffCmd(&mocks.MockIKubescape{})
			diffCmd.SetArgs([]string{"base.json", "head.json", "--format", tt.format})

			err := diffCmd.Execute()
			if tt.wantError {
				assert.ErrorContains(t, err, "invalid format")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetDiffCmd_Granularity(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		wantGranularity string
		wantError       string
	}{
		{
			name:            "evidence is the default",
			args:            []string{"base.json", "head.json"},
			wantGranularity: "evidence",
		},
		{
			name:            "evidence can be explicit",
			args:            []string{"base.json", "head.json", "--granularity", "evidence"},
			wantGranularity: "evidence",
		},
		{
			name:            "control compatibility mode",
			args:            []string{"base.json", "head.json", "--granularity", "control"},
			wantGranularity: "control",
		},
		{
			name:            "case-insensitive value is accepted and forwarded",
			args:            []string{"base.json", "head.json", "--granularity", "CONTROL"},
			wantGranularity: "CONTROL",
		},
		{
			name:      "unknown value is rejected",
			args:      []string{"base.json", "head.json", "--granularity", "path"},
			wantError: "invalid diff granularity",
		},
		{
			name:      "near miss is rejected",
			args:      []string{"base.json", "head.json", "--granularity", "controls"},
			wantError: "invalid diff granularity",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stub := &stubKubescape{}
			command := GetDiffCmd(stub)
			command.SilenceUsage = true
			command.SilenceErrors = true
			command.SetArgs(test.args)

			err := command.Execute()
			if test.wantError != "" {
				assert.ErrorContains(t, err, test.wantError)
				assert.Nil(t, stub.received, "validation must happen before invoking core")
				return
			}
			assert.NoError(t, err)
			if assert.NotNil(t, stub.received) {
				assert.Equal(t, test.wantGranularity, stub.received.Granularity)
				assert.Equal(t, "base.json", stub.received.BaseFile)
				assert.Equal(t, "head.json", stub.received.HeadFile)
			}
		})
	}
}

func TestGetDiffCmd_HelpExplainsEvidenceComparison(t *testing.T) {
	command := GetDiffCmd(&stubKubescape{})
	var output strings.Builder
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"--help"})

	assert.NoError(t, command.Execute())
	help := output.String()
	assert.Contains(t, help, "--granularity")
	assert.Contains(t, help, `"evidence" or "control"`)
	assert.Contains(t, help, "failed rules and paths are compared")
	assert.Contains(t, help, "--granularity control")
}

func TestGetDiffCmd_FailOnNewAndSeverity(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		newFailures int
		wantErr     string
	}{
		{
			name:        "fail-on-new with new failures and empty severity reports all",
			args:        []string{"base.json", "head.json", "--fail-on-new"},
			newFailures: 2,
			wantErr:     `found 2 new or incomparable failure(s) at or above severity threshold "all"`,
		},
		{
			name:        "fail-on-new with new failures uses the given severity threshold",
			args:        []string{"base.json", "head.json", "--fail-on-new", "--severity-threshold", "high"},
			newFailures: 1,
			wantErr:     `found 1 new or incomparable failure(s) at or above severity threshold "high"`,
		},
		{
			name:        "fail-on-new with no new failures succeeds",
			args:        []string{"base.json", "head.json", "--fail-on-new"},
			newFailures: 0,
		},
		{
			name:        "new failures without fail-on-new succeed",
			args:        []string{"base.json", "head.json"},
			newFailures: 5,
		},
		{
			name:    "invalid severity is rejected",
			args:    []string{"base.json", "head.json", "--severity-threshold", "unknown"},
			wantErr: "unknown severity",
		},
		{
			name:        "valid severity without fail-on-new succeeds",
			args:        []string{"base.json", "head.json", "--severity-threshold", "medium"},
			newFailures: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diffCmd := GetDiffCmd(&stubKubescape{newFailures: tt.newFailures})
			diffCmd.SilenceUsage = true
			diffCmd.SilenceErrors = true
			diffCmd.SetArgs(tt.args)

			err := diffCmd.Execute()
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
