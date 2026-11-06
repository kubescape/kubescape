package diff

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/core"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		name        string
		format      string
		wantError   bool
		expectedErr string
		wantFormat  string
	}{
		{name: "default pretty-printer", format: "pretty-printer", wantFormat: "pretty-printer"},
		{name: "summary-json", format: "summary-json", wantFormat: "summary-json"},
		{name: "summary-yaml", format: "summary-yaml", wantFormat: "summary-yaml"},
		{name: "summary-csv", format: "summary-csv", wantFormat: "summary-csv"},
		{name: "json", format: "json", wantFormat: "json"},
		{name: "yaml", format: "yaml", wantFormat: "yaml"},
		{name: "sarif", format: "sarif", wantFormat: "sarif"},
		{name: "junit", format: "junit", wantFormat: "junit"},
		{name: "gitlab-sast", format: "gitlab-sast", wantFormat: "gitlab-sast"},
		{name: "markdown", format: "markdown", wantFormat: "markdown"},
		{name: "uppercase format is normalized", format: "JSON", wantFormat: "json"},
		{name: "padded format is normalized", format: "  yaml  ", wantFormat: "yaml"},
		{name: "empty format is rejected", format: "", wantError: true, expectedErr: "format cannot be empty, supported formats:"},
		{name: "whitespace-only format is rejected", format: "   ", wantError: true, expectedErr: "format cannot be empty, supported formats:"},
		{name: "unsupported format is rejected", format: "html", wantError: true, expectedErr: `invalid format "html"`},
		{name: "scan report format is rejected", format: "pdf", wantError: true, expectedErr: `invalid format "pdf"`},
		{name: "image sbom format is rejected", format: "spdx-json", wantError: true, expectedErr: `invalid format "spdx-json"`},
		{name: "comma-separated multi-format is rejected", format: "json,pretty-printer", wantError: true, expectedErr: `invalid format "json,pretty-printer"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := &stubKubescape{}
			diffCmd := GetDiffCmd(stub)
			diffCmd.SetArgs([]string{"base.json", "head.json", "--format", tt.format})

			err := diffCmd.Execute()
			if tt.wantError {
				assert.ErrorContains(t, err, tt.expectedErr)
				assert.Nil(t, stub.received, "validation must happen before invoking core")
			} else {
				assert.NoError(t, err)
				if assert.NotNil(t, stub.received) {
					assert.Equal(t, tt.wantFormat, stub.received.Format)
				}
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
	assert.Contains(t, help, `--format string`)
	assert.Contains(t, help, `"pretty-printer", "summary-json", "summary-yaml", "summary-csv", "json", "yaml", "sarif", "junit", "gitlab-sast", "markdown"`)
}

func TestGetDiffCmd_FailOnNewAndSeverity(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		newFailures  int
		wantErr      string
		wantSeverity string
	}{
		{
			name:        "fail-on-new with new failures and empty severity reports all",
			args:        []string{"base.json", "head.json", "--fail-on-new"},
			newFailures: 2,
			wantErr:     `found 2 new or incomparable failure(s) at or above severity threshold "all"`,
		},
		{
			name:         "fail-on-new with new failures uses the given severity threshold",
			args:         []string{"base.json", "head.json", "--fail-on-new", "--severity-threshold", "high"},
			newFailures:  1,
			wantErr:      `found 1 new or incomparable failure(s) at or above severity threshold "high"`,
			wantSeverity: "high",
		},
		{
			name:         "fail-on-new with uppercase severity normalizes",
			args:         []string{"base.json", "head.json", "--fail-on-new", "--severity-threshold", "HIGH"},
			newFailures:  1,
			wantErr:      `found 1 new or incomparable failure(s) at or above severity threshold "high"`,
			wantSeverity: "high",
		},
		{
			name:         "fail-on-new with padded severity normalizes",
			args:         []string{"base.json", "head.json", "--fail-on-new", "--severity-threshold", "  medium  "},
			newFailures:  1,
			wantErr:      `found 1 new or incomparable failure(s) at or above severity threshold "medium"`,
			wantSeverity: "medium",
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
			name:         "valid severity without fail-on-new succeeds",
			args:         []string{"base.json", "head.json", "--severity-threshold", "medium"},
			newFailures:  3,
			wantSeverity: "medium",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := &stubKubescape{newFailures: tt.newFailures}
			diffCmd := GetDiffCmd(stub)
			diffCmd.SilenceErrors = true
			diffCmd.SetArgs(tt.args)

			err := diffCmd.Execute()
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
			if tt.wantSeverity != "" && assert.NotNil(t, stub.received) {
				assert.Equal(t, tt.wantSeverity, stub.received.SeverityThreshold)
			}
		})
	}
}

func TestGetDiffCmd_FailOnNewDoesNotPrintUsage(t *testing.T) {
	stub := &stubKubescape{newFailures: 1}
	diffCmd := GetDiffCmd(stub)
	var buf strings.Builder
	diffCmd.SetOut(&buf)
	diffCmd.SetErr(&buf)
	diffCmd.SetArgs([]string{"base.json", "head.json", "--fail-on-new"})

	err := diffCmd.Execute()

	assert.ErrorContains(t, err, "found 1 new or incomparable failure(s)")
	assert.NotContains(t, buf.String(), "Usage:", "threshold failure must not dump command usage")
}

func TestGetDiffCmd_ValidationErrorStillPrintsUsage(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		errMatch string
	}{
		{
			name:     "missing arguments",
			args:     []string{"base.json"},
			errMatch: "accepts 2 arg(s), received 1",
		},
		{
			name:     "empty base report path",
			args:     []string{"", "head.json"},
			errMatch: "base report file path cannot be empty",
		},
		{
			name:     "whitespace-only base report path",
			args:     []string{"   ", "head.json"},
			errMatch: "base report file path cannot be empty",
		},
		{
			name:     "empty head report path",
			args:     []string{"base.json", ""},
			errMatch: "head report file path cannot be empty",
		},
		{
			name:     "whitespace-only head report path",
			args:     []string{"base.json", "   "},
			errMatch: "head report file path cannot be empty",
		},
		{
			name:     "invalid format",
			args:     []string{"base.json", "head.json", "--format", "invalid"},
			errMatch: "invalid format",
		},
		{
			name:     "empty format",
			args:     []string{"base.json", "head.json", "--format", ""},
			errMatch: "format cannot be empty",
		},
		{
			name:     "whitespace format",
			args:     []string{"base.json", "head.json", "--format", "   "},
			errMatch: "format cannot be empty",
		},
		{
			name:     "invalid severity",
			args:     []string{"base.json", "head.json", "--severity-threshold", "invalid"},
			errMatch: "unknown severity",
		},
		{
			name:     "invalid granularity",
			args:     []string{"base.json", "head.json", "--granularity", "invalid"},
			errMatch: "invalid diff granularity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := &stubKubescape{}
			diffCmd := GetDiffCmd(stub)
			var buf strings.Builder
			diffCmd.SetOut(&buf)
			diffCmd.SetErr(&buf)
			diffCmd.SetArgs(tt.args)

			err := diffCmd.Execute()

			assert.ErrorContains(t, err, tt.errMatch)
			assert.Contains(t, buf.String(), "Usage:", "input validation errors must print command usage")
		})
	}
}

func TestGetDiffCmd_HonorsOutputWriter(t *testing.T) {
	stub := &stubKubescape{}
	diffCmd := GetDiffCmd(stub)
	var buf bytes.Buffer
	diffCmd.SetOut(&buf)
	diffCmd.SetArgs([]string{"base.json", "head.json"})

	err := diffCmd.Execute()
	require.NoError(t, err)
	require.NotNil(t, stub.received)
	assert.Same(t, &buf, stub.received.Writer)
}

func TestGetDiffCmd_NilKubescape(t *testing.T) {
	diffCmd := GetDiffCmd(nil)
	diffCmd.SilenceErrors = true
	diffCmd.SetArgs([]string{"base.json", "head.json"})

	err := diffCmd.Execute()
	require.Error(t, err)
	assert.EqualError(t, err, "uninitialized kubescape interface")
}

func TestGetDiffCmd_DirectRunE_Validations(t *testing.T) {
	t.Run("nil interface returns error", func(t *testing.T) {
		cmd := GetDiffCmd(nil)
		err := cmd.RunE(cmd, []string{"base.json", "head.json"})
		require.EqualError(t, err, "uninitialized kubescape interface")
	})

	t.Run("empty base report path returns error", func(t *testing.T) {
		stub := &stubKubescape{}
		cmd := GetDiffCmd(stub)
		err := cmd.RunE(cmd, []string{"", "head.json"})
		require.EqualError(t, err, "base report file path cannot be empty")
	})

	t.Run("whitespace-only base report path returns error", func(t *testing.T) {
		stub := &stubKubescape{}
		cmd := GetDiffCmd(stub)
		err := cmd.RunE(cmd, []string{"   ", "head.json"})
		require.EqualError(t, err, "base report file path cannot be empty")
	})

	t.Run("empty head report path returns error", func(t *testing.T) {
		stub := &stubKubescape{}
		cmd := GetDiffCmd(stub)
		err := cmd.RunE(cmd, []string{"base.json", ""})
		require.EqualError(t, err, "head report file path cannot be empty")
	})

	t.Run("whitespace-only head report path returns error", func(t *testing.T) {
		stub := &stubKubescape{}
		cmd := GetDiffCmd(stub)
		err := cmd.RunE(cmd, []string{"base.json", "   "})
		require.EqualError(t, err, "head report file path cannot be empty")
	})
}

func TestGetDiffCmd_OutputSafety_RejectsOverwrite(t *testing.T) {
	const baseContent = `{"results":[],"summaryDetails":{"controls":{}}}`
	const headContent = `{"results":[{"resourceID":"res1","controls":[{"controlID":"C-HIGH","name":"High","status":{"status":"failed"}}]}],"summaryDetails":{"controls":{"C-HIGH":{"scoreFactor":7.0}}}}`

	tempDir := t.TempDir()
	basePath := filepath.Join(tempDir, "base.json")
	headPath := filepath.Join(tempDir, "head.json")
	require.NoError(t, os.WriteFile(basePath, []byte(baseContent), 0o600))
	require.NoError(t, os.WriteFile(headPath, []byte(headContent), 0o600))

	ks := core.NewKubescape(context.Background())

	t.Run("output matching base report is rejected and preserves file", func(t *testing.T) {
		cmd := GetDiffCmd(ks)
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true
		cmd.SetArgs([]string{basePath, headPath, "--format", "json", "--output", basePath})

		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "would overwrite base report")

		content, readErr := os.ReadFile(basePath)
		require.NoError(t, readErr)
		assert.Equal(t, baseContent, string(content), "base report must not be modified")
	})

	t.Run("output matching head report is rejected and preserves file", func(t *testing.T) {
		cmd := GetDiffCmd(ks)
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true
		cmd.SetArgs([]string{basePath, headPath, "--format", "json", "--output", headPath})

		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "would overwrite head report")

		content, readErr := os.ReadFile(headPath)
		require.NoError(t, readErr)
		assert.Equal(t, headContent, string(content), "head report must not be modified")
	})

	t.Run("distinct output file succeeds", func(t *testing.T) {
		outFile := filepath.Join(tempDir, "diff_out.json")
		cmd := GetDiffCmd(ks)
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true
		cmd.SetArgs([]string{basePath, headPath, "--format", "json", "--output", outFile})

		err := cmd.Execute()
		require.NoError(t, err)

		content, readErr := os.ReadFile(outFile)
		require.NoError(t, readErr)
		assert.Contains(t, string(content), "C-HIGH")
	})
}
