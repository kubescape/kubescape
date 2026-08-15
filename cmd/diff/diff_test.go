package diff

import (
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
}

func (s *stubKubescape) Diff(_ *metav1.DiffInfo) (int, error) {
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
			wantErr:     `found 2 new failure(s) at or above severity threshold "all"`,
		},
		{
			name:        "fail-on-new with new failures uses the given severity threshold",
			args:        []string{"base.json", "head.json", "--fail-on-new", "--severity-threshold", "high"},
			newFailures: 1,
			wantErr:     `found 1 new failure(s) at or above severity threshold "high"`,
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
