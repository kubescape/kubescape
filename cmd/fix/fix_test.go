package fix

import (
	"io"
	"testing"

	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestGetFixCmd(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	// Call the GetFixCmd function
	fixCmd := GetFixCmd(mockKubescape)

	assert.Equal(t, "fix <report output file>", fixCmd.Use)

	err := fixCmd.RunE(&cobra.Command{}, []string{})
	expectedErrorMessage := "report output file is required"
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = fixCmd.RunE(&cobra.Command{}, []string{"random-file.json"})
	assert.Nil(t, err)
}

// Goes through Execute, not RunE, so Cobra's argument validation runs.
func TestFixCmdArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		// Non-nil: SetArgs(nil) makes Execute fall back to os.Args.
		{name: "no report", args: []string{}, wantErr: "report output file is required"},
		{name: "one report", args: []string{"report.json"}},
		{name: "extra report", args: []string{"a.json", "b.json"}, wantErr: "accepts at most 1 arg(s), received 2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixCmd := GetFixCmd(&mocks.MockIKubescape{})
			fixCmd.SetArgs(tt.args)
			fixCmd.SetOut(io.Discard)
			fixCmd.SetErr(io.Discard)

			err := fixCmd.Execute()
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.EqualError(t, err, tt.wantErr)
		})
	}
}

func TestValidateControlSelection(t *testing.T) {
	tests := []struct {
		name    string
		fixInfo metav1.FixInfo
		wantErr string
	}{
		{name: "no filters", fixInfo: metav1.FixInfo{}},
		{name: "populated filters", fixInfo: metav1.FixInfo{IncludeControls: []string{"C-0016"}, SkipControls: []string{"C-0017"}}},
		{name: "empty include entry", fixInfo: metav1.FixInfo{IncludeControls: []string{"C-0016", " "}}, wantErr: "--include-controls contains an empty control identifier"},
		{name: "empty skip entry", fixInfo: metav1.FixInfo{SkipControls: []string{""}}, wantErr: "--skip-controls contains an empty control identifier"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateControlSelection(&tt.fixInfo)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.EqualError(t, err, tt.wantErr)
		})
	}
}
