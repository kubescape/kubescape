package fix

import (
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

	// Verify the command name and short description
	assert.Equal(t, "fix <report output file>", fixCmd.Use)
	assert.Equal(t, "Propose a fix for the misconfiguration found when scanning Kubernetes manifest files", fixCmd.Short)
	assert.Equal(t, "", fixCmd.Long)
	assert.Equal(t, fixCmdExamples, fixCmd.Example)

	err := fixCmd.RunE(&cobra.Command{}, []string{})
	expectedErrorMessage := "report output file is required"
	assert.Equal(t, expectedErrorMessage, err.Error())

	err = fixCmd.RunE(&cobra.Command{}, []string{"random-file.json"})
	assert.Nil(t, err)
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
