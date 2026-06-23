package diff

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/stretchr/testify/assert"
)

func TestGetDiffCmd_FormatValidation(t *testing.T) {
	tests := []struct {
		name      string
		format    string
		wantError bool
	}{
		{"default pretty-printer", "pretty-printer", false},
		{"json", "json", false},
		{"unsupported format is rejected", "yaml", true},
		{"scan-only format is rejected", "sarif", true},
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
