package v1

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/stretchr/testify/assert"
)

func TestGetPrometheusDefaultScanCommand(t *testing.T) {
	t.Run("default behavior - scan all frameworks", func(t *testing.T) {
		// Ensure environment variable is not set
		os.Unsetenv("KS_METRICS_FRAMEWORKS")
		
		scanID := "1234"
		outputFile := filepath.Join(OutputDir, scanID)
		scanInfo := getPrometheusDefaultScanCommand(scanID, outputFile)

		assert.Equal(t, scanID, scanInfo.ScanID)
		assert.Equal(t, outputFile, scanInfo.Output)
		assert.Equal(t, "prometheus", scanInfo.Format)
		assert.False(t, scanInfo.Submit)
		assert.True(t, scanInfo.Local)
		assert.True(t, scanInfo.FrameworkScan)
		assert.True(t, scanInfo.ScanAll) // Scan all available frameworks by default
		assert.False(t, scanInfo.HostSensorEnabled.GetBool())
		assert.Equal(t, getter.DefaultLocalStore, scanInfo.UseArtifactsFrom)
	})

	t.Run("specific frameworks via environment variable", func(t *testing.T) {
		// Set environment variable to scan specific frameworks
		os.Setenv("KS_METRICS_FRAMEWORKS", "nsa,mitre,cis-v1.10.0")
		defer os.Unsetenv("KS_METRICS_FRAMEWORKS")
		
		scanID := "5678"
		outputFile := filepath.Join(OutputDir, scanID)
		scanInfo := getPrometheusDefaultScanCommand(scanID, outputFile)

		assert.Equal(t, scanID, scanInfo.ScanID)
		assert.Equal(t, outputFile, scanInfo.Output)
		assert.Equal(t, "prometheus", scanInfo.Format)
		assert.False(t, scanInfo.Submit)
		assert.True(t, scanInfo.Local)
		assert.True(t, scanInfo.FrameworkScan)
		assert.False(t, scanInfo.ScanAll) // Don't scan all when specific frameworks are set
		assert.False(t, scanInfo.HostSensorEnabled.GetBool())
		assert.Equal(t, getter.DefaultLocalStore, scanInfo.UseArtifactsFrom)
		
		// Verify specific frameworks are set
		assert.Len(t, scanInfo.PolicyIdentifier, 3)
		assert.Equal(t, "nsa", scanInfo.PolicyIdentifier[0].Identifier)
		assert.Equal(t, "mitre", scanInfo.PolicyIdentifier[1].Identifier)
		assert.Equal(t, "cis-v1.10.0", scanInfo.PolicyIdentifier[2].Identifier)
	})
}

func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		sep      string
		expected []string
	}{
		{
			name:     "comma-separated with spaces",
			input:    "nsa, mitre, cis-v1.10.0",
			sep:      ",",
			expected: []string{"nsa", "mitre", "cis-v1.10.0"},
		},
		{
			name:     "no spaces",
			input:    "nsa,mitre,cis-v1.10.0",
			sep:      ",",
			expected: []string{"nsa", "mitre", "cis-v1.10.0"},
		},
		{
			name:     "single item",
			input:    "nsa",
			sep:      ",",
			expected: []string{"nsa"},
		},
		{
			name:     "empty string",
			input:    "",
			sep:      ",",
			expected: []string{},
		},
		{
			name:     "whitespace only",
			input:    "  ,  ,  ",
			sep:      ",",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitAndTrim(tt.input, tt.sep)
			assert.Equal(t, tt.expected, result)
		})
	}
}
