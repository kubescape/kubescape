package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
)

func TestGetPrometheusDefaultScanCommand(t *testing.T) {
	t.Run("default behavior - scan all frameworks", func(t *testing.T) {
		scanID := "1234"
		outputFile := filepath.Join(OutputDir, scanID)
		scanInfo := getPrometheusDefaultScanCommand(scanID, outputFile, "")

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

	t.Run("specific frameworks via query parameter", func(t *testing.T) {
		scanID := "5678"
		outputFile := filepath.Join(OutputDir, scanID)
		scanInfo := getPrometheusDefaultScanCommand(scanID, outputFile, "nsa,mitre,cis-v1.10.0")

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

// TestMetrics_ScanContextDecoupledFromRequest ensures the metrics scan is not
// aborted when the scrape request context is cancelled (e.g. a Prometheus
// scrape timeout): the scan must keep running to completion.
func TestMetrics_ScanContextDecoupledFromRequest(t *testing.T) {
	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanCtxErr := make(chan error, 1)

	reqCtx, cancel := context.WithCancel(context.Background())
	scanImpl = func(ctx context.Context, _ *cautils.ScanInfo, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
		cancel() // simulate the scrape connection going away mid-scan
		scanCtxErr <- ctx.Err()
		return nil, nil
	}

	h := NewHTTPHandler(false)
	rq := httptest.NewRequest(http.MethodGet, "/v1/metrics", nil).WithContext(reqCtx)
	w := httptest.NewRecorder()
	h.Metrics(w, rq)

	select {
	case err := <-scanCtxErr:
		assert.NoError(t, err, "scan context must not be cancelled when the request context is")
	case <-time.After(5 * time.Second):
		t.Fatal("scan was not invoked")
	}
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
