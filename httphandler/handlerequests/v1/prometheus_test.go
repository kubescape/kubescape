package v1

import (
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	"github.com/stretchr/testify/assert"
)

func TestGetPrometheusDefaultScanCommand(t *testing.T) {
	scanID := "1234"
	outputFile := filepath.Join(OutputDir, scanID)
	scanInfo := getPrometheusDefaultScanCommand(scanID, outputFile)

	assert.Equal(t, scanID, scanInfo.ScanID)
	assert.Equal(t, outputFile, scanInfo.Output)
	assert.Equal(t, "prometheus", scanInfo.Format)
	// assert.False(t, *scanInfo.HostSensorEnabled.Get())
	assert.Equal(t, getter.DefaultLocalStore, scanInfo.UseArtifactsFrom)
}
