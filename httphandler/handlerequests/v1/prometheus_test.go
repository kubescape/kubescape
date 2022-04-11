package v1

import (
	"testing"

	"github.com/armosec/kubescape/v2/core/cautils/getter"
	"github.com/stretchr/testify/assert"
)

func TestGetPrometheusDefaultScanCommand(t *testing.T) {
	scanID := "1234"
	scanInfo := getPrometheusDefaultScanCommand(scanID)

	assert.Equal(t, scanID, scanInfo.ScanID)
	assert.Equal(t, scanID, scanInfo.Output)
	assert.Equal(t, "prometheus", scanInfo.Format)
	// assert.False(t, *scanInfo.HostSensorEnabled.Get())
	assert.Equal(t, getter.DefaultLocalStore, scanInfo.UseArtifactsFrom)
}
