package v1

import (
	"testing"

	"github.com/armosec/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
)

func TestDefaultScanInfo(t *testing.T) {
	s := defaultScanInfo()

	assert.Equal(t, "", s.Account)
	assert.Equal(t, "v2", s.FormatVersion)
	assert.Equal(t, "json", s.Format)
	assert.False(t, s.HostSensorEnabled.GetBool())
	assert.False(t, s.Local)
	assert.False(t, s.Submit)
}

func TestGetScanCommand(t *testing.T) {
	req := PostScanRequest{
		TargetType: reporthandling.KindFramework,
	}
	s := getScanCommand(&req, "abc")
	assert.Equal(t, "", s.Account)
	assert.Equal(t, "abc", s.ScanID)
	assert.Equal(t, "v2", s.FormatVersion)
	assert.Equal(t, "json", s.Format)
	assert.False(t, s.HostSensorEnabled.GetBool())
	assert.False(t, s.Local)
	assert.False(t, s.Submit)
}
