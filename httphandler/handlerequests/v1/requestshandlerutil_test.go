package v1

import (
	"testing"

	"github.com/kubescape/kubescape/v2/httphandler/config"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/stretchr/testify/assert"
)

func TestDefaultScanInfo(t *testing.T) {
	s := defaultScanInfo()

	assert.Equal(t, "", s.AccountID)
	assert.Equal(t, "v2", s.FormatVersion)
	assert.Equal(t, "json", s.Format)
	assert.Equal(t, "", s.AccessToken)
	assert.False(t, s.HostSensorEnabled.GetBool())
	assert.False(t, s.Local)
	assert.False(t, s.Submit)
}

func TestGetScanCommand(t *testing.T) {
	req := utilsmetav1.PostScanRequest{
		TargetType: apisv1.KindFramework,
	}
	s := getScanCommand(&req, "abc")
	assert.Equal(t, "", s.AccountID)
	assert.Equal(t, "abc", s.ScanID)
	assert.Equal(t, "v2", s.FormatVersion)
	assert.Equal(t, "json", s.Format)
	assert.Equal(t, "", s.AccessToken)
	assert.False(t, s.HostSensorEnabled.GetBool())
	assert.False(t, s.Local)
	assert.False(t, s.Submit)
}

func TestGetScanCommandWithAccessToken(t *testing.T) {
	config.SetAccessToken("test-123")

	req := utilsmetav1.PostScanRequest{
		TargetType: apisv1.KindFramework,
	}
	s := getScanCommand(&req, "abc")
	assert.Equal(t, "", s.AccountID)
	assert.Equal(t, "abc", s.ScanID)
	assert.Equal(t, "v2", s.FormatVersion)
	assert.Equal(t, "json", s.Format)
	assert.Equal(t, "test-123", s.AccessToken)
	assert.False(t, s.HostSensorEnabled.GetBool())
	assert.False(t, s.Local)
	assert.False(t, s.Submit)
}
