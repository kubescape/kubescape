package v1

import (
	"testing"

	"github.com/armosec/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
)

func TestToScanInfo(t *testing.T) {
	{
		req := PostScanRequest{
			TargetType:         reporthandling.KindFramework,
			Account:            "abc",
			Logger:             "info",
			Format:             "pdf",
			FailThreshold:      50,
			ExcludedNamespaces: []string{"kube-system", "kube-public"},
			TargetNames:        []string{"nsa", "mitre"},
		}
		s := req.ToScanInfo()
		assert.Equal(t, "abc", s.Account)
		assert.Equal(t, "v2", s.FormatVersion)
		assert.Equal(t, "pdf", s.Format)
		assert.Equal(t, 2, len(s.PolicyIdentifier))
		assert.Equal(t, "kube-system,kube-public", s.ExcludedNamespaces)

		assert.False(t, s.HostSensorEnabled.GetBool())
		assert.False(t, s.Local)
		assert.False(t, s.Submit)
		assert.False(t, s.ScanAll)
		assert.True(t, s.FrameworkScan)
		assert.Equal(t, "nsa", s.PolicyIdentifier[0].Name)
		assert.Equal(t, reporthandling.KindFramework, s.PolicyIdentifier[0].Kind)
		assert.Equal(t, "mitre", s.PolicyIdentifier[1].Name)
		assert.Equal(t, reporthandling.KindFramework, s.PolicyIdentifier[1].Kind)
	}
	{
		req := PostScanRequest{
			TargetType:        reporthandling.KindControl,
			TargetNames:       []string{"c-0001"},
			IncludeNamespaces: []string{"kube-system", "kube-public"},
		}
		s := req.ToScanInfo()
		assert.False(t, s.ScanAll)
		assert.False(t, s.FrameworkScan)
		assert.Equal(t, "kube-system,kube-public", s.IncludeNamespaces)
		assert.Equal(t, "", s.ExcludedNamespaces)
		assert.Equal(t, 1, len(s.PolicyIdentifier))
		assert.Equal(t, "c-0001", s.PolicyIdentifier[0].Name)
		assert.Equal(t, reporthandling.KindControl, s.PolicyIdentifier[0].Kind)
	}
	{
		req := PostScanRequest{}
		s := req.ToScanInfo()
		assert.True(t, s.ScanAll)
		assert.True(t, s.FrameworkScan)
	}
}
