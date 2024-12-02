package v1

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	objectsenvelopes "github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/stretchr/testify/assert"
)

func TestToScanInfo(t *testing.T) {
	{
		req := &utilsmetav1.PostScanRequest{
			TargetType:         apisv1.KindFramework,
			Account:            "abc",
			Logger:             "info",
			Format:             "pdf",
			FailThreshold:      50,
			ExcludedNamespaces: []string{"kube-system", "kube-public"},
			TargetNames:        []string{"nsa", "mitre"},
		}
		s := ToScanInfo(req)
		assert.Equal(t, "abc", s.AccountID)
		assert.Equal(t, "v2", s.FormatVersion)
		assert.Equal(t, "pdf", s.Format)
		assert.Equal(t, 2, len(s.PolicyIdentifier))
		assert.Equal(t, "kube-system,kube-public", s.ExcludedNamespaces)

		assert.False(t, s.HostSensorEnabled.GetBool())
		assert.False(t, s.Local)
		assert.False(t, s.Submit)
		assert.False(t, s.ScanAll)
		assert.True(t, s.FrameworkScan)
		assert.Equal(t, "nsa", s.PolicyIdentifier[0].Identifier)
		assert.Equal(t, apisv1.KindFramework, s.PolicyIdentifier[0].Kind)
		assert.Equal(t, "mitre", s.PolicyIdentifier[1].Identifier)
		assert.Equal(t, apisv1.KindFramework, s.PolicyIdentifier[1].Kind)
	}
	{
		req := &utilsmetav1.PostScanRequest{
			TargetType:        apisv1.KindControl,
			TargetNames:       []string{"c-0001"},
			IncludeNamespaces: []string{"kube-system", "kube-public"},
		}
		s := ToScanInfo(req)
		assert.False(t, s.ScanAll)
		assert.False(t, s.FrameworkScan)
		assert.Equal(t, "kube-system,kube-public", s.IncludeNamespaces)
		assert.Equal(t, "", s.ExcludedNamespaces)
		assert.Equal(t, 1, len(s.PolicyIdentifier))
		assert.Equal(t, "c-0001", s.PolicyIdentifier[0].Identifier)
		assert.Equal(t, apisv1.KindControl, s.PolicyIdentifier[0].Kind)
	}
	{
		req := &utilsmetav1.PostScanRequest{}
		s := ToScanInfo(req)
		assert.True(t, s.ScanAll)
		assert.True(t, s.FrameworkScan)
		assert.Nil(t, s.ScanObject)
	}
	{
		req := &utilsmetav1.PostScanRequest{
			ScanObject: &objectsenvelopes.ScanObject{
				ApiVersion: "apps/v1",
				Kind:       "Deployment",
				Metadata: objectsenvelopes.ScanObjectMetadata{
					Name:      "nginx",
					Namespace: "ns1",
				},
			},
		}
		s := ToScanInfo(req)
		assert.NotNil(t, s.ScanObject)
		assert.Equal(t, "apps/v1", s.ScanObject.GetApiVersion())
		assert.Equal(t, "Deployment", s.ScanObject.GetKind())
		assert.Equal(t, "nginx", s.ScanObject.GetName())
		assert.Equal(t, "ns1", s.ScanObject.GetNamespace())
	}
}

func TestSetTargetInScanInfo(t *testing.T) {
	{
		req := &utilsmetav1.PostScanRequest{
			TargetType:  apisv1.KindFramework,
			TargetNames: []string{""},
		}
		scanInfo := &cautils.ScanInfo{}
		setTargetInScanInfo(req, scanInfo)
		assert.True(t, scanInfo.FrameworkScan)
		assert.True(t, scanInfo.ScanAll)
		assert.Equal(t, 0, len(scanInfo.PolicyIdentifier))
	}
	{
		req := &utilsmetav1.PostScanRequest{
			TargetType:  apisv1.KindFramework,
			TargetNames: []string{"", "security"},
		}
		scanInfo := &cautils.ScanInfo{}
		setTargetInScanInfo(req, scanInfo)
		assert.True(t, scanInfo.FrameworkScan)
		assert.True(t, scanInfo.ScanAll)
		assert.Equal(t, 1, len(scanInfo.PolicyIdentifier))
	}
	{
		req := &utilsmetav1.PostScanRequest{
			TargetType:  apisv1.KindFramework,
			TargetNames: []string{},
		}
		scanInfo := &cautils.ScanInfo{}
		setTargetInScanInfo(req, scanInfo)
		assert.True(t, scanInfo.FrameworkScan)
		assert.True(t, scanInfo.ScanAll)
		assert.Equal(t, 0, len(scanInfo.PolicyIdentifier))
	}
	{
		req := &utilsmetav1.PostScanRequest{
			TargetType:  apisv1.KindFramework,
			TargetNames: []string{"nsa", "mitre"},
		}
		scanInfo := &cautils.ScanInfo{}
		setTargetInScanInfo(req, scanInfo)
		assert.True(t, scanInfo.FrameworkScan)
		assert.False(t, scanInfo.ScanAll)
		assert.Equal(t, 2, len(scanInfo.PolicyIdentifier))
	}
	{
		req := &utilsmetav1.PostScanRequest{
			TargetType:  apisv1.KindFramework,
			TargetNames: []string{"all"},
		}
		scanInfo := &cautils.ScanInfo{}
		setTargetInScanInfo(req, scanInfo)
		assert.True(t, scanInfo.FrameworkScan)
		assert.True(t, scanInfo.ScanAll)
		assert.Equal(t, 0, len(scanInfo.PolicyIdentifier))
	}
	{
		req := &utilsmetav1.PostScanRequest{}
		scanInfo := &cautils.ScanInfo{}
		setTargetInScanInfo(req, scanInfo)
		assert.True(t, scanInfo.FrameworkScan)
		assert.True(t, scanInfo.ScanAll)
		assert.Equal(t, 0, len(scanInfo.PolicyIdentifier))
	}
	{
		req := &utilsmetav1.PostScanRequest{
			TargetType:  apisv1.KindControl,
			TargetNames: []string{"c-0001"},
		}
		scanInfo := &cautils.ScanInfo{}
		setTargetInScanInfo(req, scanInfo)
		assert.False(t, scanInfo.FrameworkScan)
		assert.False(t, scanInfo.ScanAll)
		assert.Equal(t, 1, len(scanInfo.PolicyIdentifier))
	}
}
