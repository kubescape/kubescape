package v1

import (
	"encoding/json"
	"os"
	"sync"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v3/core/cautils"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	objectsenvelopes "github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestToScanInfoExceptionsCleanup(t *testing.T) {
	req := &utilsmetav1.PostScanRequest{
		Exceptions: []armotypes.PostureExceptionPolicy{
			{PortalBase: armotypes.PortalBase{Name: "ex"}},
		},
	}
	s := ToScanInfo(req)
	require.NotEmpty(t, s.UseExceptions)
	_, err := os.Stat(s.UseExceptions)
	require.NoError(t, err)

	s.Cleanup()
	_, err = os.Stat(s.UseExceptions)
	assert.True(t, os.IsNotExist(err), "expected exceptions temp file to be removed by Cleanup, got err=%v", err)
}

func TestSaveExceptions(t *testing.T) {
	{
		exceptions := []armotypes.PostureExceptionPolicy{
			{PolicyType: "postureExceptionPolicy", PortalBase: armotypes.PortalBase{Name: "ex-A"}},
		}
		path, err := saveExceptions(exceptions)
		require.NoError(t, err)
		defer os.Remove(path)

		buf, err := os.ReadFile(path)
		require.NoError(t, err)
		var got []armotypes.PostureExceptionPolicy
		require.NoError(t, json.Unmarshal(buf, &got))
		assert.Equal(t, exceptions, got)
	}
	{
		exceptions := []armotypes.PostureExceptionPolicy{{PortalBase: armotypes.PortalBase{Name: "ex"}}}
		p1, err := saveExceptions(exceptions)
		require.NoError(t, err)
		defer os.Remove(p1)

		p2, err := saveExceptions(exceptions)
		require.NoError(t, err)
		defer os.Remove(p2)

		assert.NotEqual(t, p1, p2)
	}
}

func TestSaveExceptionsConcurrent(t *testing.T) {
	const goroutines = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	errs := make(chan error, goroutines*3)
	paths := make(map[string]struct{}, goroutines)
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			exceptions := []armotypes.PostureExceptionPolicy{
				{PortalBase: armotypes.PortalBase{Name: "ex-" + string(rune('A'+id))}},
			}
			path, err := saveExceptions(exceptions)
			if err != nil {
				errs <- err
				return
			}
			defer os.Remove(path)

			buf, err := os.ReadFile(path)
			if err != nil {
				errs <- err
				return
			}
			var got []armotypes.PostureExceptionPolicy
			if err := json.Unmarshal(buf, &got); err != nil {
				errs <- err
				return
			}
			assert.Equal(t, exceptions, got)

			mu.Lock()
			paths[path] = struct{}{}
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, goroutines, len(paths))
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
