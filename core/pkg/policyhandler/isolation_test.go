package policyhandler

import (
	"context"
	"sync"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/stretchr/testify/assert"
)

type mockExceptionsGetter struct {
	exceptions []armotypes.PostureExceptionPolicy
}

func (m *mockExceptionsGetter) GetExceptions(clusterName string) ([]armotypes.PostureExceptionPolicy, error) {
	return m.exceptions, nil
}

func TestPolicyHandler_Isolation(t *testing.T) {
	// Set TTL to a high value so we can test caching
	t.Setenv("POLICIES_CACHE_TTL", "1h")

	// Instance 1: Cluster A
	ph1 := NewPolicyHandler("cluster-a")
	g1 := &cautils.Getters{
		ExceptionsGetter: &mockExceptionsGetter{
			exceptions: []armotypes.PostureExceptionPolicy{{PortalBase: armotypes.PortalBase{GUID: "exception-a"}}},
		},
	}

	// Instance 2: Cluster B
	ph2 := NewPolicyHandler("cluster-b")
	g2 := &cautils.Getters{
		ExceptionsGetter: &mockExceptionsGetter{
			exceptions: []armotypes.PostureExceptionPolicy{{PortalBase: armotypes.PortalBase{GUID: "exception-b"}}},
		},
	}

	// First call to ph1 caches cluster-a exceptions
	exc1, err := ph1.getExceptions(g1)
	assert.NoError(t, err)
	assert.Equal(t, "exception-a", exc1[0].GUID)

	// First call to ph2 should cache cluster-b exceptions, NOT cluster-a
	exc2, err := ph2.getExceptions(g2)
	assert.NoError(t, err)
	assert.Equal(t, "exception-b", exc2[0].GUID)

	// Subsequent call to ph1 should still return cluster-a (from cache)
	exc1Cached, _ := ph1.getExceptions(g1)
	assert.Equal(t, "exception-a", exc1Cached[0].GUID)

	// Verify they are different instances
	assert.NotSame(t, ph1, ph2)
}

func TestPolicyHandler_ConcurrencySafety(t *testing.T) {
	ph := NewPolicyHandler("concurrent-cluster")
	
	g := &cautils.Getters{
		ExceptionsGetter: &mockExceptionsGetter{
			exceptions: []armotypes.PostureExceptionPolicy{{PortalBase: armotypes.PortalBase{GUID: "exception-concurrent"}}},
		},
	}

	var wg sync.WaitGroup
	// Simulate multiple goroutines calling CollectPolicies on the SAME handler instance
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanInfo := &cautils.ScanInfo{
				Getters: *g,
			}
			_, _ = ph.CollectPolicies(context.Background(), nil, scanInfo)
		}()
	}
	wg.Wait()
}
