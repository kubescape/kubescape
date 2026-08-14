package policyhandler

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegistry_DifferentClustersGetIsolatedHandlers is the same isolation
// guarantee TestNewPolicyHandler_DifferentClusterNameGetsFreshInstance checks
// through NewPolicyHandler, exercised directly against the registry with
// every cache field checked, not just the top-level pointer.
func TestRegistry_DifferentClustersGetIsolatedHandlers(t *testing.T) {
	reg := &policyHandlerRegistry{entries: make(map[string]*policyHandlerEntry)}
	defer reg.closeAll()

	hA := reg.getHandler("prod-cluster-us")
	hB := reg.getHandler("dev-cluster-eu")

	assert.NotSame(t, hA, hB)
	assert.NotSame(t, hA.cachedExceptions, hB.cachedExceptions)
	assert.NotSame(t, hA.cachedControlInputs, hB.cachedControlInputs)
	assert.NotSame(t, hA.cachedPolicies, hB.cachedPolicies)
}

// TestRegistry_GetHandlerNeverLeavesMoreThanOneEntryPerActiveCluster is the
// regression test for the leak in PR #2899: getHandler creates a registry
// entry per clusterName and nothing ever removed it, so a long-running
// process (the httphandler service) accumulated one permanent entry for
// every distinct cluster name it ever scanned. Here we simulate that by
// calling getHandler for many distinct clusters and confirming the registry
// does not grow without bound once entries go idle.
func TestRegistry_GetHandlerNeverLeavesMoreThanOneEntryPerActiveCluster(t *testing.T) {
	reg := &policyHandlerRegistry{entries: make(map[string]*policyHandlerEntry)}
	defer reg.closeAll()

	past := time.Now().Add(-2 * defaultIdleEvictionWindow)
	for i := 0; i < 50; i++ {
		h := reg.getHandler(fmt.Sprintf("cluster-%d", i))
		require.NotNil(t, h)
		// Backdate this entry's lastAccess so the next getHandler call sees
		// it as idle, the same as if 2*defaultIdleEvictionWindow had really
		// passed since it was touched.
		reg.mu.Lock()
		reg.entries[fmt.Sprintf("cluster-%d", i)].lastAccess = past
		reg.mu.Unlock()
	}

	// One more access triggers a sweep. Every backdated entry should be
	// evicted; only the freshly created one should remain.
	reg.getHandler("cluster-fresh")

	assert.Equal(t, 1, reg.size(),
		"idle entries from earlier clusters must be swept, not retained forever")
}

// TestRegistry_ActiveAcquireSurvivesSweep confirms the idle sweep never
// evicts an entry something is still actively holding via acquireHandler,
// even if it's been idle a long time by clock alone.
func TestRegistry_ActiveAcquireSurvivesSweep(t *testing.T) {
	reg := &policyHandlerRegistry{entries: make(map[string]*policyHandlerEntry)}
	defer reg.closeAll()

	h, release := reg.acquireHandler("long-running-cluster")
	require.NotNil(t, h)

	reg.mu.Lock()
	reg.entries["long-running-cluster"].lastAccess = time.Now().Add(-2 * defaultIdleEvictionWindow)
	reg.mu.Unlock()

	// Trigger a sweep via an unrelated access.
	reg.getHandler("other-cluster")

	assert.Equal(t, 2, reg.size(),
		"an entry with an active acquireHandler caller must survive the sweep regardless of idle time")

	release()
}

// TestRegistry_SameClusterSharesHandler checks the TTL-cache-reuse guarantee:
// concurrent requests for the same cluster share one warm handler.
func TestRegistry_SameClusterSharesHandler(t *testing.T) {
	reg := &policyHandlerRegistry{entries: make(map[string]*policyHandlerEntry)}
	defer reg.closeAll()

	h1 := reg.getHandler("shared-cluster")
	h2 := reg.getHandler("shared-cluster")

	assert.Same(t, h1, h2)
	assert.Equal(t, 1, reg.size())
}

// TestRegistry_ConcurrentMultiCluster is the TOCTOU stress test: many
// goroutines simultaneously acquire and release handlers across a handful of
// clusters. Run with -race; it must produce zero warnings.
func TestRegistry_ConcurrentMultiCluster(t *testing.T) {
	const goroutines = 200
	const clusters = 5

	reg := &policyHandlerRegistry{entries: make(map[string]*policyHandlerEntry)}
	defer reg.closeAll()

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			name := fmt.Sprintf("cluster-%d", idx%clusters)
			if idx%2 == 0 {
				h := reg.getHandler(name)
				require.NotNil(t, h)
				require.Equal(t, name, h.clusterName)
				return
			}
			h, release := reg.acquireHandler(name)
			require.NotNil(t, h)
			require.Equal(t, name, h.clusterName)
			release()
		}(i)
	}
	wg.Wait()
}

// TestCollectPolicies_ConcurrentSameClusterDoesNotRaceOnGetters guards the
// scanMu addition: concurrent CollectPolicies calls on one shared handler
// must not race on the request-scoped getters field. Run with -race.
func TestCollectPolicies_ConcurrentSameClusterDoesNotRaceOnGetters(t *testing.T) {
	const goroutines = 20

	handler := NewRequestScopedPolicyHandler("race-cluster")
	defer handler.Close()

	getters := &cautils.Getters{
		PolicyGetter:         &PolicyGetterMock{},
		ExceptionsGetter:     &ExceptionsGetterMock{},
		ControlsInputsGetter: &ControlsInputsGetterMock{},
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			ident := []cautils.PolicyIdentifier{{Identifier: FrameworkName, Kind: "Framework"}}
			_, _ = handler.CollectPolicies(context.Background(), ident, &cautils.ScanInfo{}, getters)
		}()
	}
	wg.Wait()
}
