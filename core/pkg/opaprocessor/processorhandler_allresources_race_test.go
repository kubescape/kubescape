package opaprocessor

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/scancache"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/require"
)

// TestCelParamObjectFinderRacesAggregatorWriteback reproduces a crash seen in
// production: a scan evaluating a mix of CEL and Rego rules can panic with
// "fatal error: concurrent map iteration and map write".
//
// processRuleOnScope grows opap.AllResources mid-scan with aggregator-produced
// resources (rule.go, guarded by opap.mu), while a different rule's CEL
// evaluation concurrently calls celParamObjectFinder, which iterates
// opap.AllResources to build its lookup index. celParamObjectFinder does not
// take opap.mu, so the two goroutines access the map unsynchronized.
//
// This test drives exactly that pattern: one goroutine repeatedly calls
// celParamObjectFinder (the unguarded reader) while the main goroutine writes
// to AllResources through the same opap.mu the real write-back path uses. Run
// with `-race` to see it flagged as a data race; a plain run can also trip
// Go's runtime map-corruption check, matching the CI panic.
func TestCelParamObjectFinderRacesAggregatorWriteback(t *testing.T) {
	opap := paramRefProcessor()
	opap.AllResources = map[string]workloadinterface.IMetadata{}

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				opap.celParamObjectFinder()
			}
		}
	}()

	for i := 0; i < 5000; i++ {
		obj := objectsenvelopes.NewObject(map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]any{
				"name":      fmt.Sprintf("cm-%d", i),
				"namespace": "default",
			},
		})
		opap.mu.Lock()
		opap.AllResources[obj.GetID()] = obj
		opap.mu.Unlock()
	}
	close(done)
	wg.Wait()
}

// TestProcessControlRacesAggregatorWriteback covers the second unguarded
// reader of opap.AllResources: when the incremental cache is attached,
// processControl looks up each result's resource by ID (to hash it for the
// cache entry) with no lock, while a sibling worker's processRuleOnScope can
// concurrently grow the same map under opap.mu (processScope fans control
// evaluation out across a worker pool, so both readers and the aggregator
// writer run concurrently in a real scan). Run with `-race`.
func TestProcessControlRacesAggregatorWriteback(t *testing.T) {
	sess, _, _ := nsCacheSession(t)
	store, err := scancache.Load(t.TempDir(), "v1")
	require.NoError(t, err)
	opap := NewOPAProcessor(sess, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	opap.SetIncrementalCache(store)
	ctrl := nsCacheControl()

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				_, _ = opap.processControl(context.Background(), ctrl, evaluationScope{})
			}
		}
	}()

	for i := 0; i < 2000; i++ {
		obj := workloadinterface.NewWorkloadObj(map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]any{
				"name":      fmt.Sprintf("cm-%d", i),
				"namespace": "default",
			},
		})
		opap.mu.Lock()
		opap.AllResources[obj.GetID()] = obj
		opap.mu.Unlock()
	}
	close(done)
	wg.Wait()
}
