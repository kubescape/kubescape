package opaprocessor

import (
	"fmt"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/objectsenvelopes"
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
	go func() {
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
}
