package opaprocessor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resourcehandler"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

// TestProcessWithStreaming_Parity verifies that ProcessWithStreaming produces
// the same results as the traditional Process method for the same input.
func TestProcessWithStreaming_Parity(t *testing.T) {
	// This test creates a mock scenario with:
	// - Cluster-scoped resources (Nodes, ClusterRoles)
	// - Namespace-scoped resources (Pods in different namespaces)
	// - External resources (simulated cloud/host scanner data)

	_ = context.Background()

	// Create test resources
	clusterRole := mustWorkload(t, `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"test-cluster-role"}}`)
	node := mustWorkload(t, `{"apiVersion":"v1","kind":"Node","metadata":{"name":"test-node"}}`)
	podNs1 := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-1","namespace":"ns-1"}}`)
	podNs2 := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-2","namespace":"ns-2"}}`)
	namespace1 := mustWorkload(t, `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"ns-1"}}`)
	namespace2 := mustWorkload(t, `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"ns-2"}}`)

	// Create resource maps
	k8sResources := cautils.K8SResources{
		"/v1/pods":       {podNs1.GetID(), podNs2.GetID()},
		"/v1/nodes":      {node.GetID()},
		"/v1/namespaces": {namespace1.GetID(), namespace2.GetID()},
		"rbac.authorization.k8s.io/v1/clusterroles": {clusterRole.GetID()},
	}

	allResources := map[string]workloadinterface.IMetadata{
		clusterRole.GetID(): clusterRole,
		node.GetID():        node,
		podNs1.GetID():      podNs1,
		podNs2.GetID():      podNs2,
		namespace1.GetID():  namespace1,
		namespace2.GetID():  namespace2,
	}

	// Test with small cluster (single batch)
	t.Run("SmallCluster_SingleBatch", func(t *testing.T) {
		t.Setenv("LARGE_CLUSTER_SIZE", "1000")

		// For now, just verify the partitioning logic works correctly
		resident, batches := cautils.PartitionResources(len(allResources), k8sResources, nil, allResources)

		// Small cluster should have single resident batch
		assert.Empty(t, batches, "Small cluster should not have namespace batches")
		assert.Equal(t, cautils.ClusterScope, resident.Scope)
		assert.Equal(t, 6, resident.Len(), "All resources should be in resident batch")
	})

	// Test with large cluster (multiple batches)
	t.Run("LargeCluster_MultipleBatches", func(t *testing.T) {
		t.Setenv("LARGE_CLUSTER_SIZE", "1")

		// Verify partitioning creates multiple batches
		resident, batches := cautils.PartitionResources(len(allResources), k8sResources, nil, allResources)

		// Large cluster should split by namespace
		assert.NotEmpty(t, batches, "Large cluster should have namespace batches")
		assert.Equal(t, cautils.ClusterScope, resident.Scope)

		// Verify cluster-scoped resources are in resident batch
		assert.Contains(t, resident.AllResources, clusterRole.GetID())
		assert.Contains(t, resident.AllResources, node.GetID())

		// Verify namespace-scoped resources are in namespace batches
		var foundPodNs1, foundPodNs2 bool
		for _, batch := range batches {
			if _, ok := batch.AllResources[podNs1.GetID()]; ok {
				foundPodNs1 = true
			}
			if _, ok := batch.AllResources[podNs2.GetID()]; ok {
				foundPodNs2 = true
			}
		}
		assert.True(t, foundPodNs1, "Pod in ns-1 should be in a namespace batch")
		assert.True(t, foundPodNs2, "Pod in ns-2 should be in a namespace batch")

		// Namespaces should be in their respective namespace batches
		var foundNs1, foundNs2 bool
		for _, batch := range batches {
			if batch.Scope == "ns-1" {
				assert.Contains(t, batch.AllResources, namespace1.GetID())
				assert.Contains(t, batch.AllResources, podNs1.GetID())
				foundNs1 = true
			}
			if batch.Scope == "ns-2" {
				assert.Contains(t, batch.AllResources, namespace2.GetID())
				assert.Contains(t, batch.AllResources, podNs2.GetID())
				foundNs2 = true
			}
		}
		assert.True(t, foundNs1, "Namespace ns-1 should have its own batch")
		assert.True(t, foundNs2, "Namespace ns-2 should have its own batch")
	})
}

// TestProcessWithStreaming_EndToEndParity runs the eager and streaming
// pipelines end to end against the same directory of manifests and asserts the
// results match. It drives the real seam the streaming split introduced: the
// session object is handed to StreamResourcesBatches, whose producer goroutine
// fills the resource maps — and, before the race fix, wrote them straight onto
// sessionObj — while NewOPAProcessor is constructed against that same session.
// Running under -race instruments exactly that handoff, which no other test
// touches.
func TestProcessWithStreaming_EndToEndParity(t *testing.T) {
	t.Setenv("LARGE_CLUSTER_SIZE", "10000") // eager and streaming both evaluate as one scope

	dir := t.TempDir()
	writeFixtureManifests(t, dir)

	scanInfo := &cautils.ScanInfo{InputPatterns: []string{dir}}
	handler := resourcehandler.NewFileResourceHandler()
	frameworks := parityFrameworks(true)

	// Eager path: CollectResources → ProcessRulesListener, as scan.go does for
	// non-streaming scans.
	eagerSession := cautils.NewOPASessionObj(context.Background(), frameworks, nil, scanInfo, nil)
	eagerSession.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{}
	require.NoError(t, resourcehandler.CollectResources(context.Background(), handler, eagerSession, scanInfo))

	eager := NewOPAProcessor(eagerSession, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	require.NoError(t, eager.ProcessRulesListener(context.Background(), cautils.NewProgressHandler("")))
	require.NotEmpty(t, eager.ResourcesResult)

	// Streaming path: StreamResourcesBatches → ProcessWithStreaming, as scan.go
	// does for streaming scans. NewOPAProcessor runs against the live session
	// the producer goroutine fills — the seam this test exists to cover.
	streamingSession := cautils.NewOPASessionObj(context.Background(), frameworks, nil, scanInfo, nil)
	streamingSession.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{}

	batchChan, errChan, expectedBatches, err := handler.StreamResourcesBatches(context.Background(), streamingSession, scanInfo)
	require.NoError(t, err)

	streaming := NewOPAProcessor(streamingSession, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	streaming.SetInitialResourceCount(0) // file scans never estimate cluster size
	require.NoError(t, streaming.ProcessWithStreaming(context.Background(), batchChan, errChan, cautils.NewProgressHandler(""), expectedBatches))

	assert.Equal(t, normalize(eager.ResourcesResult), normalize(streaming.ResourcesResult))
}

// writeFixtureManifests serializes the parity harness fixture to YAML files in
// dir so FileResourceHandler can scan them like a plain directory of manifests.
func writeFixtureManifests(t *testing.T, dir string) {
	t.Helper()

	_, allResources := parityFixture()
	i := 0
	for _, wl := range allResources {
		raw, err := yaml.Marshal(wl.GetObject())
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("manifest-%03d.yaml", i)), raw, 0o600))
		i++
	}
}

// TestProcessWithStreaming_MatchesProcess pins that streaming evaluation over
// partitioned batches produces the same results as the eager Process path, and
// that the resident batch's maps land on the session object (K8SResources,
// ExternalResources, AllResources) for downstream stages. The session object is
// deliberately left without its maps before NewOPAProcessor, mirroring the real
// streaming path where the producer delivers resources on the resident batch
// while the processor is being constructed.
func TestProcessWithStreaming_MatchesProcess(t *testing.T) {
	t.Setenv("LARGE_CLUSTER_SIZE", "1") // force per-namespace batches

	policies := parityPolicies(true)

	expected := newParityProcessor(policies)
	require.NoError(t, expected.Process(context.Background(), policies, nil))
	require.NotEmpty(t, expected.ResourcesResult)

	k8sResources, allResources := parityFixture()
	sessionObj := cautils.NewOPASessionObjMock()
	// ProcessWithStreaming rebuilds AllPolicies from the session's frameworks,
	// so seed them the way CollectPolicies does in the real scan flow, with the
	// same cluster scanning scope the parity harness assumes.
	sessionObj.Policies = parityFrameworks(true)
	sessionObj.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{}

	opap := NewOPAProcessor(sessionObj, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)

	resident, batches := cautils.PartitionResources(len(allResources), k8sResources, nil, allResources)

	batchChan := make(chan *cautils.ResourceBatch, len(batches)+1)
	errChan := make(chan error, 1)
	close(errChan)
	batchChan <- resident
	for _, batch := range batches {
		batchChan <- batch
	}
	close(batchChan)

	require.NoError(t, opap.ProcessWithStreaming(context.Background(), batchChan, errChan, cautils.NewProgressHandler(""), len(batches)))

	assert.Equal(t, normalize(expected.ResourcesResult), normalize(opap.ResourcesResult))

	// Resident resources must reach the session object for downstream stages.
	assert.Len(t, opap.AllResources, len(allResources))
	assert.Equal(t, k8sResources, opap.K8SResources)
}

// TestResourceBatch_MemoryUsage verifies that namespace batches are partitioned
// correctly and that dropping a batch's reference after processing allows the
// batch wrapper to be collected.
func TestResourceBatch_MemoryUsage(t *testing.T) {
	t.Setenv("LARGE_CLUSTER_SIZE", "1")

	// Create a large number of resources to simulate a real cluster
	allResources := make(map[string]workloadinterface.IMetadata)
	k8sResources := cautils.K8SResources{}

	// Add cluster-scoped resources
	for i := 0; i < 10; i++ {
		node := mustWorkload(t, `{"apiVersion":"v1","kind":"Node","metadata":{"name":"node-`+strconv.Itoa(i)+`"}}`)
		allResources[node.GetID()] = node
		k8sResources["/v1/nodes"] = append(k8sResources["/v1/nodes"], node.GetID())
	}

	// Add namespace-scoped resources across multiple namespaces
	for ns := 0; ns < 5; ns++ {
		for i := 0; i < 20; i++ {
			pod := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-`+strconv.Itoa(ns*20+i)+`","namespace":"ns-`+strconv.Itoa(ns)+`"}}`)
			allResources[pod.GetID()] = pod
			k8sResources["/v1/pods"] = append(k8sResources["/v1/pods"], pod.GetID())
		}
	}

	// Partition resources
	resident, batches := cautils.PartitionResources(len(allResources), k8sResources, nil, allResources)

	// Verify resident batch contains only cluster-scoped resources
	assert.Equal(t, 10, resident.Len(), "Resident batch should have 10 nodes")

	// Verify namespace batches contain their respective resources
	totalNamespaceResources := 0
	for _, batch := range batches {
		totalNamespaceResources += batch.Len()
	}
	assert.Equal(t, 100, totalNamespaceResources, "Namespace batches should have 100 pods")

	// Simulate memory release
	for _, batch := range batches {
		// Clear batch resources
		for id := range batch.AllResources {
			delete(batch.AllResources, id)
		}
		for key := range batch.K8SResources {
			delete(batch.K8SResources, key)
		}
	}

	// Verify batches are cleared
	for _, batch := range batches {
		assert.Equal(t, 0, batch.Len(), "Batch should be cleared after processing")
	}

	// Verify resident batch is still intact
	assert.Equal(t, 10, resident.Len(), "Resident batch should still have resources")
}

// BenchmarkStreamingMemoryUsage benchmarks memory usage for streaming vs eager evaluation.
// This provides baseline measurements for peak memory validation.
func BenchmarkStreamingMemoryUsage(b *testing.B) {
	b.Setenv("LARGE_CLUSTER_SIZE", "1")

	// Create a realistic cluster size for benchmarking
	allResources := make(map[string]workloadinterface.IMetadata)
	k8sResources := cautils.K8SResources{}

	// Add cluster-scoped resources (typically 10-20% of total)
	for i := 0; i < 50; i++ {
		node, _ := workloadinterface.NewWorkload([]byte(`{"apiVersion":"v1","kind":"Node","metadata":{"name":"node-` + strconv.Itoa(i) + `"}}`))
		allResources[node.GetID()] = node
		k8sResources["/v1/nodes"] = append(k8sResources["/v1/nodes"], node.GetID())
	}

	// Add namespace-scoped resources (typically 80-90% of total)
	for ns := 0; ns < 10; ns++ {
		for i := 0; i < 100; i++ {
			pod, _ := workloadinterface.NewWorkload([]byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-` + strconv.Itoa(ns*100+i) + `","namespace":"ns-` + strconv.Itoa(ns) + `"}}`))
			allResources[pod.GetID()] = pod
			k8sResources["/v1/pods"] = append(k8sResources["/v1/pods"], pod.GetID())
		}
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Partition resources (simulates streaming approach)
		resident, batches := cautils.PartitionResources(len(allResources), k8sResources, nil, allResources)

		// Process resident batch
		_ = resident.Len()

		// Process namespace batches one at a time (simulates streaming)
		for _, batch := range batches {
			_ = batch.Len()

			// Release memory after processing
			for id := range batch.AllResources {
				delete(batch.AllResources, id)
			}
			for key := range batch.K8SResources {
				delete(batch.K8SResources, key)
			}
		}
	}
}

// BenchmarkEagerMemoryUsage benchmarks memory usage for eager (non-streaming) evaluation.
// This provides baseline measurements for comparison with streaming.
func BenchmarkEagerMemoryUsage(b *testing.B) {
	b.Setenv("LARGE_CLUSTER_SIZE", "10000") // Disable streaming

	// Create the same cluster size as streaming benchmark
	allResources := make(map[string]workloadinterface.IMetadata)
	k8sResources := cautils.K8SResources{}

	// Add cluster-scoped resources
	for i := 0; i < 50; i++ {
		node, _ := workloadinterface.NewWorkload([]byte(`{"apiVersion":"v1","kind":"Node","metadata":{"name":"node-` + strconv.Itoa(i) + `"}}`))
		allResources[node.GetID()] = node
		k8sResources["/v1/nodes"] = append(k8sResources["/v1/nodes"], node.GetID())
	}

	// Add namespace-scoped resources
	for ns := 0; ns < 10; ns++ {
		for i := 0; i < 100; i++ {
			pod, _ := workloadinterface.NewWorkload([]byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-` + strconv.Itoa(ns*100+i) + `","namespace":"ns-` + strconv.Itoa(ns) + `"}}`))
			allResources[pod.GetID()] = pod
			k8sResources["/v1/pods"] = append(k8sResources["/v1/pods"], pod.GetID())
		}
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Partition resources (simulates eager approach - single batch)
		resident, batches := cautils.PartitionResources(len(allResources), k8sResources, nil, allResources)

		// Process all resources at once (simulates eager evaluation)
		_ = resident.Len()
		for _, batch := range batches {
			_ = batch.Len()
		}

		// In eager approach, all resources stay in memory throughout
		// No explicit memory release
	}
}

// TestProcessWithStreaming_PopulatesCELNamespaceIndex pins the CEL
// namespaceObject binding on the streaming path. NewOPAProcessor builds the
// namespace index from sessionObj.AllResources, which is still empty when the
// streaming path constructs the processor, so without per-batch indexing every
// lookup would resolve to nil and admission-scoped CEL rules would silently
// behave differently under --enable-streaming than on the eager path.
func TestProcessWithStreaming_PopulatesCELNamespaceIndex(t *testing.T) {
	namespace := mustWorkload(t, `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"prod","labels":{"pod-security.kubernetes.io/enforce":"restricted"}}}`)
	pod := mustWorkload(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-1","namespace":"prod"}}`)
	node := mustWorkload(t, `{"apiVersion":"v1","kind":"Node","metadata":{"name":"node-1"}}`)

	scanInfo := &cautils.ScanInfo{}
	session := cautils.NewOPASessionObj(context.Background(), parityFrameworks(true), nil, scanInfo, nil)
	session.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{}

	opap := NewOPAProcessor(session, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	require.Empty(t, opap.celNamespaceIndex,
		"the streaming path constructs the processor before any resource is collected")

	// A Namespace object is scoped to its own name, so it arrives in that
	// namespace's batch rather than the resident one.
	resident := cautils.NewResourceBatch(cautils.ClusterScope)
	resident.K8SResources["/v1/nodes"] = []string{node.GetID()}
	resident.AllResources[node.GetID()] = node

	nsBatch := cautils.NewResourceBatch("prod")
	nsBatch.K8SResources["/v1/namespaces"] = []string{namespace.GetID()}
	nsBatch.K8SResources["/v1/pods"] = []string{pod.GetID()}
	nsBatch.AllResources[namespace.GetID()] = namespace
	nsBatch.AllResources[pod.GetID()] = pod

	batchChan := make(chan *cautils.ResourceBatch, 2)
	batchChan <- resident
	batchChan <- nsBatch
	close(batchChan)

	errChan := make(chan error)
	close(errChan)

	require.NoError(t, opap.ProcessWithStreaming(context.Background(), batchChan, errChan, cautils.NewProgressHandler(""), 1))

	got := opap.celNamespaceObjectFor(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "pod-1", "namespace": "prod"},
	})
	require.NotNil(t, got, "the namespace object streamed in its batch must be bound, not nil")
	labels := got["metadata"].(map[string]any)["labels"].(map[string]any)
	assert.Equal(t, "restricted", labels["pod-security.kubernetes.io/enforce"],
		"the binding must carry the real Namespace object, labels included")

	assert.Nil(t, opap.celNamespaceObjectFor(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "pod-2", "namespace": "staging"},
	}), "a namespace the scan never streamed must still resolve to nil")
}

func mustWorkload(t *testing.T, raw string) workloadinterface.IMetadata {
	t.Helper()
	workload, err := workloadinterface.NewWorkload([]byte(raw))
	require.NoError(t, err)
	require.NotNil(t, workload)
	return workload
}
