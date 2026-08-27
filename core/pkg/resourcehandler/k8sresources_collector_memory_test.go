package resourcehandler

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"sync"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
)

// This file is the synthetic-cluster harness for the streaming collector's
// memory behaviour. It exists to answer one question that a wall-clock
// benchmark cannot: how much of a scan's heap is held by the collector before
// the first batch is evaluated, as opposed to by the session that retains
// every resource afterwards for exceptions, printers and image scanning.
//
// The two are measured at different points of the same run:
//
//	collector-peak  live heap when the resident batch is handed over. Every
//	                queryable GVR has been traversed and every namespace
//	                partition is still held by the producer, so this is the
//	                collection-phase high-water mark.
//	downstream      live heap once every batch has been drained and merged the
//	                way OPAProcessor.ProcessWithStreaming merges them into the
//	                session. The producer has dropped its references by then,
//	                so this is what the rest of the scan pays for.
//
// Today the two are close, because the collector holds the whole cluster on
// the Go heap until it starts emitting. Work that bounds the collection phase
// should drive collector-peak down while leaving downstream where it is; this
// harness is what makes that visible rather than asserted.
//
// Run it with:
//
//	go test ./core/pkg/resourcehandler/ -run '^$' -bench BenchmarkStreamingCollectorMemory -benchtime 1x
//
// Set KUBESCAPE_COLLECTOR_HEAP_PROFILE_DIR to also write a heap profile taken
// at the collector peak of each size, readable with `go tool pprof`.
//
// Baseline on an amd64 laptop when this harness was written, to give the shape
// rather than an absolute the numbers should be compared against across
// machines:
//
//	size   collector_peak   downstream   allocated   list_calls
//	5k          65 MB          65 MB       89 MB          11
//	20k        260 MB         259 MB      356 MB          41
//	50k        652 MB         648 MB      893 MB         101
//
// Peak tracks downstream almost exactly and both grow linearly with the
// cluster: the collector is holding the whole cluster when it emits its first
// batch. The list_calls column is the other half of the contract — one
// paginated traversal per GVR, never one per namespace.
const collectorHeapProfileDirEnv = "KUBESCAPE_COLLECTOR_HEAP_PROFILE_DIR"

// syntheticClusterSpec describes a fake cluster to point the collector at.
// Sizes are chosen so namespaced objects dominate, as they do in a real
// cluster, and so every namespace spans several pages.
type syntheticClusterSpec struct {
	name           string
	namespaces     int
	podsPerNS      int
	nodes          int
	serverPageSize int
}

func (spec syntheticClusterSpec) total() int {
	return spec.namespaces*spec.podsPerNS + spec.nodes
}

var syntheticClusters = []syntheticClusterSpec{
	{name: "5k", namespaces: 50, podsPerNS: 99, nodes: 50, serverPageSize: 500},
	{name: "20k", namespaces: 100, podsPerNS: 199, nodes: 100, serverPageSize: 500},
	{name: "50k", namespaces: 200, podsPerNS: 249, nodes: 200, serverPageSize: 500},
}

// podTemplate is close in shape and size to a scheduled pod as the API server
// returns it, so per-object heap cost is representative rather than a
// name-and-namespace stub. It carries no pod-template-hash label and no owner
// references: a pod with either is a controller's replica, which the
// collector's parent filter drops before it ever reaches a batch, so serving
// them would measure a cluster the scan does not retain.
const podTemplate = `{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "PLACEHOLDER_NAME",
    "namespace": "PLACEHOLDER_NAMESPACE",
    "uid": "PLACEHOLDER_UID",
    "resourceVersion": "148213",
    "creationTimestamp": "2024-05-14T09:12:41Z",
    "labels": {"app": "checkout", "tier": "backend", "environment": "production"},
    "annotations": {
      "kubectl.kubernetes.io/restartedAt": "2024-05-14T09:12:40Z",
      "prometheus.io/scrape": "true",
      "prometheus.io/port": "9090",
      "checksum/config": "9f2c1e0d7a4b6c8e2f1a3d5b7c9e0f2a4b6d8e0f1a3c5e7b9d1f3a5c7e9b1d3f"
    }
  },
  "spec": {
    "serviceAccountName": "checkout",
    "restartPolicy": "Always",
    "terminationGracePeriodSeconds": 30,
    "dnsPolicy": "ClusterFirst",
    "nodeName": "node-17",
    "containers": [
      {
        "name": "checkout",
        "image": "registry.example.com/checkout:1.24.3",
        "imagePullPolicy": "IfNotPresent",
        "ports": [{"name": "http", "containerPort": 8080, "protocol": "TCP"}],
        "env": [
          {"name": "LOG_LEVEL", "value": "info"},
          {"name": "DB_HOST", "value": "postgres.data.svc.cluster.local"},
          {"name": "OTEL_EXPORTER_OTLP_ENDPOINT", "value": "http://otel-collector.observability:4317"}
        ],
        "resources": {"requests": {"cpu": "250m", "memory": "256Mi"}, "limits": {"cpu": "1", "memory": "512Mi"}},
        "securityContext": {"runAsNonRoot": true, "runAsUser": 10001, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": {"drop": ["ALL"]}},
        "volumeMounts": [
          {"name": "config", "mountPath": "/etc/checkout", "readOnly": true},
          {"name": "kube-api-access", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount", "readOnly": true}
        ]
      }
    ],
    "volumes": [
      {"name": "config", "configMap": {"name": "checkout-config", "defaultMode": 420}},
      {"name": "kube-api-access", "projected": {"defaultMode": 420, "sources": [{"serviceAccountToken": {"expirationSeconds": 3607, "path": "token"}}]}}
    ]
  },
  "status": {
    "phase": "Running",
    "hostIP": "10.0.3.17",
    "podIP": "10.244.7.42",
    "startTime": "2024-05-14T09:12:41Z",
    "conditions": [
      {"type": "Initialized", "status": "True", "lastTransitionTime": "2024-05-14T09:12:41Z"},
      {"type": "Ready", "status": "True", "lastTransitionTime": "2024-05-14T09:12:52Z"},
      {"type": "ContainersReady", "status": "True", "lastTransitionTime": "2024-05-14T09:12:52Z"},
      {"type": "PodScheduled", "status": "True", "lastTransitionTime": "2024-05-14T09:12:41Z"}
    ],
    "containerStatuses": [
      {"name": "checkout", "ready": true, "restartCount": 0, "started": true, "image": "registry.example.com/checkout:1.24.3", "imageID": "registry.example.com/checkout@sha256:1f2e3d4c5b6a798877665544332211ffeeddccbbaa99887766554433221100ff", "containerID": "containerd://a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00"}
    ]
  }
}`

const nodeTemplate = `{
  "apiVersion": "v1",
  "kind": "Node",
  "metadata": {
    "name": "PLACEHOLDER_NAME",
    "uid": "PLACEHOLDER_UID",
    "resourceVersion": "91233",
    "labels": {"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64", "node.kubernetes.io/instance-type": "m5.2xlarge", "topology.kubernetes.io/zone": "eu-west-1b"}
  },
  "spec": {"podCIDR": "10.244.7.0/24"},
  "status": {
    "capacity": {"cpu": "8", "memory": "32052580Ki", "pods": "110"},
    "allocatable": {"cpu": "7900m", "memory": "31427172Ki", "pods": "110"},
    "nodeInfo": {"kubeletVersion": "v1.29.4", "containerRuntimeVersion": "containerd://1.7.13", "osImage": "Ubuntu 22.04.4 LTS", "kernelVersion": "5.15.0-105-generic"},
    "conditions": [{"type": "Ready", "status": "True", "lastHeartbeatTime": "2024-05-14T09:20:11Z"}]
  }
}`

// syntheticLister answers LIST the way a paginating API server does, decoding
// a fresh object per item. Materializing objects on demand keeps the fixture
// itself out of the measurement: nothing the collector retains is shared with
// a pre-built corpus, so the heap it holds is heap it actually owns.
type syntheticLister struct {
	spec syntheticClusterSpec

	mu    sync.Mutex
	calls map[string]int
}

func newSyntheticLister(spec syntheticClusterSpec) *syntheticLister {
	return &syntheticLister{spec: spec, calls: map[string]int{}}
}

func (s *syntheticLister) listCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for _, count := range s.calls {
		total += count
	}
	return total
}

func (s *syntheticLister) list(resource string, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	s.mu.Lock()
	s.calls[resource]++
	s.mu.Unlock()

	offset := 0
	if opts.Continue != "" {
		parsed, err := strconv.Atoi(opts.Continue)
		if err != nil {
			return nil, fmt.Errorf("malformed continue token %q", opts.Continue)
		}
		offset = parsed
	}

	var (
		template string
		count    int
		kind     string
	)
	switch resource {
	case "pods":
		template, count, kind = podTemplate, s.spec.namespaces*s.spec.podsPerNS, "PodList"
	case "nodes":
		template, count, kind = nodeTemplate, s.spec.nodes, "NodeList"
	default:
		return nil, fmt.Errorf("synthetic cluster serves no %q", resource)
	}

	end := min(offset+s.spec.serverPageSize, count)
	list := &unstructured.UnstructuredList{
		Object: map[string]any{"apiVersion": "v1", "kind": kind},
		Items:  make([]unstructured.Unstructured, 0, max(end-offset, 0)),
	}
	for i := offset; i < end; i++ {
		object := map[string]any{}
		if err := json.Unmarshal([]byte(template), &object); err != nil {
			return nil, err
		}
		metadata := object["metadata"].(map[string]any)
		metadata["uid"] = fmt.Sprintf("%s-%08d", resource, i)
		if resource == "pods" {
			metadata["name"] = fmt.Sprintf("checkout-%06d", i)
			metadata["namespace"] = fmt.Sprintf("team-%04d", i/s.spec.podsPerNS)
		} else {
			metadata["name"] = fmt.Sprintf("node-%04d", i)
		}
		list.Items = append(list.Items, unstructured.Unstructured{Object: object})
	}
	if end < count {
		list.SetContinue(strconv.Itoa(end))
	}
	return list, nil
}

type syntheticDynamicClient struct {
	dynamic.Interface
	lister *syntheticLister
}

func (c *syntheticDynamicClient) Resource(resource schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return &syntheticResourceClient{lister: c.lister, resource: resource.Resource}
}

type syntheticResourceClient struct {
	dynamic.NamespaceableResourceInterface
	lister   *syntheticLister
	resource string
}

func (c *syntheticResourceClient) Namespace(string) dynamic.ResourceInterface { return c }

func (c *syntheticResourceClient) List(_ context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	return c.lister.list(c.resource, opts)
}

func (s *syntheticLister) handler() *K8sResourceHandler {
	return &K8sResourceHandler{k8s: &k8sinterface.KubernetesApi{
		KubernetesClient: fakeclientset.NewClientset(),
		DynamicClient:    &syntheticDynamicClient{lister: s},
	}}
}

func syntheticQueryableResources() QueryableResources {
	namespaced, clusterScoped := true, false
	return QueryableResources{
		"/v1/pods":  {GroupVersionResourceTriplet: "/v1/pods", Namespaced: &namespaced},
		"/v1/nodes": {GroupVersionResourceTriplet: "/v1/nodes", Namespaced: &clusterScoped},
	}
}

// liveHeapBytes returns the bytes of reachable heap. Two collections settle
// finalizers and freshly swept spans, so readings taken at different points of
// a run are comparable to each other.
func liveHeapBytes() uint64 {
	runtime.GC()
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc
}

func heapDelta(from, to uint64) float64 {
	if to < from {
		return 0
	}
	return float64(to-from) / (1 << 20)
}

func writeHeapProfile(b *testing.B, label string) {
	dir := os.Getenv(collectorHeapProfileDirEnv)
	if dir == "" {
		return
	}
	require.NoError(b, os.MkdirAll(dir, 0o700))
	path := filepath.Join(dir, "collector-peak-"+label+".pprof")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	require.NoError(b, err)
	defer file.Close()
	require.NoError(b, pprof.Lookup("heap").WriteTo(file, 0))
	b.Logf("heap profile at collector peak: %s", path)
}

// BenchmarkStreamingCollectorMemory reports the streaming collector's
// pre-evaluation heap peak separately from what the scan retains downstream,
// across three synthetic cluster sizes. See the file comment for how to read
// the metrics.
func BenchmarkStreamingCollectorMemory(b *testing.B) {
	for _, spec := range syntheticClusters {
		b.Run(spec.name, func(b *testing.B) {
			var collectorPeak, downstream, allocated, listCalls float64

			for range b.N {
				peak, retainedHeap, churn, calls := runSyntheticCollection(b, spec)
				collectorPeak += peak
				downstream += retainedHeap
				allocated += churn
				listCalls += float64(calls)
			}

			runs := float64(b.N)
			b.ReportMetric(collectorPeak/runs, "MB_collector_peak")
			b.ReportMetric(downstream/runs, "MB_downstream")
			b.ReportMetric(allocated/runs, "MB_allocated")
			b.ReportMetric(listCalls/runs, "list_calls")
		})
	}
}

// runSyntheticCollection drives one collection of a synthetic cluster and
// returns, in megabytes, the collector's peak, the downstream retention, and
// the total allocated during collection, plus the number of LIST calls made.
func runSyntheticCollection(b *testing.B, spec syntheticClusterSpec) (peakMB, downstreamMB, allocatedMB float64, listCalls int) {
	b.Helper()

	ctx := context.Background()
	lister := newSyntheticLister(spec)
	handler := lister.handler()
	scanInfo, session := streamingTestSession(ctx)

	b.StopTimer()
	baseline := liveHeapBytes()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	b.StartTimer()

	// Unbuffered: the producer is still holding every namespace partition when
	// the resident batch arrives, which is the point the peak is taken at.
	batches := make(chan *cautils.ResourceBatch)
	collectErr := make(chan error, 1)
	go func() {
		defer close(batches)
		collectErr <- handler.collectAndStreamBatches(ctx, syntheticQueryableResources(), &EmptySelector{}, session, scanInfo, cautils.ExternalResources{}, batches, nil)
	}()

	resident := <-batches

	b.StopTimer()
	peak := liveHeapBytes()
	writeHeapProfile(b, spec.name)
	b.StartTimer()

	// Merge every batch the way ProcessWithStreaming merges them into the
	// session, so downstream retention is measured against the same map the
	// scan would go on to use.
	retained := make(map[string]workloadinterface.IMetadata, spec.total())
	maps.Copy(retained, resident.AllResources)
	for batch := range batches {
		maps.Copy(retained, batch.AllResources)
	}

	b.StopTimer()
	require.NoError(b, <-collectErr)
	require.Len(b, retained, spec.total(), "the synthetic cluster must be collected in full")

	settled := liveHeapBytes()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	peakMB = heapDelta(baseline, peak)
	downstreamMB = heapDelta(baseline, settled)
	allocatedMB = float64(after.TotalAlloc-before.TotalAlloc) / (1 << 20)
	listCalls = lister.listCalls()

	runtime.KeepAlive(retained)
	b.StartTimer()
	return peakMB, downstreamMB, allocatedMB, listCalls
}

// TestSyntheticCollectorHarness keeps the harness honest under `go test`: the
// fixture must serve the cluster it claims to, the collector must partition
// all of it, and one paginated traversal per GVR must be all it takes. Without
// this, a broken fixture would quietly turn the benchmark into a measurement
// of nothing.
func TestSyntheticCollectorHarness(t *testing.T) {
	spec := syntheticClusterSpec{name: "harness", namespaces: 4, podsPerNS: 7, nodes: 3, serverPageSize: 5}

	ctx := context.Background()
	lister := newSyntheticLister(spec)
	handler := lister.handler()
	scanInfo, session := streamingTestSession(ctx)

	batches := make(chan *cautils.ResourceBatch, spec.namespaces+1)
	require.NoError(t, handler.collectAndStreamBatches(ctx, syntheticQueryableResources(), &EmptySelector{}, session, scanInfo, cautils.ExternalResources{}, batches, nil))
	close(batches)

	resident := <-batches
	require.Len(t, resident.AllResources, spec.nodes, "nodes are cluster-scoped and belong in the resident batch")

	namespaces := 0
	namespaced := 0
	for batch := range batches {
		namespaces++
		namespaced += len(batch.AllResources)
		require.Len(t, batch.AllResources, spec.podsPerNS)
	}
	require.Equal(t, spec.namespaces, namespaces)
	require.Equal(t, spec.total(), namespaced+len(resident.AllResources))

	// 28 pods at 5 per page is 6 calls, 3 nodes is 1: one traversal per GVR,
	// never one per namespace.
	require.Equal(t, 7, lister.listCalls())
}
