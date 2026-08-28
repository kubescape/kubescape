package resourcehandler

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
)

// pagedLister answers LIST the way a paginating API server does: every call
// returns at most pageSize items starting at the offset encoded in
// opts.Continue, and sets a continue token whenever items remain. Per-selector
// behaviour is keyed by field selector so a test can fail one query and leave
// the others intact.
//
// The pager fetches pages on a background goroutine while the caller's sink
// runs on the test goroutine, so every field is guarded.
type pagedLister struct {
	mu       sync.Mutex
	pageSize int
	// items holds the objects each field selector serves.
	items map[string][]unstructured.Unstructured
	// failAfterPage makes the (n+1)-th call for a selector fail once n pages
	// have been served for it.
	failAfterPage map[string]int
	failWith      map[string]error
	calls         []metav1.ListOptions
}

func newPagedLister(pageSize int) *pagedLister {
	return &pagedLister{
		pageSize:      pageSize,
		items:         map[string][]unstructured.Unstructured{},
		failAfterPage: map[string]int{},
		failWith:      map[string]error{},
	}
}

func (p *pagedLister) serve(selector string, items ...unstructured.Unstructured) *pagedLister {
	p.items[selector] = items
	return p
}

func (p *pagedLister) failSelectorAfterPage(selector string, pages int, err error) *pagedLister {
	p.failAfterPage[selector] = pages
	p.failWith[selector] = err
	return p
}

func (p *pagedLister) list(_ context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, opts)

	offset := 0
	if opts.Continue != "" {
		parsed, err := strconv.Atoi(opts.Continue)
		if err != nil {
			return nil, fmt.Errorf("malformed continue token %q", opts.Continue)
		}
		offset = parsed
	}

	if pages, failing := p.failAfterPage[opts.FieldSelector]; failing && offset >= pages*p.pageSize {
		return nil, p.failWith[opts.FieldSelector]
	}

	items := p.items[opts.FieldSelector]
	end := min(offset+p.pageSize, len(items))
	list := &unstructured.UnstructuredList{
		Object: map[string]any{"apiVersion": "v1", "kind": "PodList"},
		Items:  items[offset:end],
	}
	if end < len(items) {
		list.SetContinue(strconv.Itoa(end))
	}
	return list, nil
}

func (p *pagedLister) recordedCalls() []metav1.ListOptions {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]metav1.ListOptions(nil), p.calls...)
}

func (p *pagedLister) handler() *K8sResourceHandler {
	return &K8sResourceHandler{k8s: &k8sinterface.KubernetesApi{
		KubernetesClient: fakeclientset.NewClientset(),
		DynamicClient:    &mockDynamicClient{listFunc: p.list},
	}}
}

func sinkTestPod(name, namespace string) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
		},
	}}
}

func sinkTestPods(namespace string, count int) []unstructured.Unstructured {
	pods := make([]unstructured.Unstructured, 0, count)
	for i := range count {
		pods = append(pods, sinkTestPod(fmt.Sprintf("pod-%d", i), namespace))
	}
	return pods
}

func collectNames(objs []*unstructured.Unstructured) []string {
	names := make([]string, 0, len(objs))
	for _, obj := range objs {
		names = append(names, obj.GetName())
	}
	return names
}

var sinkTestGVR = &schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

// A sink sees every object of a paginated traversal exactly once and in page
// order, and the slice-returning wrapper the eager collector still uses agrees
// with it object for object.
func TestPullSingleResourceInto_YieldsEveryPagedObjectOnce(t *testing.T) {
	lister := newPagedLister(3).serve("", sinkTestPods("default", 7)...)
	handler := lister.handler()

	var seen []*unstructured.Unstructured
	selectorErrs := handler.pullSingleResourceInto(context.Background(), sinkTestGVR, "", "", &EmptySelector{}, nil, func(obj *unstructured.Unstructured) error {
		// Copy: obj aims into the page the pager still owns.
		seen = append(seen, obj.DeepCopy())
		return nil
	})

	require.Empty(t, selectorErrs)
	assert.Equal(t,
		[]string{"pod-0", "pod-1", "pod-2", "pod-3", "pod-4", "pod-5", "pod-6"},
		collectNames(seen),
		"the sink must see each paged object once, in page order")

	calls := lister.recordedCalls()
	require.Len(t, calls, 3, "7 objects at 3 per page is three LIST calls")
	assert.Empty(t, calls[0].Continue, "the first page must not carry a continue token")
	assert.Equal(t, []string{"3", "6"}, []string{calls[1].Continue, calls[2].Continue})

	// The eager collector's API is unchanged by the sink refactor.
	eager := newPagedLister(3).serve("", sinkTestPods("default", 7)...)
	slice, sliceErrs := eager.handler().pullSingleResource(context.Background(), sinkTestGVR, "", "", &EmptySelector{}, nil)
	require.Empty(t, sliceErrs)
	require.Len(t, slice, 7)
	for i := range slice {
		assert.Equal(t, seen[i].GetName(), slice[i].GetName())
	}
}

// An expired continuation token must surface as a failure for the selector
// being walked, not restart it: pager.EachListItem has no full-relist
// fallback, so the objects already handed to the sink stay put and none of
// them is replayed. This is what lets a sink store objects as they arrive
// without needing to deduplicate a re-listed GVR.
func TestPullSingleResourceInto_ExpiredContinuationTokenIsNotReplayed(t *testing.T) {
	expired := apierrors.NewResourceExpired("continue token 2 expired")
	lister := newPagedLister(2).
		serve("", sinkTestPods("default", 6)...).
		failSelectorAfterPage("", 1, expired)

	var seen []*unstructured.Unstructured
	selectorErrs := lister.handler().pullSingleResourceInto(context.Background(), sinkTestGVR, "", "", &EmptySelector{}, nil, func(obj *unstructured.Unstructured) error {
		seen = append(seen, obj.DeepCopy())
		return nil
	})

	assert.Equal(t, []string{"pod-0", "pod-1"}, collectNames(seen),
		"the objects served before the token expired must be kept, and only once")

	require.Len(t, selectorErrs, 1)
	assert.True(t, apierrors.IsResourceExpired(errors.Unwrap(selectorErrs[0].err)),
		"the expired status must reach the caller as the selector's failure")

	calls := lister.recordedCalls()
	require.Len(t, calls, 2, "the traversal must stop at the expired page")
	for _, call := range calls[1:] {
		assert.NotEmpty(t, call.Continue,
			"a call without a continue token after page 1 would be a full re-list, which would replay page 1 into the sink")
	}
}

// One selector failing part-way keeps what it already yielded and does not
// abandon the remaining selectors. Callers rely on this to report partial
// coverage for a GVR rather than dropping it.
func TestPullSingleResourceInto_PartialSelectorFailureKeepsWalkingRemainingSelectors(t *testing.T) {
	lister := newPagedLister(2).
		serve("metadata.namespace=broken", sinkTestPods("broken", 6)...).
		serve("metadata.namespace=healthy", sinkTestPods("healthy", 3)...).
		failSelectorAfterPage("metadata.namespace=broken", 1, errors.New("etcd unavailable"))

	selectors := &staticFieldSelector{selectors: []string{"metadata.namespace=broken", "metadata.namespace=healthy"}}

	var seen []*unstructured.Unstructured
	selectorErrs := lister.handler().pullSingleResourceInto(context.Background(), sinkTestGVR, "", "", selectors, nil, func(obj *unstructured.Unstructured) error {
		seen = append(seen, obj.DeepCopy())
		return nil
	})

	require.Len(t, seen, 5, "page 1 of the failed selector plus every object of the healthy one")
	assert.Equal(t, []string{"broken", "broken", "healthy", "healthy", "healthy"},
		[]string{seen[0].GetNamespace(), seen[1].GetNamespace(), seen[2].GetNamespace(), seen[3].GetNamespace(), seen[4].GetNamespace()})

	require.Len(t, selectorErrs, 1)
	assert.Equal(t, "metadata.namespace=broken", selectorErrs[0].selector)
	assert.ErrorContains(t, selectorErrs[0].err, "etcd unavailable")
}

// A sink whose per-object work fails stops the selector it is walking the same
// way a LIST error does, and the caller learns which selector it was.
func TestPullSingleResourceInto_SinkErrorStopsTheSelectorAndIsReported(t *testing.T) {
	sinkErr := errors.New("partition store is full")
	lister := newPagedLister(2).serve("", sinkTestPods("default", 6)...)

	handed := 0
	selectorErrs := lister.handler().pullSingleResourceInto(context.Background(), sinkTestGVR, "", "", &EmptySelector{}, nil, func(*unstructured.Unstructured) error {
		handed++
		if handed == 3 {
			return sinkErr
		}
		return nil
	})

	assert.Equal(t, 3, handed, "the traversal must stop at the failing object")
	require.Len(t, selectorErrs, 1)
	assert.ErrorIs(t, selectorErrs[0].err, sinkErr)
}

// Parent filtering happens before the sink, so a sink never stores an object
// the eager collector would have dropped.
func TestPullSingleResourceInto_FiltersOwnedWorkloadsBeforeTheSink(t *testing.T) {
	owned := sinkTestPod("owned-pod", "default")
	owned.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", UID: "1"}})

	lister := newPagedLister(2).serve("", sinkTestPod("bare-pod", "default"), owned)

	var seen []*unstructured.Unstructured
	selectorErrs := lister.handler().pullSingleResourceInto(context.Background(), sinkTestGVR, "", "", &EmptySelector{}, nil, func(obj *unstructured.Unstructured) error {
		seen = append(seen, obj.DeepCopy())
		return nil
	})

	require.Empty(t, selectorErrs)
	assert.Equal(t, []string{"bare-pod"}, collectNames(seen))
}

// A cancelled scan reaches no sink at all: cancellation must not leave a
// half-ingested GVR behind for a caller that stores objects as they arrive.
func TestPullSingleResourceInto_CancelledContextNeverReachesTheSink(t *testing.T) {
	lister := newPagedLister(2).serve("", sinkTestPods("default", 6)...)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	handed := 0
	selectorErrs := lister.handler().pullSingleResourceInto(ctx, sinkTestGVR, "", "", &EmptySelector{}, nil, func(*unstructured.Unstructured) error {
		handed++
		return nil
	})

	assert.Zero(t, handed)
	assert.Empty(t, lister.recordedCalls())
	require.Len(t, selectorErrs, 1)
	assert.ErrorIs(t, selectorErrs[0].err, context.Canceled)
}

// The streaming collector partitions objects as the pager yields them, so a
// GVR whose objects span several pages and several namespaces still lands in
// the right batches, each object exactly once.
func TestCollectAndStreamBatches_PartitionsObjectsAcrossPages(t *testing.T) {
	var pods []unstructured.Unstructured
	for _, namespace := range []string{"ns-a", "ns-b", "ns-c"} {
		for i := range 3 {
			pods = append(pods, sinkTestPod(fmt.Sprintf("%s-pod-%d", namespace, i), namespace))
		}
	}
	// Two per page, so every namespace is split across a page boundary.
	lister := newPagedLister(2).serve("", pods...)
	handler := lister.handler()

	namespaced := true
	queryable := QueryableResources{
		"/v1/pods": {GroupVersionResourceTriplet: "/v1/pods", Namespaced: &namespaced},
	}

	ctx := context.Background()
	scanInfo, session := streamingTestSession(ctx)
	batches := make(chan *cautils.ResourceBatch, 8)

	require.NoError(t, handler.collectAndStreamBatches(ctx, queryable, &EmptySelector{}, session, scanInfo, cautils.ExternalResources{}, batches, nil))
	close(batches)

	resident := <-batches
	assert.Empty(t, resident.AllResources, "no pod in this GVR is cluster-scoped")

	perNamespace := map[string][]string{}
	for batch := range batches {
		perNamespace[batch.Scope] = collectMetadataNames(batch.AllResources)
		assert.Len(t, batch.K8SResources["/v1/pods"], 3,
			"the GVR bucket must list every object of the namespace exactly once")
	}

	assert.Equal(t, map[string][]string{
		"ns-a": {"ns-a-pod-0", "ns-a-pod-1", "ns-a-pod-2"},
		"ns-b": {"ns-b-pod-0", "ns-b-pod-1", "ns-b-pod-2"},
		"ns-c": {"ns-c-pod-0", "ns-c-pod-1", "ns-c-pod-2"},
	}, perNamespace)

	require.Len(t, lister.recordedCalls(), 5, "9 pods at 2 per page is a single paginated traversal, not a LIST per namespace")
}

func collectMetadataNames(resources map[string]workloadinterface.IMetadata) []string {
	names := make([]string, 0, len(resources))
	for _, resource := range resources {
		names = append(names, resource.GetName())
	}
	sort.Strings(names)
	return names
}
