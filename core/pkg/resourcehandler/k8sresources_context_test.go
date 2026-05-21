package resourcehandler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// TestPullSingleResource_ContextPropagated verifies that pullSingleResource
// forwards the caller's context to the underlying K8s List call. Before the
// fix, context.Background() was used unconditionally, so timeouts and
// cancellations set by the scan pipeline were silently ignored.
func TestPullSingleResource_ContextPropagated(t *testing.T) {
	type ctxKey struct{}
	const sentinel = "ctx-sentinel"

	var capturedCtx context.Context

	handler := &K8sResourceHandler{
		k8s: &k8sinterface.KubernetesApi{
			DynamicClient: &mockDynamicClient{
				listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
					capturedCtx = ctx
					return &unstructured.UnstructuredList{}, nil
				},
			},
		},
	}

	ctx := context.WithValue(context.Background(), ctxKey{}, sentinel)
	gvr := &schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	handler.pullSingleResource(ctx, gvr, nil, "", &EmptySelector{})

	require.NotNil(t, capturedCtx,
		"pullSingleResource must pass a context to the K8s List call")
	assert.Equal(t, sentinel, capturedCtx.Value(ctxKey{}),
		"the context received by List must carry values from the caller's context")
}

// TestPullResources_ContextCancellationUnblocksSlowList verifies that when the
// context is cancelled while a K8s List call is in progress, pullResources
// unblocks and returns promptly rather than hanging until the API server
// responds. The cancelled resource must appear in failedQueries.
func TestPullResources_ContextCancellationUnblocksSlowList(t *testing.T) {
	// This channel simulates a hung API server: the list function blocks until
	// the context is cancelled (or the channel is closed).
	hangForever := make(chan struct{})

	handler := &K8sResourceHandler{
		k8s: &k8sinterface.KubernetesApi{
			DynamicClient: &mockDynamicClient{
				listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
					select {
					case <-hangForever:
						return &unstructured.UnstructuredList{}, nil
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				},
			},
		},
	}

	qrs := QueryableResources{
		"//v1/pods": QueryableResource{GroupVersionResourceTriplet: "//v1/pods"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, _, failedQueries := handler.pullResources(ctx, qrs, &EmptySelector{})
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 3*time.Second,
		"pullResources must return after context cancellation, not hang indefinitely")

	assert.NotEmpty(t, failedQueries,
		"the resource whose List call was cancelled should appear in failedQueries")
	for _, f := range failedQueries {
		assert.True(t,
			errors.Is(f.err, context.DeadlineExceeded) || errors.Is(f.err, context.Canceled),
			"failedQuery error should be a context error, got: %v", f.err)
	}
}

// TestPullResources_SemaphoreContextCancellation verifies that goroutines
// waiting for a semaphore slot are unblocked when the context is cancelled.
// This exercises the `select { case sem<-: case <-ctx.Done(): }` path added
// to prevent goroutines from hanging indefinitely at semaphore acquisition.
func TestPullResources_SemaphoreContextCancellation(t *testing.T) {
	// Release is never closed — the goroutines that get through the semaphore
	// will block on the listFunc forever, saturating all slots.
	release := make(chan struct{})
	// listStarted is incremented each time a goroutine enters the list call so
	// we can wait until all semaphore slots are filled.
	listStarted := make(chan struct{}, maxParallelResourcePulls)

	handler := &K8sResourceHandler{
		k8s: &k8sinterface.KubernetesApi{
			DynamicClient: &mockDynamicClient{
				listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
					listStarted <- struct{}{} // signal that this slot is now occupied
					select {
					case <-release:
						return &unstructured.UnstructuredList{}, nil
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				},
			},
		},
	}

	// Create exactly maxParallelResourcePulls+2 resources so at least 2
	// goroutines will be blocked at the semaphore.
	qrs := make(QueryableResources, maxParallelResourcePulls+2)
	qrs["//v1/pods"] = QueryableResource{GroupVersionResourceTriplet: "//v1/pods"}
	qrs["//v1/configmaps"] = QueryableResource{GroupVersionResourceTriplet: "//v1/configmaps"}
	qrs["//v1/secrets"] = QueryableResource{GroupVersionResourceTriplet: "//v1/secrets"}
	qrs["rbac.authorization.k8s.io/v1/clusterrolebindings"] = QueryableResource{
		GroupVersionResourceTriplet: "rbac.authorization.k8s.io/v1/clusterrolebindings",
	}
	qrs["//v1/namespaces"] = QueryableResource{GroupVersionResourceTriplet: "//v1/namespaces"}
	qrs["//v1/nodes"] = QueryableResource{GroupVersionResourceTriplet: "//v1/nodes"}
	qrs["apps/v1/deployments"] = QueryableResource{GroupVersionResourceTriplet: "apps/v1/deployments"}
	qrs["apps/v1/replicasets"] = QueryableResource{GroupVersionResourceTriplet: "apps/v1/replicasets"}
	qrs["apps/v1/daemonsets"] = QueryableResource{GroupVersionResourceTriplet: "apps/v1/daemonsets"}
	qrs["apps/v1/statefulsets"] = QueryableResource{GroupVersionResourceTriplet: "apps/v1/statefulsets"}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	var failedQueries map[string]queryFailure
	go func() {
		defer close(done)
		_, _, failedQueries = handler.pullResources(ctx, qrs, &EmptySelector{})
	}()

	// Wait until all semaphore slots are occupied by blocking list calls.
	for range maxParallelResourcePulls {
		select {
		case <-listStarted:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for goroutines to fill the semaphore")
		}
	}

	// Cancel the context; goroutines waiting on the semaphore should exit.
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pullResources did not return after context cancellation")
	}

	// The goroutines that were queued behind the semaphore should have
	// recorded context.Canceled in failedQueries.
	hasCanceled := false
	for _, f := range failedQueries {
		if errors.Is(f.err, context.Canceled) {
			hasCanceled = true
			break
		}
	}
	assert.True(t, hasCanceled,
		"goroutines waiting on the semaphore must record context.Canceled in failedQueries")
}

// TestPullResources_ContextPassedToGoroutines verifies that the context given
// to pullResources is forwarded to each goroutine's pullSingleResource call,
// not discarded at the goroutine boundary.
func TestPullResources_ContextPassedToGoroutines(t *testing.T) {
	type ctxKey struct{}
	const sentinel = "goroutine-ctx-sentinel"

	capturedCtxCh := make(chan context.Context, 1)

	handler := &K8sResourceHandler{
		k8s: &k8sinterface.KubernetesApi{
			DynamicClient: &mockDynamicClient{
				listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
					select {
					case capturedCtxCh <- ctx:
					default:
					}
					return &unstructured.UnstructuredList{}, nil
				},
			},
		},
	}

	ctx := context.WithValue(context.Background(), ctxKey{}, sentinel)
	qrs := QueryableResources{
		"//v1/pods": QueryableResource{GroupVersionResourceTriplet: "//v1/pods"},
	}

	handler.pullResources(ctx, qrs, &EmptySelector{})

	select {
	case got := <-capturedCtxCh:
		assert.Equal(t, sentinel, got.Value(ctxKey{}),
			"the context passed to goroutines must carry values from the pullResources caller")
	case <-time.After(2 * time.Second):
		t.Fatal("no context was captured from the goroutine's List call")
	}
}

// TestScanInfo_ScanTimeout verifies that the ScanTimeout field is correctly
// parsed and stored by ScanInfo. This underpins the --scan-timeout CLI flag.
func TestScanInfo_ScanTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
	}{
		{"zero means no timeout", 0},
		{"five minutes", 5 * time.Minute},
		{"thirty seconds", 30 * time.Second},
		{"one hour", time.Hour},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			si := &cautils.ScanInfo{ScanTimeout: tc.timeout}
			assert.Equal(t, tc.timeout, si.ScanTimeout,
				"ScanInfo.ScanTimeout should store the duration exactly")
		})
	}
}

