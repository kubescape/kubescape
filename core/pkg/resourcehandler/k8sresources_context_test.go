package resourcehandler

import (
	"context"
	"errors"
	"fmt"
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

	require.NotNil(t, capturedCtx)
	assert.Equal(t, sentinel, capturedCtx.Value(ctxKey{}))
}

func TestPullResources_ContextCancellationUnblocksSlowList(t *testing.T) {
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

	assert.Less(t, elapsed, 3*time.Second)
	assert.NotEmpty(t, failedQueries)
	for _, f := range failedQueries {
		assert.True(t,
			errors.Is(f.err, context.DeadlineExceeded) || errors.Is(f.err, context.Canceled),
			"unexpected error: %v", f.err)
	}
}

func TestPullResources_SemaphoreContextCancellation(t *testing.T) {
	release := make(chan struct{})
	listStarted := make(chan struct{}, maxParallelResourcePulls)

	handler := &K8sResourceHandler{
		k8s: &k8sinterface.KubernetesApi{
			DynamicClient: &mockDynamicClient{
				listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
					listStarted <- struct{}{}
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

	qrs := make(QueryableResources, maxParallelResourcePulls+2)
	for i := range maxParallelResourcePulls + 2 {
		key := fmt.Sprintf("//v1/resource%d", i)
		qrs[key] = QueryableResource{GroupVersionResourceTriplet: key}
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	var failedQueries map[string]queryFailure
	go func() {
		defer close(done)
		_, _, failedQueries = handler.pullResources(ctx, qrs, &EmptySelector{})
	}()

	for range maxParallelResourcePulls {
		select {
		case <-listStarted:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for goroutines to fill the semaphore")
		}
	}

	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pullResources did not return after context cancellation")
	}

	hasCanceled := false
	for _, f := range failedQueries {
		if errors.Is(f.err, context.Canceled) {
			hasCanceled = true
			break
		}
	}
	assert.True(t, hasCanceled)
}

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
		assert.Equal(t, sentinel, got.Value(ctxKey{}))
	case <-time.After(2 * time.Second):
		t.Fatal("no context was captured from the goroutine's List call")
	}
}

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
			assert.Equal(t, tc.timeout, si.ScanTimeout)
		})
	}
}

func TestPullResources_PostPullContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	handler := &K8sResourceHandler{
		k8s: &k8sinterface.KubernetesApi{
			DynamicClient: &mockDynamicClient{
				listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
					cancel()

					return &unstructured.UnstructuredList{
						Items: []unstructured.Unstructured{
							{},
						},
					}, nil
				},
			},
		},
	}

	qrs := QueryableResources{
		"//v1/pods": QueryableResource{
			GroupVersionResourceTriplet: "//v1/pods",
		},
	}

	k8sResources, allResources, failedQueries := handler.pullResources(ctx, qrs, &EmptySelector{})

	ids, ok := k8sResources["//v1/pods"]
	assert.True(t, ok)
	assert.Empty(t, ids)

	assert.Empty(t, allResources)
	assert.NotEmpty(t, failedQueries)

	hasCanceled := false
	for _, f := range failedQueries {
		if errors.Is(f.err, context.Canceled) {
			hasCanceled = true
			break
		}
	}

	assert.True(t, hasCanceled)
}
