package resourcehandler

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler/partitionstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestPullSingleResource_RateLimit429RetrySuccess(t *testing.T) {
	var attempts atomic.Int32
	mockClient := &mockDynamicClient{
		listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			current := attempts.Add(1)
			if current == 1 {
				// First attempt fails with 429 TooManyRequests
				return nil, apierrors.NewTooManyRequestsError("APF bucket rate limit exceeded")
			}
			return &unstructured.UnstructuredList{
				Items: []unstructured.Unstructured{
					{
						Object: map[string]any{
							"apiVersion": "v1",
							"kind":       "Pod",
							"metadata": map[string]any{
								"name":      "recovered-pod",
								"namespace": "default",
							},
						},
					},
				},
			}, nil
		},
	}

	handler := &K8sResourceHandler{
		k8s: &k8sinterface.KubernetesApi{
			DynamicClient: mockClient,
		},
	}

	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	results, failures := handler.pullSingleResource(context.Background(), &gvr, "", "", &EmptySelector{}, nil)

	require.Empty(t, failures, "429 should have been retried and resolved without failure")
	require.Len(t, results, 1, "resource should be recovered after 429 retry")
	assert.Equal(t, "recovered-pod", results[0].GetName())
	assert.Equal(t, int32(2), attempts.Load(), "should have retried exactly once after 429")
}

func TestPullSingleResource_RateLimit429ExhaustedRetries(t *testing.T) {
	var attempts atomic.Int32
	mockClient := &mockDynamicClient{
		listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			attempts.Add(1)
			return nil, apierrors.NewTooManyRequestsError("persistent rate limit")
		},
	}

	handler := &K8sResourceHandler{
		k8s: &k8sinterface.KubernetesApi{
			DynamicClient: mockClient,
		},
		retrySleep: func(ctx context.Context, d time.Duration) error {
			return nil
		},
	}

	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	results, failures := handler.pullSingleResource(context.Background(), &gvr, "", "", &EmptySelector{}, nil)

	assert.Empty(t, results)
	require.Len(t, failures, 1, "persistent 429 should be recorded as a failure")
	assert.Contains(t, failures[0].err.Error(), "persistent rate limit")
	// Initial attempt + 5 retries = 6 attempts total
	assert.Equal(t, int32(6), attempts.Load())
}

func TestPullSingleResource_RateLimit429SuggestsClientDelayCapped(t *testing.T) {
	var attempts atomic.Int32
	var capturedSleepDelay time.Duration

	mockClient := &mockDynamicClient{
		listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			current := attempts.Add(1)
			if current == 1 {
				// Server asks to wait 120 seconds (must be capped at 30s)
				status := apierrors.NewTooManyRequestsError("rate limit exceeded").ErrStatus
				status.Details = &metav1.StatusDetails{
					RetryAfterSeconds: 120,
				}
				return nil, &apierrors.StatusError{ErrStatus: status}
			}
			return &unstructured.UnstructuredList{}, nil
		},
	}

	handler := &K8sResourceHandler{
		k8s: &k8sinterface.KubernetesApi{
			DynamicClient: mockClient,
		},
		retrySleep: func(ctx context.Context, d time.Duration) error {
			capturedSleepDelay = d
			return nil
		},
	}

	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	results, failures := handler.pullSingleResource(context.Background(), &gvr, "", "", &EmptySelector{}, nil)

	require.Empty(t, failures)
	assert.Empty(t, results)
	assert.Equal(t, int32(2), attempts.Load())
	assert.Equal(t, 30*time.Second, capturedSleepDelay, "suggested client delay of 120s must be capped at 30s")
}

func TestPullResources_ConfigurableParallelism(t *testing.T) {
	t.Run("configured via handler method", func(t *testing.T) {
		handler := &K8sResourceHandler{}
		handler.SetMaxParallelResourcePulls(3)
		assert.Equal(t, 3, handler.getMaxParallelPulls())
	})

	t.Run("configured via environment variable", func(t *testing.T) {
		t.Setenv("KUBESCAPE_MAX_PARALLEL_PULLS", "5")
		handler := &K8sResourceHandler{}
		assert.Equal(t, 5, handler.getMaxParallelPulls())
	})

	t.Run("configured via environment variable with whitespace padding", func(t *testing.T) {
		t.Setenv("KUBESCAPE_MAX_PARALLEL_PULLS", "  7  \n")
		handler := &K8sResourceHandler{}
		assert.Equal(t, 7, handler.getMaxParallelPulls())
	})

	t.Run("partition store in-memory configured with whitespace padding", func(t *testing.T) {
		t.Setenv("KUBESCAPE_PARTITION_STORE", "  memory  ")
		handler := &K8sResourceHandler{}
		store, err := handler.newStore()
		require.NoError(t, err)
		require.NotNil(t, store)
		t.Cleanup(func() { _ = store.Close() })
		assert.IsType(t, &partitionstore.MemoryStore{}, store)
	})

	t.Run("spill dir configured with whitespace padding", func(t *testing.T) {
		spillDir := t.TempDir()
		t.Setenv("KUBESCAPE_PARTITION_STORE", " disk ")
		t.Setenv("KUBESCAPE_SPILL_DIR", "  "+spillDir+"  \n")
		handler := &K8sResourceHandler{}
		store, err := handler.newStore()
		require.NoError(t, err)
		require.NotNil(t, store)
		t.Cleanup(func() { _ = store.Close() })
		assert.IsType(t, &partitionstore.DiskStore{}, store)

		entries, err := os.ReadDir(spillDir)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.True(t, entries[0].IsDir())
		assert.True(t, strings.HasPrefix(entries[0].Name(), "kubescape-spill-"))
	})

	t.Run("configured via scanInfo in GetResources", func(t *testing.T) {
		handler, sessionObj, scanInfo := listedGVRsSession()
		scanInfo.MaxParallelResourcePulls = 3
		_, _, _, _, err := handler.GetResources(context.Background(), sessionObj, scanInfo)
		require.NoError(t, err)
		assert.Equal(t, 3, handler.getMaxParallelPulls())
	})

	t.Run("configured via scanInfo in StreamResourcesBatches", func(t *testing.T) {
		handler, sessionObj, scanInfo := listedGVRsSession()
		scanInfo.MaxParallelResourcePulls = 4
		batchChan, errChan, _, err := handler.StreamResourcesBatches(context.Background(), sessionObj, scanInfo)
		require.NoError(t, err)
		for range batchChan {
		}
		require.NoError(t, <-errChan)
		assert.Equal(t, 4, handler.getMaxParallelPulls())
	})

	t.Run("defaults to defaultMaxParallelResourcePulls when unset", func(t *testing.T) {
		t.Setenv("KUBESCAPE_MAX_PARALLEL_PULLS", "")
		handler := &K8sResourceHandler{}
		assert.Equal(t, defaultMaxParallelResourcePulls, handler.getMaxParallelPulls())
	})

	t.Run("enforces concurrency limit during pullResources", func(t *testing.T) {
		var activeConcurrency atomic.Int32
		var maxObservedConcurrency atomic.Int32

		mockClient := &mockDynamicClient{
			listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
				current := activeConcurrency.Add(1)
				for {
					oldMax := maxObservedConcurrency.Load()
					if current <= oldMax || maxObservedConcurrency.CompareAndSwap(oldMax, current) {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
				activeConcurrency.Add(-1)
				return &unstructured.UnstructuredList{}, nil
			},
		}

		handler := &K8sResourceHandler{
			k8s: &k8sinterface.KubernetesApi{
				DynamicClient: mockClient,
			},
		}
		handler.SetMaxParallelResourcePulls(2)

		qrs := make(QueryableResources)
		for i := 0; i < 6; i++ {
			triplet := "//v1/configmaps"
			key := triplet + fmt.Sprintf("/sel-%d", i)
			qrs[key] = QueryableResource{
				GroupVersionResourceTriplet: triplet,
				FieldSelectors:              fmt.Sprintf("metadata.name=cm-%d", i),
			}
		}

		_, _, _ = handler.pullResources(context.Background(), qrs, &EmptySelector{}, "")
		assert.LessOrEqual(t, maxObservedConcurrency.Load(), int32(2), "concurrency must not exceed configured limit of 2")
	})
}
