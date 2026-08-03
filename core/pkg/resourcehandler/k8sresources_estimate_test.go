package resourcehandler

import (
	"context"
	"errors"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// gvrAwareDynamicClient is a mock dynamic client that can return different
// list results per GVR.
type gvrAwareDynamicClient struct {
	dynamic.Interface
	listFunc func(gvr schema.GroupVersionResource, ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error)
}

func (m *gvrAwareDynamicClient) Resource(resource schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return &gvrAwareResourceClient{gvr: resource, listFunc: m.listFunc}
}

type gvrAwareResourceClient struct {
	dynamic.NamespaceableResourceInterface
	gvr      schema.GroupVersionResource
	listFunc func(gvr schema.GroupVersionResource, ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error)
}

func (m *gvrAwareResourceClient) Namespace(s string) dynamic.ResourceInterface {
	return m
}

func (m *gvrAwareResourceClient) List(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	return m.listFunc(m.gvr, ctx, opts)
}

func TestEstimateClusterSize_NilClient(t *testing.T) {
	handler := &K8sResourceHandler{}
	size, err := handler.EstimateClusterSize(context.Background(), &cautils.ScanInfo{})
	require.Error(t, err)
	assert.Equal(t, 0, size)
}

func TestEstimateClusterSize_NilDynamicClient(t *testing.T) {
	handler := &K8sResourceHandler{k8s: &k8sinterface.KubernetesApi{}}
	size, err := handler.EstimateClusterSize(context.Background(), &cautils.ScanInfo{})
	require.Error(t, err)
	assert.Equal(t, 0, size)
}

func newListWithRemaining(n int64) *unstructured.UnstructuredList {
	return &unstructured.UnstructuredList{
		Object: map[string]any{
			"metadata": map[string]any{
				"remainingItemCount": n,
			},
		},
	}
}

func TestEstimateClusterSize_SmallCluster(t *testing.T) {
	mockClient := &gvrAwareDynamicClient{
		listFunc: func(gvr schema.GroupVersionResource, ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			assert.Equal(t, int64(1), opts.Limit)
			var n int64 = 10
			switch gvr.Resource {
			case "pods":
				n = 50
			case "services":
				n = 10
			case "deployments":
				n = 5
			case "configmaps":
				n = 20
			}
			return newListWithRemaining(n), nil
		},
	}

	handler := &K8sResourceHandler{
		k8s: &k8sinterface.KubernetesApi{DynamicClient: mockClient},
	}

	size, err := handler.EstimateClusterSize(context.Background(), &cautils.ScanInfo{})
	require.NoError(t, err)
	// 50+10+5+20 + (12 other GVRs * 10 each) = 85 + 120 = 205
	assert.Equal(t, 205, size)
}

func TestEstimateClusterSize_LargeCluster(t *testing.T) {
	mockClient := &gvrAwareDynamicClient{
		listFunc: func(gvr schema.GroupVersionResource, ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			return newListWithRemaining(500), nil
		},
	}

	handler := &K8sResourceHandler{
		k8s: &k8sinterface.KubernetesApi{DynamicClient: mockClient},
	}

	size, err := handler.EstimateClusterSize(context.Background(), &cautils.ScanInfo{})
	require.NoError(t, err)
	// 16 GVRs * 500 each = 8000
	assert.Equal(t, 8000, size)
}

func TestEstimateClusterSize_ListErrors(t *testing.T) {
	mockClient := &gvrAwareDynamicClient{
		listFunc: func(gvr schema.GroupVersionResource, ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			if gvr.Resource == "pods" {
				return nil, errors.New("API server error")
			}
			return newListWithRemaining(100), nil
		},
	}

	handler := &K8sResourceHandler{
		k8s: &k8sinterface.KubernetesApi{DynamicClient: mockClient},
	}

	size, err := handler.EstimateClusterSize(context.Background(), &cautils.ScanInfo{})
	require.NoError(t, err)
	// 15 GVRs * 100 = 1500 (pods error is skipped)
	assert.Equal(t, 1500, size)
}

func TestEstimateClusterSize_NilRemainingItemCount(t *testing.T) {
	mockClient := &gvrAwareDynamicClient{
		listFunc: func(gvr schema.GroupVersionResource, ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			if gvr.Resource == "pods" {
				// No metadata at all — GetRemainingItemCount returns nil
				return &unstructured.UnstructuredList{}, nil
			}
			return newListWithRemaining(200), nil
		},
	}

	handler := &K8sResourceHandler{
		k8s: &k8sinterface.KubernetesApi{DynamicClient: mockClient},
	}

	size, err := handler.EstimateClusterSize(context.Background(), &cautils.ScanInfo{})
	require.NoError(t, err)
	// 15 GVRs * 200 = 3000 (pods with nil remainingItemCount is skipped)
	assert.Equal(t, 3000, size)
}
