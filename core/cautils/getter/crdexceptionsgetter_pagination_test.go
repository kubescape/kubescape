package getter

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

type mockPaginatedDynamicClient struct {
	dynamic.Interface
	t        *testing.T
	listFunc func(opts metav1.ListOptions) (*unstructured.UnstructuredList, error)
}

func (m *mockPaginatedDynamicClient) Resource(resource schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return &mockPaginatedNamespaceableResource{client: m}
}

type mockPaginatedNamespaceableResource struct {
	dynamic.NamespaceableResourceInterface
	client *mockPaginatedDynamicClient
}

func (m *mockPaginatedNamespaceableResource) List(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return m.client.listFunc(opts)
}

func TestListCRDsWithPagination_MultiPage(t *testing.T) {
	ctx := context.Background()
	gvr := schema.GroupVersionResource{Resource: "test"}

	pageCount := 0
	mockClient := &mockPaginatedDynamicClient{
		t: t,
		listFunc: func(opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			pageCount++
			list := &unstructured.UnstructuredList{}
			if opts.Continue == "" {
				list.Items = []unstructured.Unstructured{{}, {}}
				list.SetContinue("token1")
			} else if opts.Continue == "token1" {
				list.Items = []unstructured.Unstructured{{}}
				list.SetContinue("")
			} else {
				return nil, fmt.Errorf("unexpected token")
			}
			return list, nil
		},
	}

	var totalItems []unstructured.Unstructured
	err := listCRDsWithPagination(ctx, gvr, mockClient, func(list *unstructured.UnstructuredList) error {
		totalItems = append(totalItems, list.Items...)
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, 2, pageCount)
	assert.Len(t, totalItems, 3)
}

func TestListCRDsWithPagination_Retry429(t *testing.T) {
	ctx := context.Background()
	gvr := schema.GroupVersionResource{Resource: "test"}

	attempts := 0
	mockClient := &mockPaginatedDynamicClient{
		t: t,
		listFunc: func(opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			attempts++
			if attempts < 3 {
				// return 429
				return nil, k8serrors.NewTooManyRequests("too many requests", 1)
			}
			list := &unstructured.UnstructuredList{}
			list.Items = []unstructured.Unstructured{{}}
			return list, nil
		},
	}

	var totalItems []unstructured.Unstructured
	err := listCRDsWithPagination(ctx, gvr, mockClient, func(list *unstructured.UnstructuredList) error {
		totalItems = append(totalItems, list.Items...)
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, 3, attempts)
	assert.Len(t, totalItems, 1)
}

func TestListCRDsWithPagination_RetriesExhausted(t *testing.T) {
	ctx := context.Background()
	gvr := schema.GroupVersionResource{Resource: "test"}

	attempts := 0
	mockClient := &mockPaginatedDynamicClient{
		t: t,
		listFunc: func(opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			attempts++
			return nil, k8serrors.NewTooManyRequests("too many requests", 1)
		},
	}

	err := listCRDsWithPagination(ctx, gvr, mockClient, func(list *unstructured.UnstructuredList) error {
		return nil
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many requests")
	assert.Equal(t, 5, attempts) // 5 is the max retries defined in the function
}

func TestListCRDsWithPagination_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	gvr := schema.GroupVersionResource{Resource: "test"}

	mockClient := &mockPaginatedDynamicClient{
		t: t,
		listFunc: func(opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			cancel() // cancel during the backoff
			return nil, k8serrors.NewTooManyRequests("too many requests", 1)
		},
	}

	err := listCRDsWithPagination(ctx, gvr, mockClient, func(list *unstructured.UnstructuredList) error {
		return nil
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}
