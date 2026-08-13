package hostsensorutils

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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
)

type mockDynamicClient struct {
	resourceFunc func(gvr schema.GroupVersionResource) dynamic.NamespaceableResourceInterface
}

func (m *mockDynamicClient) Resource(resource schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return m.resourceFunc(resource)
}

type mockNamespaceableResourceInterface struct {
	listFunc func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error)
}

func (m *mockNamespaceableResourceInterface) Namespace(string) dynamic.ResourceInterface { return m }
func (m *mockNamespaceableResourceInterface) Create(ctx context.Context, obj *unstructured.Unstructured, options metav1.CreateOptions, subresources ...string) (*unstructured.Unstructured, error) {
	return nil, nil
}
func (m *mockNamespaceableResourceInterface) Update(ctx context.Context, obj *unstructured.Unstructured, options metav1.UpdateOptions, subresources ...string) (*unstructured.Unstructured, error) {
	return nil, nil
}
func (m *mockNamespaceableResourceInterface) UpdateStatus(ctx context.Context, obj *unstructured.Unstructured, options metav1.UpdateOptions) (*unstructured.Unstructured, error) {
	return nil, nil
}
func (m *mockNamespaceableResourceInterface) Delete(ctx context.Context, name string, options metav1.DeleteOptions, subresources ...string) error {
	return nil
}
func (m *mockNamespaceableResourceInterface) DeleteCollection(ctx context.Context, options metav1.DeleteOptions, listOptions metav1.ListOptions) error {
	return nil
}
func (m *mockNamespaceableResourceInterface) Get(ctx context.Context, name string, options metav1.GetOptions, subresources ...string) (*unstructured.Unstructured, error) {
	return nil, nil
}
func (m *mockNamespaceableResourceInterface) List(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	return m.listFunc(ctx, opts)
}
func (m *mockNamespaceableResourceInterface) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return nil, nil
}
func (m *mockNamespaceableResourceInterface) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, options metav1.PatchOptions, subresources ...string) (*unstructured.Unstructured, error) {
	return nil, nil
}
func (m *mockNamespaceableResourceInterface) Apply(ctx context.Context, name string, obj *unstructured.Unstructured, options metav1.ApplyOptions, subresources ...string) (*unstructured.Unstructured, error) {
	return nil, nil
}
func (m *mockNamespaceableResourceInterface) ApplyStatus(ctx context.Context, name string, obj *unstructured.Unstructured, options metav1.ApplyOptions) (*unstructured.Unstructured, error) {
	return nil, nil
}

func TestHostSensorPagination(t *testing.T) {
	totalItems := 525
	var allItems []unstructured.Unstructured
	for i := 0; i < totalItems; i++ {
		item := unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": fmt.Sprintf("%s/%s", hostDataGroup, hostDataVersion),
				"kind":       "OsReleaseFile",
				"metadata": map[string]interface{}{
					"name": fmt.Sprintf("node-%d", i),
				},
				"spec": map[string]interface{}{
					"os": "linux",
				},
			},
		}
		allItems = append(allItems, item)
	}

	listCount := 0
	mockResource := &mockNamespaceableResourceInterface{
		listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			listCount++
			limit := opts.Limit
			if limit != 50 {
				panic(fmt.Sprintf("expected limit 50, got %d", limit))
			}
			startIndex := 0
			if opts.Continue != "" {
				fmt.Sscanf(opts.Continue, "%d", &startIndex)
			}

			endIndex := startIndex + int(limit)
			nextContinue := ""
			if endIndex < totalItems {
				nextContinue = fmt.Sprintf("%d", endIndex)
			} else {
				endIndex = totalItems
			}

			list := &unstructured.UnstructuredList{
				Object: map[string]interface{}{
					"apiVersion": fmt.Sprintf("%s/%s", hostDataGroup, hostDataVersion),
					"kind":       "OsReleaseFileList",
				},
				Items: allItems[startIndex:endIndex],
			}
			list.SetContinue(nextContinue)

			return list, nil
		},
	}

	hsh := &HostSensorHandler{
		dynamicClient: &mockDynamicClient{
			resourceFunc: func(gvr schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
				return mockResource
			},
		},
	}

	ctx := context.Background()
	var items []unstructured.Unstructured
	err := hsh.listCRDResources(ctx, "osreleasefiles", "OsReleaseFile", func(page []unstructured.Unstructured) error {
		items = append(items, page...)
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, totalItems, len(items))
	assert.Equal(t, 11, listCount)
}

func TestHostSensorRateLimitRetry(t *testing.T) {
	listCount := 0
	mockResource := &mockNamespaceableResourceInterface{
		listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			listCount++
			if listCount <= 2 {
				return nil, k8serrors.NewTooManyRequests("Rate limited", 1)
			}
			list := &unstructured.UnstructuredList{
				Object: map[string]interface{}{
					"apiVersion": fmt.Sprintf("%s/%s", hostDataGroup, hostDataVersion),
					"kind":       "OsReleaseFileList",
				},
				Items: []unstructured.Unstructured{},
			}
			return list, nil
		},
	}

	hsh := &HostSensorHandler{
		dynamicClient: &mockDynamicClient{
			resourceFunc: func(gvr schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
				return mockResource
			},
		},
	}

	ctx := context.Background()
	var items []unstructured.Unstructured
	err := hsh.listCRDResources(ctx, "osreleasefiles", "OsReleaseFile", func(page []unstructured.Unstructured) error {
		items = append(items, page...)
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, 0, len(items))
	assert.Equal(t, 3, listCount)
}
