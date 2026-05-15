package resourcehandler

import (
	"context"
	"errors"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

type mockDynamicClient struct {
	dynamic.Interface
	listFunc func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error)
}

func (m *mockDynamicClient) Resource(resource schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return &mockNamespaceableResourceClient{listFunc: m.listFunc}
}

type mockNamespaceableResourceClient struct {
	dynamic.NamespaceableResourceInterface
	listFunc func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error)
}

func (m *mockNamespaceableResourceClient) Namespace(s string) dynamic.ResourceInterface {
	return m
}

func (m *mockNamespaceableResourceClient) List(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	return m.listFunc(ctx, opts)
}

func TestPullResources_PartialFailureSurface(t *testing.T) {
	mockErr := errors.New("simulated API failure")
	mockClient := &mockDynamicClient{
		listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			if opts.FieldSelector == "metadata.name=fail" {
				return nil, mockErr
			}
			return &unstructured.UnstructuredList{
				Items: []unstructured.Unstructured{
					{
						Object: map[string]interface{}{
							"apiVersion": "v1",
							"kind":       "Pod",
							"metadata": map[string]interface{}{
								"name":      "test-pod",
								"namespace": "default",
							},
						},
					},
				},
			}, nil
		},
	}

	k8sApi := &k8sinterface.KubernetesApi{
		DynamicClient: mockClient,
	}

	handler := &K8sResourceHandler{
		k8s: k8sApi,
	}

	queryableResources := QueryableResources{
		"//v1/configmaps/metadata.name=ok": QueryableResource{
			GroupVersionResourceTriplet: "//v1/configmaps",
			FieldSelectors:              "metadata.name=ok",
		},
		"//v1/configmaps/metadata.name=fail": QueryableResource{
			GroupVersionResourceTriplet: "//v1/configmaps",
			FieldSelectors:              "metadata.name=fail",
		},
	}

	k8sResourcesMap, allResources, failedQueries := handler.pullResources(queryableResources, &EmptySelector{})

	// Verify that the successful selector populated the shared raw-GVR bucket.
	assert.Len(t, allResources, 1)
	assert.Len(t, k8sResourcesMap["//v1/configmaps"], 1)

	// Verify that the failed selector is retained under its selector-qualified key.
	assert.Len(t, failedQueries, 1)
	fq, ok := failedQueries["//v1/configmaps/metadata.name=fail"]
	assert.True(t, ok, "expected failed query key to include the field selector")
	assert.Equal(t, "//v1/configmaps", fq.gvr)
	assert.ErrorContains(t, fq.err, "simulated API failure")
}

func TestGetResources_SurfacesMissingGVRFailuresInInfoMap(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	handler := getResourceHandlerMock()

	handler.k8s.DynamicClient = &mockDynamicClient{
		listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			if opts.FieldSelector != "" {
				return nil, errors.New("simulated API failure")
			}
			return &unstructured.UnstructuredList{
				Items: []unstructured.Unstructured{{
					Object: map[string]interface{}{
						"apiVersion": "v1",
						"kind":       "Namespace",
						"metadata": map[string]interface{}{
							"name": "default",
						},
					},
				}},
			}, nil
		},
	}

	rule := mockRule("rule-a", nil, "")
	rule.Match = append(rule.Match, mockMatch(6), mockMatch(4))
	control := mockControl("control-1", nil)
	control.Rules = append(control.Rules, rule)
	framework := mockFramework("test", nil)
	framework.Controls = append(framework.Controls, control)

	scanInfo := &cautils.ScanInfo{}
	sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo)
	sessionObj.Policies = append(sessionObj.Policies, *framework)

	_, _, _, _, err := handler.GetResources(context.Background(), sessionObj, scanInfo)
	assert.NoError(t, err)

	info, ok := sessionObj.InfoMap["core/v1/secrets"]
	assert.True(t, ok, "expected missing secrets GVR to be surfaced in InfoMap")
	assert.Contains(t, info.InnerInfo, "simulated API failure")
}

func TestGetResources_FailsWhenAllQueriesFail(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	handler := getResourceHandlerMock()

	handler.k8s.DynamicClient = &mockDynamicClient{
		listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			return nil, errors.New("simulated API failure")
		},
	}

	rule := mockRule("rule-a", nil, "")
	rule.Match = append(rule.Match, mockMatch(4))
	control := mockControl("control-1", nil)
	control.Rules = append(control.Rules, rule)
	framework := mockFramework("test", nil)
	framework.Controls = append(framework.Controls, control)

	scanInfo := &cautils.ScanInfo{}
	sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo)
	sessionObj.Policies = append(sessionObj.Policies, *framework)

	_, _, _, _, err := handler.GetResources(context.Background(), sessionObj, scanInfo)
	assert.ErrorContains(t, err, "failed to pull any Kubernetes resources")
	assert.ErrorContains(t, err, "simulated API failure")
}
