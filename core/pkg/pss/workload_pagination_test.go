package pss

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestWorkloadPagination_DoesNotDropLaterPods(t *testing.T) {
	gvr := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{gvr: "PodList"})
	calls := 0
	client.PrependReactor("list", "pods", func(_ ktesting.Action) (bool, runtime.Object, error) {
		calls++
		list := &unstructured.UnstructuredList{Items: []unstructured.Unstructured{{Object: map[string]any{"metadata": map[string]any{"name": "pod"}}}}}
		if calls == 1 {
			list.SetContinue("next-page")
		}
		return true, list, nil
	})
	workloads, err := FetchNamespaceWorkloads(context.Background(), client, "ns", []WorkloadTarget{{GVR: gvr, Kind: "Pod"}})
	require.NoError(t, err)
	require.Len(t, workloads, 2)
	require.Equal(t, 2, calls)
}

func pagedWorkloadClient(t *testing.T, call func(ktesting.Action, metav1.ListOptions) (*unstructured.UnstructuredList, error)) *dynamicfake.FakeDynamicClient {
	t.Helper()
	kinds := make(map[schema.GroupVersionResource]string)
	for _, target := range DefaultWorkloadTargets {
		kinds[target.GVR] = target.Kind + "List"
	}
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), kinds)
	client.PrependReactor("list", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
		withOptions, ok := action.(interface{ GetListOptions() metav1.ListOptions })
		require.True(t, ok)
		list, err := call(action, withOptions.GetListOptions())
		if list == nil {
			return true, nil, err
		}
		return true, list, err
	})
	return client
}

func pagedPod(name string, privileged bool) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": name, "namespace": "ns"},
		"spec": map[string]any{"containers": []any{map[string]any{
			"name": "app", "image": "fixture", "securityContext": map[string]any{"privileged": privileged},
		}}},
	}}
}

func pageList(token string, items ...unstructured.Unstructured) *unstructured.UnstructuredList {
	list := &unstructured.UnstructuredList{Items: items}
	list.SetContinue(token)
	return list
}

func podTarget() []WorkloadTarget {
	return FilterTargetsByKind(DefaultWorkloadTargets, "Pod")
}

func TestWorkloadPagination_UsesOpaqueTokenAndBoundedPageSize(t *testing.T) {
	token := t.Name() + "+/= continuation"
	var options []metav1.ListOptions
	client := pagedWorkloadClient(t, func(action ktesting.Action, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		require.Equal(t, "ns", action.GetNamespace())
		options = append(options, opts)
		if opts.Continue == "" {
			return pageList(token, pagedPod("first", false)), nil
		}
		require.Equal(t, token, opts.Continue)
		return pageList("", pagedPod("second", true)), nil
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", podTarget())
	require.NoError(t, err)
	require.Len(t, items, 2)
	require.Len(t, options, 2)
	require.Equal(t, workloadListPageSize, options[0].Limit)
	require.Equal(t, options[0].Limit, options[1].Limit)
	require.Empty(t, options[0].Continue)
}

func TestWorkloadPagination_LaterViolationAffectsComplianceResult(t *testing.T) {
	client := pagedWorkloadClient(t, func(_ ktesting.Action, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		if opts.Continue == "" {
			return pageList("next", pagedPod("safe", false)), nil
		}
		return pageList("", pagedPod("privileged", true)), nil
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", podTarget())
	require.NoError(t, err)
	result := Aggregate("ns", items, Baseline)
	require.Equal(t, 2, result.TotalWorkloads)
	require.Equal(t, 1, result.PassingWorkloads)
	require.Equal(t, 1, result.FailingWorkloads)
	require.Equal(t, Privileged, result.CurrentEffectiveLevel)
	require.Equal(t, "privileged", result.FailingResults()[0].Name)
}

func TestWorkloadPagination_EmptyPageWithContinuationIsNotEndOfList(t *testing.T) {
	client := pagedWorkloadClient(t, func(_ ktesting.Action, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		if opts.Continue == "" {
			return pageList("later"), nil
		}
		return pageList("", pagedPod("later-pod", true)), nil
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", podTarget())
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "later-pod", items[0].GetName())
	require.Len(t, client.Actions(), 2)
}

func TestWorkloadPagination_EmptyFinalPageEndsListing(t *testing.T) {
	client := pagedWorkloadClient(t, func(_ ktesting.Action, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		if opts.Continue == "" {
			return pageList("last", pagedPod("first", false)), nil
		}
		return pageList(""), nil
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", podTarget())
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Len(t, client.Actions(), 2)
}

func TestWorkloadPagination_PreservesOrderAcrossThreePages(t *testing.T) {
	calls := 0
	client := pagedWorkloadClient(t, func(_ ktesting.Action, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		calls++
		next := fmt.Sprint(calls)
		if calls == 3 {
			next = ""
		}
		return pageList(next, pagedPod(fmt.Sprint(calls, "a"), false), pagedPod(fmt.Sprint(calls, "b"), false)), nil
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", podTarget())
	require.NoError(t, err)
	require.Len(t, items, 6)
	for i, name := range []string{"1a", "1b", "2a", "2b", "3a", "3b"} {
		require.Equal(t, name, items[i].GetName())
		require.Equal(t, "Pod", items[i].GetKind())
	}
}

func TestWorkloadPagination_ContinuationResetsForEachKind(t *testing.T) {
	client := pagedWorkloadClient(t, func(action ktesting.Action, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		if opts.Continue == "" {
			return pageList("shared-token"), nil
		}
		return pageList("", pagedPod(action.GetResource().Resource, false)), nil
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", DefaultWorkloadTargets)
	require.NoError(t, err)
	require.Len(t, items, len(DefaultWorkloadTargets))
	require.Len(t, client.Actions(), 2*len(DefaultWorkloadTargets))
	for i, target := range DefaultWorkloadTargets {
		require.Equal(t, target.Kind, items[i].GetKind())
		require.Equal(t, target.GVR.Resource, items[i].GetName())
	}
}

func TestWorkloadPagination_LaterPageErrorsNeverReturnSuccessfulPartialScan(t *testing.T) {
	failure := errors.New("second page unavailable")
	client := pagedWorkloadClient(t, func(_ ktesting.Action, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		if opts.Continue == "" {
			return pageList("later", pagedPod("safe", false)), nil
		}
		return nil, failure
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", podTarget())
	require.ErrorIs(t, err, failure)
	require.Nil(t, items)
	var listErr *ListResourceError
	require.ErrorAs(t, err, &listErr)
	require.Equal(t, "Pod", listErr.Kind)
	require.Equal(t, podTarget()[0].GVR, listErr.GVR)
}

func TestWorkloadPagination_ExpiredContinuationRemainsAnError(t *testing.T) {
	failure := apierrors.NewResourceExpired("expired snapshot")
	client := pagedWorkloadClient(t, func(_ ktesting.Action, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		if opts.Continue == "" {
			return pageList("expired", pagedPod("old", false)), nil
		}
		return nil, failure
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", podTarget())
	require.ErrorIs(t, err, failure)
	require.True(t, apierrors.IsResourceExpired(err))
	require.Nil(t, items)
	require.Len(t, client.Actions(), 2)
}

func TestWorkloadPagination_RepeatedTokenIsRejected(t *testing.T) {
	client := pagedWorkloadClient(t, func(_ ktesting.Action, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		return pageList("same", pagedPod("pod", false)), nil
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", podTarget())
	require.ErrorContains(t, err, "repeated a continuation token")
	require.Nil(t, items)
	require.Len(t, client.Actions(), 2)
}

func TestWorkloadPagination_MultiTokenCycleIsRejected(t *testing.T) {
	calls := 0
	client := pagedWorkloadClient(t, func(_ ktesting.Action, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		calls++
		tokens := []string{"a", "b", "a"}
		return pageList(tokens[calls-1]), nil
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", podTarget())
	require.ErrorContains(t, err, "repeated a continuation token")
	require.Nil(t, items)
	require.Equal(t, 3, calls)
}

func TestWorkloadPagination_PageBudgetStopsUnboundedEmptyResponses(t *testing.T) {
	calls := 0
	client := pagedWorkloadClient(t, func(_ ktesting.Action, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		calls++
		return pageList(fmt.Sprint(calls)), nil
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", podTarget())
	require.ErrorContains(t, err, "page safety limit")
	require.Nil(t, items)
	require.Equal(t, maxWorkloadListPages, calls)
}

func TestWorkloadPagination_FinalPageAtBudgetIsAccepted(t *testing.T) {
	calls := 0
	client := pagedWorkloadClient(t, func(_ ktesting.Action, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		calls++
		if calls == maxWorkloadListPages {
			return pageList("", pagedPod("last", true)), nil
		}
		return pageList(fmt.Sprint(calls)), nil
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", podTarget())
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "last", items[0].GetName())
}

func TestWorkloadPagination_CancellationBetweenPagesStopsBeforeNextRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := pagedWorkloadClient(t, func(_ ktesting.Action, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		cancel()
		return pageList("later", pagedPod("safe", false)), nil
	})
	items, err := FetchNamespaceWorkloads(ctx, client, "ns", podTarget())
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, items)
	require.Len(t, client.Actions(), 1)
}

func TestWorkloadPagination_AlreadyCanceledContextMakesNoRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := pagedWorkloadClient(t, func(_ ktesting.Action, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		t.Fatal("canceled scan must not list")
		return nil, nil
	})
	items, err := FetchNamespaceWorkloads(ctx, client, "ns", podTarget())
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, items)
	require.Empty(t, client.Actions())
}

func TestWorkloadPagination_PreservesExplicitItemKind(t *testing.T) {
	client := pagedWorkloadClient(t, func(_ ktesting.Action, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		item := pagedPod("explicit", false)
		item.SetKind("Deployment")
		return pageList("", item), nil
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", podTarget())
	require.NoError(t, err)
	require.Equal(t, "Deployment", items[0].GetKind())
}

func TestWorkloadPagination_FirstPagePermissionErrorIsPreserved(t *testing.T) {
	failure := apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("denied"))
	client := pagedWorkloadClient(t, func(_ ktesting.Action, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		return nil, failure
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", podTarget())
	require.ErrorIs(t, err, failure)
	require.True(t, apierrors.IsForbidden(err))
	require.Nil(t, items)
	require.Len(t, client.Actions(), 1)
}

func TestWorkloadPagination_NoTargetsDoesNotList(t *testing.T) {
	client := pagedWorkloadClient(t, func(_ ktesting.Action, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		t.Fatal("no targets must not list")
		return nil, nil
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", nil)
	require.NoError(t, err)
	require.Empty(t, items)
	require.Empty(t, client.Actions())
}

func TestWorkloadPagination_LaterKindFailureDiscardsEarlierKindResults(t *testing.T) {
	failure := errors.New("pods unavailable")
	client := pagedWorkloadClient(t, func(action ktesting.Action, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		if action.GetResource().Resource == "pods" {
			return nil, failure
		}
		return pageList("", pagedPod("earlier", false)), nil
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", DefaultWorkloadTargets)
	require.ErrorIs(t, err, failure)
	require.Nil(t, items)
	var listErr *ListResourceError
	require.ErrorAs(t, err, &listErr)
	require.Equal(t, "Pod", listErr.Kind)
}

func TestWorkloadPagination_EachWorkloadKindRestoresMissingTypeOnEveryPage(t *testing.T) {
	for _, target := range DefaultWorkloadTargets {
		t.Run(target.Kind, func(t *testing.T) {
			client := pagedWorkloadClient(t, func(_ ktesting.Action, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
				if opts.Continue == "" {
					return pageList("later", pagedPod("first", false)), nil
				}
				return pageList("", pagedPod("last", false)), nil
			})
			items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", []WorkloadTarget{target})
			require.NoError(t, err)
			require.Len(t, items, 2)
			require.Equal(t, target.Kind, items[0].GetKind())
			require.Equal(t, target.Kind, items[1].GetKind())
		})
	}
}

func TestWorkloadPagination_DeadlineExceededRemainsWrapped(t *testing.T) {
	client := pagedWorkloadClient(t, func(_ ktesting.Action, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		return nil, context.DeadlineExceeded
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", podTarget())
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, items)
	var listErr *ListResourceError
	require.ErrorAs(t, err, &listErr)
	require.Equal(t, podTarget()[0].GVR, listErr.GVR)
}

func TestWorkloadPagination_RequestDoesNotChangeNamespaceOrSelectors(t *testing.T) {
	var calls int
	client := pagedWorkloadClient(t, func(action ktesting.Action, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		calls++
		require.Equal(t, "tenant-a", action.GetNamespace())
		require.Empty(t, opts.LabelSelector)
		require.Empty(t, opts.FieldSelector)
		require.Empty(t, opts.ResourceVersion)
		require.False(t, opts.Watch)
		if calls == 1 {
			return pageList("next"), nil
		}
		return pageList(""), nil
	})
	_, err := FetchNamespaceWorkloads(context.Background(), client, "tenant-a", podTarget())
	require.NoError(t, err)
	require.Equal(t, 2, calls)
}

func TestWorkloadPagination_FreshCallStartsWithoutStaleContinuation(t *testing.T) {
	var starts int
	client := pagedWorkloadClient(t, func(_ ktesting.Action, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		if opts.Continue == "" {
			starts++
			return pageList("reused-token"), nil
		}
		return pageList("", pagedPod("last", false)), nil
	})
	for i := 0; i < 2; i++ {
		items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", podTarget())
		require.NoError(t, err)
		require.Len(t, items, 1)
	}
	require.Equal(t, 2, starts)
}

func TestWorkloadPagination_CollectionCanBeDeduplicatedAfterPaging(t *testing.T) {
	parent := makeWorkloadWithUID("Deployment", "app", "ns", "parent")
	child := makeWorkloadWithUID("ReplicaSet", "app-child", "ns", "child", metav1.OwnerReference{
		Kind: "Deployment", Name: "app", UID: "parent", Controller: boolPtr(true),
	})
	calls := 0
	client := pagedWorkloadClient(t, func(_ ktesting.Action, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		calls++
		if calls == 1 {
			return pageList("later", parent), nil
		}
		return pageList("", child), nil
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", podTarget())
	require.NoError(t, err)
	result := DeduplicateWorkloads(items)
	require.Len(t, result, 1)
	require.Equal(t, "Deployment", result[0].GetKind())
}

func TestWorkloadPagination_ResourceVersionAndAnnotationsSurvivePaging(t *testing.T) {
	item := pagedPod("pod", false)
	item.SetResourceVersion("123")
	item.SetAnnotations(map[string]string{"fixture": "original"})
	client := pagedWorkloadClient(t, func(_ ktesting.Action, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		if opts.Continue == "" {
			return pageList("later"), nil
		}
		return pageList("", item), nil
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", podTarget())
	require.NoError(t, err)
	require.Equal(t, "123", items[0].GetResourceVersion())
	require.Equal(t, item.GetAnnotations(), items[0].GetAnnotations())
	require.Equal(t, "Pod", items[0].GetKind())
}

func TestWorkloadPagination_AllNamespaceScopeIsPreserved(t *testing.T) {
	calls := 0
	client := pagedWorkloadClient(t, func(action ktesting.Action, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		calls++
		require.Empty(t, action.GetNamespace())
		if calls == 1 {
			return pageList("next", pagedPod("first", false)), nil
		}
		return pageList("", pagedPod("last", false)), nil
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "", podTarget())
	require.NoError(t, err)
	require.Len(t, items, 2)
}

func TestWorkloadPagination_EmptyNamespaceCollectionReturnsNoWorkloads(t *testing.T) {
	client := pagedWorkloadClient(t, func(_ ktesting.Action, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		return pageList(""), nil
	})
	items, err := FetchNamespaceWorkloads(context.Background(), client, "ns", podTarget())
	require.NoError(t, err)
	require.Empty(t, items)
	require.Len(t, client.Actions(), 1)
}
