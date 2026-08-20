package resourcehandler

import (
	"context"
	"fmt"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"

	"k8s.io/client-go/dynamic/fake"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
)

type staticFieldSelector struct {
	selectors []string
}

func (s *staticFieldSelector) GetNamespacesSelectors(resource *schema.GroupVersionResource) []string {
	return s.selectors
}
func (s *staticFieldSelector) GetClusterScope(resource *schema.GroupVersionResource) bool {
	return false
}
func TestPullSingleResource_FieldSelectorDoesNotLeakAcrossIterations(t *testing.T) {
	var capturedSelectors []string

	podList := &unstructured.UnstructuredList{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "PodList",
		},
	}

	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		listAction, ok := action.(k8stesting.ListAction)
		require.True(t, ok)

		capturedSelectors = append(
			capturedSelectors,
			listAction.GetListRestrictions().Fields.String(),
		)

		return true, podList, nil
	})

	resource := &schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "pods",
	}

	fieldSelector := &staticFieldSelector{
		selectors: []string{
			"metadata.namespace=test-ns",
			"",
		},
	}

	_, selectorErrs := handler.pullSingleResource(
		context.Background(),
		resource,
		nil,
		"",
		fieldSelector,
	)

	require.Empty(t, selectorErrs)

	require.Len(t, capturedSelectors, 2)

	assert.Equal(t,
		"metadata.namespace=test-ns",
		capturedSelectors[0],
	)

	assert.Equal(t,
		"",
		capturedSelectors[1],
	)
}

// gvrToListKind registers the GVRs used in these tests so the fake dynamic
// client doesn't panic when List is called on them.
var testGVRToListKind = map[schema.GroupVersionResource]string{
	{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings"}: "ClusterRoleBindingList",
	{Group: "", Version: "v1", Resource: "pods"}:                                         "PodList",
	{Group: "", Version: "v1", Resource: "somecrd"}:                                      "SomeCRDList",
}

// newHandlerWithReactor builds a K8sResourceHandler whose dynamic client
// prepends a reactor so tests can inject per-GVR errors.
func newHandlerWithReactor(t *testing.T, reactor k8stesting.ReactionFunc) *K8sResourceHandler {
	t.Helper()
	client := fakeclientset.NewClientset()
	dynClient := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), testGVRToListKind)
	dynClient.PrependReactor("list", "*", reactor)

	k8s := &k8sinterface.KubernetesApi{
		KubernetesClient: client,
		DynamicClient:    dynClient,
		DiscoveryClient:  client.Discovery(),
		Context:          context.Background(),
	}
	return NewK8sResourceHandler(context.Background(), k8s, nil, nil, "test-cluster")
}

// TestPullResources_NonForbiddenErrorRecorded verifies that a non-404 API error
// (e.g. 403 Forbidden) is recorded in failedQueries so the caller can surface
// the affected control as skipped rather than falsely passed.
func TestPullResources_NonForbiddenErrorRecorded(t *testing.T) {
	forbiddenErr := fmt.Errorf("forbidden: User cannot list clusterrolebindings")

	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenErr
	})

	qrs := QueryableResources{
		"rbac.authorization.k8s.io/v1/clusterrolebindings": QueryableResource{
			GroupVersionResourceTriplet: "rbac.authorization.k8s.io/v1/clusterrolebindings",
		},
	}

	_, _, failedQueries := handler.pullResources(context.Background(), qrs, &EmptySelector{})

	require.Len(t, failedQueries, 1, "expected one failed query entry")
	for _, f := range failedQueries {
		assert.Equal(t, "rbac.authorization.k8s.io/v1/clusterrolebindings", f.gvr)
		assert.ErrorContains(t, f.err, "forbidden")
	}
}

// TestPullResources_NotFoundErrorIgnored verifies that a "server could not find
// the requested resource" error (CRD not installed) is silently ignored and does
// NOT appear in failedQueries — this is expected behaviour when a control
// references an optional CRD that isn't present on the cluster.
func TestPullResources_NotFoundErrorIgnored(t *testing.T) {
	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("the server could not find the requested resource")
	})

	qrs := QueryableResources{
		"/v1/somecrd": QueryableResource{
			GroupVersionResourceTriplet: "/v1/somecrd",
		},
	}

	_, _, failedQueries := handler.pullResources(context.Background(), qrs, &EmptySelector{})

	assert.Empty(t, failedQueries, "404-style errors should not be recorded as failures")
}

// TestPullResources_PartialFailure verifies that when one GVR succeeds and
// another fails, only the failed GVR appears in failedQueries AND the
// successful resource still lands in allResources / k8sResources — proving the
// "scan continues" half of the contract, not just the "error is recorded" half.
func TestPullResources_PartialFailure(t *testing.T) {
	forbiddenGVR := "rbac.authorization.k8s.io/v1/clusterrolebindings"
	podsGVR := "/v1/pods"

	pod := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      "pod-survives",
				"namespace": "default",
			},
		},
	}
	podList := &unstructured.UnstructuredList{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "PodList",
		},
		Items: []unstructured.Unstructured{*pod},
	}

	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetResource().Resource == "clusterrolebindings" {
			return true, nil, fmt.Errorf("forbidden: cannot list clusterrolebindings")
		}
		if action.GetResource().Resource == "pods" {
			return true, podList, nil
		}
		return false, nil, nil
	})

	qrs := QueryableResources{
		forbiddenGVR: QueryableResource{
			GroupVersionResourceTriplet: forbiddenGVR,
		},
		podsGVR: QueryableResource{
			GroupVersionResourceTriplet: podsGVR,
		},
	}

	k8sResources, allResources, failedQueries := handler.pullResources(context.Background(), qrs, &EmptySelector{})

	// failed query is recorded
	assert.Len(t, failedQueries, 1)
	for _, f := range failedQueries {
		assert.Equal(t, forbiddenGVR, f.gvr)
	}

	// successful pod survives in both maps — this is what "scan continues" means
	assert.Len(t, allResources, 1, "the successful pod must still be collected")
	assert.Len(t, k8sResources[podsGVR], 1, "k8sResources[pods] must contain the surviving pod ID")
	for id := range allResources {
		assert.Contains(t, id, "pod-survives")
	}
}

// TestPullResources_TotalFailure verifies that when every query fails,
// failedQueries contains all of them and allResources is empty.
func TestPullResources_TotalFailure(t *testing.T) {
	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("forbidden: no permissions")
	})

	qrs := QueryableResources{
		"rbac.authorization.k8s.io/v1/clusterrolebindings": QueryableResource{
			GroupVersionResourceTriplet: "rbac.authorization.k8s.io/v1/clusterrolebindings",
		},
		"/v1/pods": QueryableResource{
			GroupVersionResourceTriplet: "/v1/pods",
		},
	}

	_, allResources, failedQueries := handler.pullResources(context.Background(), qrs, &EmptySelector{})

	assert.Empty(t, allResources, "no resources should be collected when all queries fail")
	assert.Len(t, failedQueries, 2, "both failed GVRs should be recorded")
}

// TestRecordFailedQueryStatuses_WrittenWhenGVRTotallyAbsent verifies that when
// a GVR fails and k8sResources has no data for it, the helper writes a
// StatusSkipped entry into infoMap so mapControlToInfo can mark the affected
// controls as skipped. Drives the real production helper, not an inlined copy.
func TestRecordFailedQueryStatuses_WrittenWhenGVRTotallyAbsent(t *testing.T) {
	failedGVR := "rbac.authorization.k8s.io/v1/clusterrolebindings"
	infoMap := map[string]apis.StatusInfo{}

	k8sResourcesMap := cautils.K8SResources{
		failedGVR: []string{}, // empty — no successful pull
	}
	failedQueries := map[string]queryFailure{
		failedGVR: {gvr: failedGVR, err: fmt.Errorf("forbidden")},
	}

	partials := recordFailedQueryStatuses(failedQueries, k8sResourcesMap, infoMap)

	info, ok := infoMap[failedGVR]
	require.True(t, ok, "InfoMap should have an entry for the failed GVR")
	assert.Equal(t, apis.StatusSkipped, info.InnerStatus)
	assert.Contains(t, info.InnerInfo, "forbidden")
	assert.Empty(t, partials, "whole-GVR failure should not produce a PartialGVRPull")
}

// TestRecordFailedQueryStatuses_PartialFailureSurfaced verifies the fix for the
// silent false-negative bug: when a GVR failed for one field-selector query but
// another selector for the same GVR succeeded, the failure must NOT be silently
// suppressed. Instead it must be returned as a PartialGVRPull so the operator
// and CI/CD pipelines can detect the incomplete scan.
//
// Prior to the fix, the presence of data in k8sResources[gvr] caused the
// failure to be discarded entirely, leaving controls to evaluate (and silently
// pass) against a truncated resource set.
func TestRecordFailedQueryStatuses_PartialFailureSurfaced(t *testing.T) {
	gvr := "/v1/pods"
	selector := "metadata.namespace==prod"
	infoMap := map[string]apis.StatusInfo{}

	k8sResourcesMap := cautils.K8SResources{
		gvr: []string{"default/pod-abc"}, // data from the successful selector
	}
	failedQueries := map[string]queryFailure{
		gvr + "/" + selector: {gvr: gvr, selector: selector, err: fmt.Errorf("forbidden for prod namespace")},
	}

	partials := recordFailedQueryStatuses(failedQueries, k8sResourcesMap, infoMap)

	// InfoMap must NOT be written — the whole GVR is not absent, so marking
	// it as skipped would incorrectly suppress control evaluation.
	assert.Empty(t, infoMap, "InfoMap must not be written for a partial GVR failure")

	// The failure must be surfaced as a PartialGVRPull — not silently dropped.
	require.Len(t, partials, 1, "partial failure must be returned, not suppressed")
	assert.Equal(t, gvr, partials[0].GVR)
	assert.Equal(t, selector, partials[0].Selector)
	assert.Contains(t, partials[0].Error, "forbidden for prod namespace")
}

// TestRecordFailedQueryStatuses_PartialFailureSessionField verifies that when
// two field-selector queries target the same GVR and one succeeds while the
// other fails, GetResources stores the failure in sessionObj.PartialGVRFailures
// rather than suppressing it silently.
//
// This is the end-to-end regression test for the silent false-negative bug:
// prior to the fix, the presence of data from the first selector caused the
// second selector's failure to be silently discarded, leaving the caller with
// no indication that the resource set is incomplete.
func TestRecordFailedQueryStatuses_PartialFailureSessionField(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	handler := getResourceHandlerMock()

	fakeSecret := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata":   map[string]any{"name": "secret1", "namespace": "default"},
		},
	}
	secretList := &unstructured.UnstructuredList{
		Object: map[string]any{"apiVersion": "v1", "kind": "SecretList"},
		Items:  []unstructured.Unstructured{*fakeSecret},
	}

	handler.k8s.DynamicClient = &mockDynamicClient{
		listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			// First secret selector succeeds; second fails to simulate a
			// per-resource RBAC restriction on a different secret.
			if opts.FieldSelector == "metadata.name=secret1" {
				return secretList, nil
			}
			if opts.FieldSelector == "metadata.name=secret2,metadata.namespace=default" {
				return nil, fmt.Errorf("RBAC denied for secret2")
			}
			// Any other query (e.g. Namespace list) returns empty — not an error.
			return &unstructured.UnstructuredList{Items: []unstructured.Unstructured{}}, nil
		},
	}

	// mockMatch(4) produces two field-selectors for the Secret GVR:
	//   1. metadata.name=secret1  → succeeds
	//   2. metadata.name=secret2,metadata.namespace=default → fails
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
	require.NoError(t, err)

	// The GVR has data (from selector 1), so InfoMap must NOT have a whole-GVR
	// skip entry — that would incorrectly mark the control as NotEvaluated.
	_, inInfoMap := sessionObj.InfoMap["core/v1/secrets"]
	assert.False(t, inInfoMap, "a partially-collected GVR must not appear as a whole-GVR skip in InfoMap")

	// The per-selector failure must surface in PartialGVRFailures so the caller
	// can warn the operator — this is the fix for the silent false-negative.
	require.NotEmpty(t, sessionObj.PartialGVRFailures,
		"the failed selector must be recorded in PartialGVRFailures, not silently dropped")
	assert.Contains(t, sessionObj.PartialGVRFailures[0].Error, "RBAC denied for secret2")
}
