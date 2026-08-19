package resourcehandler

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func queryableResource(triplet, kind string) QueryableResource {
	return QueryableResource{GroupVersionResourceTriplet: triplet, Kind: kind}
}

func kindFilteredQueries(t *testing.T, scanInfo *cautils.ScanInfo, resources ...QueryableResource) []string {
	t.Helper()
	queryable := make(QueryableResources, len(resources))
	for _, resource := range resources {
		queryable.Add(resource)
	}
	filterQueryableResourcesByKind(queryable, scanInfo)

	kept := make([]string, 0, len(queryable))
	for key := range queryable {
		kept = append(kept, key)
	}
	sort.Strings(kept)
	return kept
}

func TestFilterQueryableResourcesByKind(t *testing.T) {
	pods := queryableResource("/v1/pods", "Pod")
	deployments := queryableResource("apps/v1/deployments", "Deployment")
	jobs := queryableResource("batch/v1/jobs", "Job")
	// A resource the resolver could not name a Kind for: no discovery answer.
	sandboxes := queryableResource("agents.x-k8s.io/v1alpha1/sandboxes", "")

	tests := []struct {
		name     string
		scanInfo *cautils.ScanInfo
		want     []string
	}{
		{
			name:     "no filters keeps everything",
			scanInfo: &cautils.ScanInfo{},
			want:     []string{"/v1/pods", "agents.x-k8s.io/v1alpha1/sandboxes", "apps/v1/deployments", "batch/v1/jobs"},
		},
		{
			name:     "include keeps only the listed kinds",
			scanInfo: &cautils.ScanInfo{IncludeKinds: "Deployment"},
			want:     []string{"agents.x-k8s.io/v1alpha1/sandboxes", "apps/v1/deployments"},
		},
		{
			name:     "exclude drops the listed kinds",
			scanInfo: &cautils.ScanInfo{ExcludeKinds: "Job,Pod"},
			want:     []string{"agents.x-k8s.io/v1alpha1/sandboxes", "apps/v1/deployments"},
		},
		{
			name:     "include and exclude both apply",
			scanInfo: &cautils.ScanInfo{IncludeKinds: "Deployment,Job", ExcludeKinds: "Job"},
			want:     []string{"agents.x-k8s.io/v1alpha1/sandboxes", "apps/v1/deployments"},
		},
		{
			name:     "kind matching is case insensitive",
			scanInfo: &cautils.ScanInfo{ExcludeKinds: " DEPLOYMENT "},
			want:     []string{"/v1/pods", "agents.x-k8s.io/v1alpha1/sandboxes", "batch/v1/jobs"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, kindFilteredQueries(t, test.scanInfo, pods, deployments, jobs, sandboxes))
		})
	}
}

// TestFilterQueryableResourcesByKindKeepsFieldSelectorVariants covers the map
// key being the triplet plus its field selectors: every variant of a rejected
// kind has to go, not just the bare one.
func TestFilterQueryableResourcesByKindKeepsFieldSelectorVariants(t *testing.T) {
	scoped := queryableResource("batch/v1/jobs", "Job")
	scoped.AddFieldSelector("metadata.namespace=default")

	kept := kindFilteredQueries(t, &cautils.ScanInfo{ExcludeKinds: "Job"},
		queryableResource("batch/v1/jobs", "Job"), scoped, queryableResource("/v1/pods", "Pod"))

	assert.Equal(t, []string{"/v1/pods"}, kept)
}

func agentRuntimeListKinds() map[schema.GroupVersionResource]string {
	listKinds := map[schema.GroupVersionResource]string{}
	for _, gvr := range []schema.GroupVersionResource{
		{Group: "agents.x-k8s.io", Version: "v1alpha1", Resource: "sandboxes"},
		{Group: "agents.x-k8s.io", Version: "v1beta1", Resource: "sandboxes"},
		{Group: "extensions.agents.x-k8s.io", Version: "v1alpha1", Resource: "sandboxtemplates"},
		{Group: "extensions.agents.x-k8s.io", Version: "v1beta1", Resource: "sandboxtemplates"},
		{Group: "ate.dev", Version: "v1alpha1", Resource: "actortemplates"},
		{Group: "ate.dev", Version: "v1alpha1", Resource: "workerpools"},
	} {
		listKinds[gvr] = "CustomResourceList"
	}
	return listKinds
}

func listedTriplets(actions []k8stesting.Action) []string {
	var listed []string
	for _, action := range actions {
		if action.GetVerb() != "list" {
			continue
		}
		gvr := action.GetResource()
		listed = append(listed, k8sinterface.GroupVersionResourceToString(&gvr))
	}
	sort.Strings(listed)
	return listed
}

func agentRuntimeQueryableResources(t *testing.T, scanInfo *cautils.ScanInfo) QueryableResources {
	t.Helper()
	resolver, discoveryFailures := newDiscoveryResourceResolver(agentRuntimeDiscovery())
	require.Empty(t, discoveryFailures)
	queryable, _ := getQueryableResourceMapFromPolicies(
		[]reporthandling.Framework{agentRuntimeFramework()},
		nil,
		reporthandling.ScopeCluster,
		resolver,
	)
	filterQueryableResourcesByKind(queryable, scanInfo)
	return queryable
}

// TestPullResourcesSkipsKindFilteredQueries is the point of filtering at query
// planning: an excluded kind must never reach the API server, since collection
// is what a scan of a large cluster spends its time on.
func TestPullResourcesSkipsKindFilteredQueries(t *testing.T) {
	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), agentRuntimeListKinds())
	dynamicClient.PrependReactor("list", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &unstructured.UnstructuredList{}, nil
	})
	handler := &K8sResourceHandler{k8s: &k8sinterface.KubernetesApi{DynamicClient: dynamicClient}}

	queryable := agentRuntimeQueryableResources(t, &cautils.ScanInfo{ExcludeKinds: "Sandbox,WorkerPool"})
	_, _, failures := handler.pullResources(context.Background(), queryable, &EmptySelector{}, "")
	require.Empty(t, failures)

	assert.Equal(t, []string{
		"ate.dev/v1alpha1/actortemplates",
		"extensions.agents.x-k8s.io/v1alpha1/sandboxtemplates",
		"extensions.agents.x-k8s.io/v1beta1/sandboxtemplates",
	}, listedTriplets(dynamicClient.Actions()))
}

func TestPullResourcesKeepsOnlyIncludedKindQueries(t *testing.T) {
	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), agentRuntimeListKinds())
	dynamicClient.PrependReactor("list", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &unstructured.UnstructuredList{}, nil
	})
	handler := &K8sResourceHandler{k8s: &k8sinterface.KubernetesApi{DynamicClient: dynamicClient}}

	queryable := agentRuntimeQueryableResources(t, &cautils.ScanInfo{IncludeKinds: "sandbox"})
	_, _, failures := handler.pullResources(context.Background(), queryable, &EmptySelector{}, "")
	require.Empty(t, failures)

	assert.Equal(t, []string{
		"agents.x-k8s.io/v1alpha1/sandboxes",
		"agents.x-k8s.io/v1beta1/sandboxes",
	}, listedTriplets(dynamicClient.Actions()))
}

// TestKindFilteredQueryFailureStaysOutOfScanCoverage is the reported-result half
// of the same bug: a listing that ran anyway could still fail, and a failed pull
// reaches InfoMap, where BuildScanCoverage turns it into a failed GVR pull and
// docks the coverage score over a kind the scan was told to leave out.
func TestKindFilteredQueryFailureStaysOutOfScanCoverage(t *testing.T) {
	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), agentRuntimeListKinds())
	dynamicClient.PrependReactor("list", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &unstructured.UnstructuredList{}, nil
	})
	dynamicClient.PrependReactor("list", "sandboxes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("forbidden: User cannot list sandboxes")
	})
	handler := &K8sResourceHandler{k8s: &k8sinterface.KubernetesApi{DynamicClient: dynamicClient}}

	framework := agentRuntimeFramework()
	resolver, discoveryFailures := newDiscoveryResourceResolver(agentRuntimeDiscovery())
	require.Empty(t, discoveryFailures)
	resourceToControls := map[string][]string{}
	setComplexKSResourceMap([]reporthandling.Framework{framework}, resourceToControls, resolver)
	require.Contains(t, resourceToControls, "agents.x-k8s.io/v1alpha1/sandboxes",
		"the excluded kind is a control dependency, so a failed pull of it would be reported")

	queryable := agentRuntimeQueryableResources(t, &cautils.ScanInfo{ExcludeKinds: "Sandbox"})
	k8sResources, _, failedQueries := handler.pullResources(context.Background(), queryable, &EmptySelector{}, "")

	infoMap := map[string]apis.StatusInfo{}
	require.Empty(t, recordFailedQueryStatuses(failedQueries, k8sResources, infoMap))
	assert.Empty(t, infoMap, "an excluded kind must not be reported as a failed dependency")

	coverage := cautils.BuildScanCoverage(infoMap, resourceToControls, nil, nil, nil)
	coverage.ComputeCoverageScore(1)
	assert.Empty(t, coverage.FailedGVRPulls)
	assert.Empty(t, coverage.NotEvaluatedControls)
	assert.False(t, coverage.Degraded)
}

// TestPreflightSkipsAccessReviewForKindFilteredResource keeps the dry-run in
// step with collection, the same way it already skips unlistable resources: a
// kind the scan will not list must not read as a permission problem.
func TestPreflightSkipsAccessReviewForKindFilteredResource(t *testing.T) {
	client := fakeclientset.NewClientset()
	var reviewed []string
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		ssar := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		reviewed = append(reviewed, ssar.Spec.ResourceAttributes.Resource)
		ssar.Status.Allowed = ssar.Spec.ResourceAttributes.Resource != "sandboxes"
		return true, ssar, nil
	})
	handler := &K8sResourceHandler{k8s: &k8sinterface.KubernetesApi{
		KubernetesClient: client,
		DiscoveryClient:  agentRuntimeDiscovery(),
	}}

	scanInfo := &cautils.ScanInfo{ExcludeKinds: "Sandbox"}
	sessionObj := cautils.NewOPASessionObj(context.Background(), []reporthandling.Framework{agentRuntimeFramework()}, nil, scanInfo, nil)

	result, err := handler.Preflight(context.Background(), sessionObj, scanInfo)
	require.NoError(t, err)

	assert.NotContains(t, reviewed, "sandboxes")
	assert.Empty(t, result.Denied())
	assert.NotEmpty(t, result.Checks)
}
