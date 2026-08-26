package resourcehandler

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	discoveryfake "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// unlistableAgentDiscovery mixes resources a scan can collect with endpoints the
// API server only serves for "create", plus one resource whose verbs discovery
// did not report at all.
func unlistableAgentDiscovery() *discoveryfake.FakeDiscovery {
	client := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	client.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "agents.x-k8s.io/v1alpha1",
			APIResources: []metav1.APIResource{
				{Name: "sandboxes", Kind: "Sandbox", Namespaced: true, Verbs: metav1.Verbs{"get", "list", "watch"}},
				{Name: "sandboxexecs", Kind: "SandboxExec", Namespaced: true, Verbs: metav1.Verbs{"create"}},
				{Name: "sandboxreports", Kind: "SandboxReport", Namespaced: true},
			},
		},
		{
			GroupVersion: "authentication.k8s.io/v1",
			APIResources: []metav1.APIResource{
				{Name: "tokenreviews", Kind: "TokenReview", Verbs: metav1.Verbs{"create"}},
			},
		},
	}
	return client
}

func TestDiscoveryResolverSkipsResourceWithoutListVerb(t *testing.T) {
	resolver, failures := newDiscoveryResourceResolver(unlistableAgentDiscovery())
	require.Empty(t, failures)

	assert.Empty(t, resolver("agents.x-k8s.io", "v1alpha1", "SandboxExec"))
	assert.Empty(t, resolver("agents.x-k8s.io", "v1alpha1", "sandboxexecs"))

	resolved := resolver("agents.x-k8s.io", "v1alpha1", "Sandbox")
	require.Len(t, resolved, 1)
	assert.Equal(t, "agents.x-k8s.io/v1alpha1/sandboxes", resolved[0].groupVersionResourceTriplet)
}

// TestDiscoveryResolverKeepsResourceWithUnreportedVerbs pins the compatibility
// rule: an empty verb set is missing data, not a declaration that the resource
// cannot be listed.
func TestDiscoveryResolverKeepsResourceWithUnreportedVerbs(t *testing.T) {
	resolver, failures := newDiscoveryResourceResolver(unlistableAgentDiscovery())
	require.Empty(t, failures)

	resolved := resolver("agents.x-k8s.io", "v1alpha1", "SandboxReport")
	require.Len(t, resolved, 1)
	assert.Equal(t, "agents.x-k8s.io/v1alpha1/sandboxreports", resolved[0].groupVersionResourceTriplet)
}

// TestDiscoveryResolverDoesNotFallBackToBuiltInForUnlistableResource guards the
// fallback order: k8s-interface knows a GVR for create-only built-ins, so a
// resource skipped for lacking "list" must not be resurrected by it.
func TestDiscoveryResolverDoesNotFallBackToBuiltInForUnlistableResource(t *testing.T) {
	builtIn := defaultResourceResolver("authentication.k8s.io", "v1", "tokenreviews")
	require.Len(t, builtIn, 1, "k8s-interface resolves tokenreviews, so the fallback would fire")

	resolver, failures := newDiscoveryResourceResolver(unlistableAgentDiscovery())
	require.Empty(t, failures)
	assert.Empty(t, resolver("authentication.k8s.io", "v1", "tokenreviews"))
}

func TestDiscoveryResolverWildcardExcludesUnlistableResources(t *testing.T) {
	resolver, failures := newDiscoveryResourceResolver(unlistableAgentDiscovery())
	require.Empty(t, failures)

	var triplets []string
	for _, resolved := range resolver("*", "*", "*") {
		triplets = append(triplets, resolved.groupVersionResourceTriplet)
	}
	assert.Equal(t, []string{
		"agents.x-k8s.io/v1alpha1/sandboxes",
		"agents.x-k8s.io/v1alpha1/sandboxreports",
	}, triplets)
}

// TestPullResourcesSkipsUnlistableResourceInWildcardScan is the end-to-end
// guarantee: a wildcard policy must not turn a create-only endpoint into a LIST
// that can only fail.
func TestPullResourcesSkipsUnlistableResourceInWildcardScan(t *testing.T) {
	// Every discovered resource is registered so an unwanted query is reported
	// by the assertion below rather than by a fake-client panic.
	listKinds := map[schema.GroupVersionResource]string{
		{Group: "agents.x-k8s.io", Version: "v1alpha1", Resource: "sandboxes"}:      "CustomResourceList",
		{Group: "agents.x-k8s.io", Version: "v1alpha1", Resource: "sandboxreports"}: "CustomResourceList",
		{Group: "agents.x-k8s.io", Version: "v1alpha1", Resource: "sandboxexecs"}:   "CustomResourceList",
		{Group: "authentication.k8s.io", Version: "v1", Resource: "tokenreviews"}:   "TokenReviewList",
	}
	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds)
	dynamicClient.PrependReactor("list", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &unstructured.UnstructuredList{}, nil
	})
	handler := &K8sResourceHandler{k8s: &k8sinterface.KubernetesApi{
		DynamicClient:   dynamicClient,
		DiscoveryClient: unlistableAgentDiscovery(),
	}}

	resolver, discoveryFailures := newDiscoveryResourceResolver(handler.k8s.DiscoveryClient)
	require.Empty(t, discoveryFailures)
	rule := mockRule("wildcard-rule", []reporthandling.RuleMatchObjects{{
		APIGroups:   []string{"*"},
		APIVersions: []string{"*"},
		Resources:   []string{"*"},
	}}, "")
	control := mockControl("C-0001", []reporthandling.PolicyRule{rule})
	framework := mockFramework("wildcard-framework", []reporthandling.Control{control})

	queryable, _ := getQueryableResourceMapFromPolicies(
		[]reporthandling.Framework{*framework},
		nil,
		reporthandling.ScopeCluster,
		resolver,
	)
	_, _, failures := handler.pullResources(context.Background(), queryable, &EmptySelector{}, "")
	assert.Empty(t, failures)

	queried := map[string]struct{}{}
	for _, action := range dynamicClient.Actions() {
		if action.GetVerb() == "list" {
			gvr := action.GetResource()
			queried[k8sinterface.GroupVersionResourceToString(&gvr)] = struct{}{}
		}
	}
	assert.Equal(t, map[string]struct{}{
		"agents.x-k8s.io/v1alpha1/sandboxes":      {},
		"agents.x-k8s.io/v1alpha1/sandboxreports": {},
	}, queried)
}

// TestPreflightSkipsAccessReviewForUnlistableResource keeps the dry-run check in
// step with collection: a resource the scan will never list must not be reported
// as a permission problem.
func TestPreflightSkipsAccessReviewForUnlistableResource(t *testing.T) {
	client := fakeclientset.NewClientset()
	var reviewed []string
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		ssar := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		reviewed = append(reviewed, ssar.Spec.ResourceAttributes.Resource)
		ssar.Status.Allowed = true
		return true, ssar, nil
	})
	handler := &K8sResourceHandler{k8s: &k8sinterface.KubernetesApi{
		KubernetesClient: client,
		DiscoveryClient:  unlistableAgentDiscovery(),
	}}

	matches := []reporthandling.RuleMatchObjects{{
		APIGroups:   []string{"agents.x-k8s.io"},
		APIVersions: []string{"v1alpha1"},
		Resources:   []string{"Sandbox", "SandboxExec"},
	}}
	rule := mockRule("agent-rule", matches, "")
	control := mockControl("C-0001", []reporthandling.PolicyRule{rule})
	framework := mockFramework("agent-framework", []reporthandling.Control{control})

	scanInfo := &cautils.ScanInfo{}
	sessionObj := cautils.NewOPASessionObj(context.Background(), []reporthandling.Framework{*framework}, nil, scanInfo, nil)

	result, err := handler.Preflight(context.Background(), sessionObj, scanInfo)
	require.NoError(t, err)
	assert.Equal(t, []string{"sandboxes"}, reviewed)
	require.Len(t, result.Checks, 1)
	assert.Equal(t, "agents.x-k8s.io/v1alpha1/sandboxes", result.Checks[0].GVR)
}

func TestIsExplicitPolicyMatch(t *testing.T) {
	assert.True(t, isExplicitPolicyMatch("agents.x-k8s.io", "v1alpha1", "Sandbox"))
	assert.True(t, isExplicitPolicyMatch("", "v1", "Pod"))
	assert.False(t, isExplicitPolicyMatch("*", "v1alpha1", "Sandbox"))
	assert.False(t, isExplicitPolicyMatch("agents.x-k8s.io", "*", "Sandbox"))
	assert.False(t, isExplicitPolicyMatch("agents.x-k8s.io", "v1alpha1", "*"))
}
