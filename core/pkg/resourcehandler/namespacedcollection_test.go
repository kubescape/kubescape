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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

var namespacedPodsGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

// clusterScopeForbidden is the error a real API server returns for a
// cluster-scoped LIST from a caller holding only a namespaced Role.
type clusterScopeForbidden struct{}

func (clusterScopeForbidden) Error() string {
	return `User "system:serviceaccount:team-a:scanner" cannot list resource "pods" in API group "" at the cluster scope`
}

// namespaceScopedRBACReactor models a caller holding only a Role+RoleBinding in
// "team-a", exactly as the Kubernetes RBAC authorizer behaves:
//
//   - a request to the cluster-scoped collection endpoint (GET /api/v1/pods)
//     resolves with requestInfo.Namespace == "", so only ClusterRoleBindings are
//     consulted and it is denied. The fieldSelector on the request is applied
//     after authorization and never enters the decision.
//   - a request to the namespaced endpoint (GET /api/v1/namespaces/team-a/pods)
//     resolves with requestInfo.Namespace == "team-a" and the Role allows it.
func namespaceScopedRBACReactor(endpoints *[]string) k8stesting.ReactionFunc {
	return func(action k8stesting.Action) (bool, runtime.Object, error) {
		ns := action.GetNamespace()
		*endpoints = append(*endpoints, ns)
		if ns != "team-a" {
			return true, nil, apierrors.NewForbidden(namespacedPodsGVR.GroupResource(), "", clusterScopeForbidden{})
		}
		return true, &unstructured.UnstructuredList{Items: []unstructured.Unstructured{{Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata":   map[string]any{"name": "api", "namespace": "team-a"},
			"spec":       map[string]any{"hostNetwork": true},
		}}}}, nil
	}
}

// TestIncludeNamespacesIssuesNamespacedList pins that --include-namespaces
// addresses each namespace's own collection endpoint, which Kubernetes
// authorizes against a namespaced Role, instead of narrowing a cluster-scoped
// LIST by field selector. The endpoint already restricts the result set, so the
// query carries no metadata.namespace selector of its own.
func TestIncludeNamespacesIssuesNamespacedList(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()

	type observed struct{ ns, field string }
	var seen []observed

	handler := newHandlerWithReactor(t, func(action k8stesting.Action) (bool, runtime.Object, error) {
		if la, ok := action.(k8stesting.ListAction); ok {
			seen = append(seen, observed{action.GetNamespace(), la.GetListRestrictions().Fields.String()})
		}
		return true, &unstructured.UnstructuredList{}, nil
	})

	namespaced := true
	handler.pullSingleResource(context.Background(), &namespacedPodsGVR, "", "", NewIncludeSelector("team-a,team-b"), &namespaced)

	require.Len(t, seen, 2, "one query per included namespace")
	for _, o := range seen {
		t.Logf("LIST -> endpoint namespace=%q fieldSelector=%q", o.ns, o.field)
		assert.Empty(t, o.field, "the namespaced endpoint already scopes the query")
	}
	assert.Equal(t, "team-a", seen[0].ns)
	assert.Equal(t, "team-b", seen[1].ns)
}

// TestNamespaceScopedRBACCollectsResources is the reason this exists: a caller
// holding only a Role in team-a, scanning exactly team-a, collects its
// resources. Against the same simulated RBAC a cluster-scoped LIST is denied.
func TestNamespaceScopedRBACCollectsResources(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()

	var endpoints []string
	handler := newHandlerWithReactor(t, namespaceScopedRBACReactor(&endpoints))

	namespaced := true
	collected, errs := handler.pullSingleResource(
		context.Background(), &namespacedPodsGVR, "", "", NewIncludeSelector("team-a"), &namespaced)

	t.Logf("endpoint namespaces hit: %q", endpoints)
	t.Logf("resources collected: %d, selector failures: %d", len(collected), len(errs))
	for _, e := range errs {
		t.Logf("failure: %v", e.err)
	}

	require.Empty(t, errs, "the namespaced endpoint is authorized by the Role")
	require.Len(t, collected, 1)
	assert.Equal(t, []string{"team-a"}, endpoints)
	assert.Equal(t, "api", collected[0].GetName())
}

// TestPreflightReviewsRequestedNamespace pins that --dry-run reviews access at
// the scope collection will use, so a caller who can list pods in the namespace
// they asked to scan is reported as allowed.
func TestPreflightReviewsRequestedNamespace(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()

	var reviewedNamespaces []string
	client := fakeclientset.NewClientset()
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		ssar := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		reviewedNamespaces = append(reviewedNamespaces, ssar.Spec.ResourceAttributes.Namespace)
		// The caller holds a Role in team-a only: allowed there, denied cluster-wide.
		allowed := ssar.Spec.ResourceAttributes.Namespace == "team-a"
		ssar.Status = authorizationv1.SubjectAccessReviewStatus{
			Allowed: allowed,
			Denied:  !allowed,
			Reason:  "no ClusterRoleBinding grants cluster-scoped list",
		}
		return true, ssar, nil
	})

	handler := &K8sResourceHandler{k8s: &k8sinterface.KubernetesApi{
		KubernetesClient: client,
		DiscoveryClient:  client.Discovery(),
		Context:          context.Background(),
	}}

	check := handler.checkListAccess(context.Background(), "/v1/pods", []string{"team-a"}, nil)

	t.Logf("SelfSubjectAccessReview namespaces reviewed: %q", reviewedNamespaces)
	t.Logf("preflight verdict for /v1/pods -> allowed=%v reason=%q", check.Allowed, check.Reason)

	require.Equal(t, []string{"team-a"}, reviewedNamespaces)
	assert.True(t, check.Allowed, "the namespace the scan will address is allowed")

	clusterCheck := handler.checkListAccess(context.Background(), "/v1/pods", nil, nil)
	assert.False(t, clusterCheck.Allowed, "cluster scope stays denied for the same caller")
}

// TestGetResourcesSucceedsUnderNamespaceScopedRBAC is the scan-level outcome: a
// full collection pass for a framework that needs Pods, run by a caller holding
// only a Role in team-a and asking to scan team-a, completes and collects the
// namespace's resources.
func TestGetResourcesSucceedsUnderNamespaceScopedRBAC(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()

	var endpoints []string
	handler := newHandlerWithReactor(t, namespaceScopedRBACReactor(&endpoints))

	podMatch := reporthandling.RuleMatchObjects{
		APIGroups:   []string{""},
		APIVersions: []string{"v1"},
		Resources:   []string{"Pod"},
	}
	rule := mockRule("rule-a", []reporthandling.RuleMatchObjects{podMatch}, "")
	control := mockControl("control-1", []reporthandling.PolicyRule{rule})
	framework := mockFramework("test", []reporthandling.Control{control})

	scanInfo := &cautils.ScanInfo{IncludeNamespaces: "team-a"}
	sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	sessionObj.Policies = append(sessionObj.Policies, *framework)

	_, allResources, _, _, err := handler.GetResources(context.Background(), sessionObj, scanInfo)

	t.Logf("endpoint namespaces hit: %q", endpoints)
	t.Logf("resources collected: %d", len(allResources))

	require.NoError(t, err, "the scan proceeds under namespace-scoped RBAC")
	require.NotEmpty(t, allResources)
	for _, ns := range endpoints {
		assert.Equal(t, "team-a", ns, "every query addresses the requested namespace")
	}
}
