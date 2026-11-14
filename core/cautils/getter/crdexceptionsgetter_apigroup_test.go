package getter

import (
	"context"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Exercise CRD conversion and the same result exception application used by scans.
// An empty apiGroup is a core-group constraint; an omitted apiGroup is unscoped.
func TestCRDExceptions_ApiGroup(t *testing.T) {
	tests := []struct {
		name       string
		resource   map[string]any
		apiVersion string
		kind       string
		namespace  string
		selector   map[string]any
		labels     map[string]any
		wantMatch  bool
	}{
		{name: "named group matches", resource: map[string]any{"apiGroup": "apps", "kind": "Deployment"}, apiVersion: "apps/v1", kind: "Deployment", wantMatch: true},
		{name: "group alone matches", resource: map[string]any{"apiGroup": "apps"}, apiVersion: "apps/v1", kind: "Deployment", wantMatch: true},
		{name: "different group does not match", resource: map[string]any{"apiGroup": "batch", "kind": "Deployment"}, apiVersion: "apps/v1", kind: "Deployment"},
		{name: "version is not a group", resource: map[string]any{"apiGroup": "apps/v1"}, apiVersion: "apps/v1", kind: "Deployment"},
		{name: "regex group matches", resource: map[string]any{"apiGroup": "app.*"}, apiVersion: "apps/v1", kind: "Deployment", wantMatch: true},
		{name: "explicit core group matches", resource: map[string]any{"apiGroup": ""}, apiVersion: "v1", kind: "Pod", wantMatch: true},
		{name: "explicit core group excludes named group", resource: map[string]any{"apiGroup": ""}, apiVersion: "apps/v1", kind: "Deployment"},
		{name: "explicit core group constrains kind", resource: map[string]any{"apiGroup": "", "kind": "Deployment"}, apiVersion: "apps/v1", kind: "Deployment"},
		{name: "omitted group matches named group", resource: map[string]any{"kind": "Deployment"}, apiVersion: "apps/v1", kind: "Deployment", wantMatch: true},
		{name: "omitted group matches core group", resource: map[string]any{"kind": "Pod"}, apiVersion: "v1", kind: "Pod", wantMatch: true},
		{name: "group and selector match", resource: map[string]any{"apiGroup": "apps"}, apiVersion: "apps/v1", kind: "Deployment", selector: map[string]any{"matchLabels": map[string]any{"app": "web"}}, labels: map[string]any{"app": "web"}, wantMatch: true},
		{name: "group does not bypass selector", resource: map[string]any{"apiGroup": "apps"}, apiVersion: "apps/v1", kind: "Deployment", selector: map[string]any{"matchLabels": map[string]any{"app": "web"}}, labels: map[string]any{"app": "worker"}},
		{name: "label cannot impersonate group", resource: map[string]any{"apiGroup": "batch"}, apiVersion: "apps/v1", kind: "Deployment", labels: map[string]any{"apiGroup": "batch"}},
		{name: "another namespace", resource: map[string]any{"apiGroup": "apps"}, apiVersion: "apps/v1", kind: "Deployment", namespace: "team-b", wantMatch: true},
	}
	for _, crdKind := range []string{"SecurityException", "ClusterSecurityException"} {
		t.Run(crdKind, func(t *testing.T) {
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					match := map[string]any{"resources": []any{tc.resource}}
					if tc.selector != nil {
						match["objectSelector"] = tc.selector
					}
					policies := apiGroupCRDPolicies(t, crdKind, match)
					require.Len(t, policies[0].Resources, 1)
					group, present := policies[0].Resources[0].Attributes[identifiers.AttributeApiGroup]
					wantGroup, wantPresent := tc.resource["apiGroup"]
					assert.Equal(t, wantPresent, present)
					if wantPresent {
						assert.Equal(t, wantGroup, group)
					}
					namespace := tc.namespace
					if namespace == "" {
						namespace = "team-a"
					}
					metadata := map[string]any{"name": "web", "namespace": namespace}
					if tc.labels != nil {
						metadata["labels"] = tc.labels
					}
					workload := objectsenvelopes.NewObject(map[string]any{
						"apiVersion": tc.apiVersion, "kind": tc.kind, "metadata": metadata,
					})
					require.NotNil(t, workload)
					result := failingApiGroupResult()
					result.SetExceptions(workload, policies, "cluster-a", map[string]reporthandling.Control{"C-0001": {ControlID: "C-0001"}})
					wantMatch := tc.wantMatch && (crdKind == "ClusterSecurityException" || namespace == "team-a")
					assert.Equal(t, wantMatch, result.GetStatus(nil).IsPassed())
					assert.Equal(t, wantMatch, len(result.AssociatedControls[0].ResourceAssociatedRules[0].Exception) > 0)
				})
			}
		})
	}
}

// TestCRDExceptions_ApiGroupRBACSubject checks subjects with a bare API group.
func TestCRDExceptions_ApiGroupRBACSubject(t *testing.T) {
	vector, err := objectsenvelopes.NewRegoResponseVectorObjectFromBytes([]byte(`{"apiGroup":"rbac.authorization.k8s.io","kind":"Group","name":"system:masters","relatedObjects":[{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"cluster-admin"}}]}`))
	require.NoError(t, err)
	for _, group := range []string{"rbac.authorization.k8s.io", "apps", ""} {
		t.Run("group="+group, func(t *testing.T) {
			policies := apiGroupCRDPolicies(t, "ClusterSecurityException", map[string]any{
				"resources": []any{map[string]any{"apiGroup": group, "kind": "Group", "name": "system:masters"}},
			})
			result := failingApiGroupResult()
			result.SetExceptions(vector, policies, "cluster-a", map[string]reporthandling.Control{"C-0001": {ControlID: "C-0001"}})
			assert.Equal(t, group == "rbac.authorization.k8s.io", result.GetStatus(nil).IsPassed())
		})
	}
}

// TestDeduplicateExceptions_ExplicitCoreApiGroup preserves broader CRD scopes
// when the primary exception is restricted to the core group.
func TestDeduplicateExceptions_ExplicitCoreApiGroup(t *testing.T) {
	coreOnly := apiGroupCRDPolicies(t, "ClusterSecurityException", map[string]any{"resources": []any{map[string]any{"apiGroup": "", "name": "web"}}})
	unscoped := apiGroupCRDPolicies(t, "ClusterSecurityException", map[string]any{"resources": []any{map[string]any{"name": "web"}}})
	// The primary's core-only scope cannot cover the CRD's named-group resources.
	merged := deduplicateExceptions(coreOnly, unscoped)
	require.Len(t, merged, 2)
	workload := objectsenvelopes.NewObject(map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "web"}})
	result := failingApiGroupResult()
	result.SetExceptions(workload, merged, "cluster-a", map[string]reporthandling.Control{"C-0001": {ControlID: "C-0001"}})
	assert.True(t, result.GetStatus(nil).IsPassed())
	require.Len(t, deduplicateExceptions(coreOnly, coreOnly), 1, "identical core-group scopes still deduplicate")
	require.Len(t, deduplicateExceptions(unscoped, coreOnly), 1, "an unconstrained primary still covers the core group")
	require.Contains(t, coreOnly[0].Resources[0].Attributes, identifiers.AttributeApiGroup, "deduplication must not remove the original constraint")
}

// TestDeduplicateExceptions_ApiGroupPrimaryPrecedence keeps the primary action
// authoritative when a CRD narrows an otherwise identical designator by API group.
func TestDeduplicateExceptions_ApiGroupPrimaryPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		apiGroup   string
		apiVersion string
		kind       string
	}{
		{name: "named group", apiGroup: "apps", apiVersion: "apps/v1", kind: "Deployment"},
		{name: "core group", apiGroup: "", apiVersion: "v1", kind: "Pod"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			primary := apiGroupCRDPolicies(t, "ClusterSecurityException", map[string]any{"resources": []any{map[string]any{"name": "web"}}})
			primary[0].Name = "primary"
			primary[0].Actions = []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly}
			crd := apiGroupCRDPolicies(t, "ClusterSecurityException", map[string]any{"resources": []any{map[string]any{"apiGroup": tc.apiGroup, "name": "web"}}})
			crd[0].Name = "crd"
			require.Equal(t, []armotypes.PostureExceptionPolicyActions{armotypes.Disable}, crd[0].Actions)

			merged := deduplicateExceptions(primary, crd)
			assert.Len(t, merged, 1, "the narrower CRD must not override the primary action")
			workload := objectsenvelopes.NewObject(map[string]any{
				"apiVersion": tc.apiVersion, "kind": tc.kind, "metadata": map[string]any{"name": "web"},
			})
			result := failingApiGroupResult()
			result.SetExceptions(workload, merged, "cluster-a", map[string]reporthandling.Control{"C-0001": {ControlID: "C-0001"}})
			assert.True(t, result.GetStatus(nil).IsFailed(), "AlertOnly must acknowledge the finding without suppressing it")
			matched := result.AssociatedControls[0].ResourceAssociatedRules[0].Exception
			require.Len(t, matched, 1, "only the primary should contribute an exception match")
			assert.Equal(t, "primary", matched[0].Name)
			assert.Equal(t, tc.apiGroup, crd[0].Resources[0].Attributes[identifiers.AttributeApiGroup], "deduplication must preserve the original designator")
		})
	}
}

// apiGroupCRDPolicies converts an ignore-action CRD with the supplied match scope.
func apiGroupCRDPolicies(t *testing.T, kind string, match map[string]any) []armotypes.PostureExceptionPolicy {
	t.Helper()
	metadata := map[string]any{"name": "group-exception"}
	if kind == "SecurityException" {
		metadata["namespace"] = "team-a"
	}
	policies, err := convertCRDObjectToPosturePolicies(context.Background(), &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "kubescape.io/v1beta1", "kind": kind, "metadata": metadata,
		"spec": map[string]any{"match": match, "posture": []any{map[string]any{"controlID": "C-0001", "action": "ignore"}}},
	}}, kind, nil)
	require.NoError(t, err)
	require.Len(t, policies, 1)
	return policies
}

// failingApiGroupResult supplies a failed finding for exception application tests.
func failingApiGroupResult() resourcesresults.Result {
	return resourcesresults.Result{AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
		ControlID:               "C-0001",
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Name: "test-rule", Status: apis.StatusFailed}},
	}}}
}
