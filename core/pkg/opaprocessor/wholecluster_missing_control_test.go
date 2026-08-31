package opaprocessor

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// saTokenBindingRule mirrors the shape of C-0261's real has_service_account_binding
// logic: it fails a Pod whose (default) ServiceAccount is named as a subject by
// any RoleBinding in the input, regardless of which namespace that RoleBinding
// itself lives in. A RoleBinding legally binds a ServiceAccount subject from a
// different namespace than its own metadata.namespace.
//
//nolint:gosec // G101: this is a Rego rule fixture, not a hardcoded credential
const saTokenBindingRule = `package armo_builtins

deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    sa := input[_]
    sa.kind == "ServiceAccount"
    sa.metadata.name == "default"
    sa.metadata.namespace == pod.metadata.namespace

    rb := input[_]
    rb.kind == "RoleBinding"
    subject := rb.subjects[_]
    subject.kind == "ServiceAccount"
    subject.name == sa.metadata.name
    subject.namespace == sa.metadata.namespace

    msga := {
        "alertMessage": "pod's default service account is bound via a RoleBinding",
        "packagename":  "armo_builtins",
        "alertScore":   9,
        "fixPaths":     [],
        "failedPaths":  [],
        "alertObject":  {"k8sApiObjects": [pod]},
    }
}
`

// saTokenBindingFixture places the workload and its ServiceAccount in ns-a, and
// the RoleBinding that actually grants that ServiceAccount elevated access in
// ns-b — the standard cross-namespace RBAC pattern C-0261 has to catch.
func saTokenBindingFixture() (cautils.K8SResources, map[string]workloadinterface.IMetadata) {
	raw := []string{
		`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"ns-a"}}`,
		`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"ns-b"}}`,
		`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"app","namespace":"ns-a"},"spec":{"containers":[{"name":"app","image":"nginx"}]}}`,
		`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"default","namespace":"ns-a"}}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"grant","namespace":"ns-b"},"subjects":[{"kind":"ServiceAccount","name":"default","namespace":"ns-a"}],"roleRef":{"kind":"ClusterRole","name":"admin"}}`,
	}

	k8sResources := make(cautils.K8SResources)
	allResources := make(map[string]workloadinterface.IMetadata, len(raw))
	for _, item := range raw {
		object := make(map[string]any)
		if err := json.Unmarshal([]byte(item), &object); err != nil {
			panic(err)
		}
		workload := workloadinterface.NewWorkloadObj(object)
		allResources[workload.GetID()] = workload

		var groupResource string
		switch workload.GetKind() {
		case "Namespace":
			groupResource = "/v1/namespaces"
		case "Pod":
			groupResource = "/v1/pods"
		case "ServiceAccount":
			groupResource = "/v1/serviceaccounts"
		case "RoleBinding":
			groupResource = "rbac.authorization.k8s.io/v1/rolebindings"
		}
		k8sResources[groupResource] = append(k8sResources[groupResource], workload.GetID())
	}
	return k8sResources, allResources
}

func saTokenBindingControl(controlID string) reporthandling.Control {
	control := reporthandling.Control{ControlID: controlID}
	control.Name = "SA token bound via cross-namespace RoleBinding"
	control.Rules = []reporthandling.PolicyRule{
		{
			Rule:         saTokenBindingRule,
			RuleLanguage: reporthandling.RegoLanguage,
			Match: []reporthandling.RuleMatchObjects{
				{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod", "ServiceAccount"}},
				{APIGroups: []string{"rbac.authorization.k8s.io"}, APIVersions: []string{"v1"}, Resources: []string{"RoleBinding"}},
			},
		},
	}
	control.Rules[0].Name = "sa-token-binding-rule"
	return control
}

// TestControlRequiresWholeClusterInput_C0261 pins C-0261 in
// wholeClusterControlIDsFallback: it has the same "workload/ServiceAccount +
// RoleBinding, no resourcesAggregator" shape as C-0266/C-0267/C-0272, which are
// already in the map.
func TestControlRequiresWholeClusterInput_C0261(t *testing.T) {
	control := &reporthandling.Control{ControlID: "C-0261"}
	assert.True(t, controlRequiresWholeClusterInput(control),
		"C-0261 (SA token auto-mount bound via cross-namespace RoleBinding) needs whole-cluster input, same as C-0266/C-0267/C-0272")
}

// TestProcess_C0261ShapedControlCatchesCrossNamespaceBinding verifies that a
// control built with C-0261's real join shape reaches the same verdict
// whether the cluster is evaluated as one scope or partitioned per namespace
// (the eager large-cluster path): the RoleBinding that grants access lives in
// a different namespace batch than the Pod/ServiceAccount it targets, so
// without the whole-cluster deferral the partitioned pass would never see it.
func TestProcess_C0261ShapedControlCatchesCrossNamespaceBinding(t *testing.T) {
	control := saTokenBindingControl("C-0261")
	policies := convertFrameworksToPolicies(
		[]reporthandling.Framework{{Controls: []reporthandling.Control{control}}},
		nil, reporthandling.ScopeCluster,
	)

	const podID = "/v1/ns-a/Pod/app"

	newProcessor := func() *OPAProcessor {
		k8sResources, allResources := saTokenBindingFixture()
		sessionObj := cautils.NewOPASessionObjMock()
		sessionObj.K8SResources = k8sResources
		sessionObj.AllResources = allResources
		opap := NewOPAProcessor(sessionObj, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
		opap.AllPolicies = policies
		return opap
	}

	t.Run("single scope", func(t *testing.T) {
		t.Setenv("LARGE_CLUSTER_SIZE", "100000")
		opap := newProcessor()
		require.NoError(t, opap.Process(context.Background(), policies, nil))
		require.Contains(t, opap.ResourcesResult, podID)
		singleResult := opap.ResourcesResult[podID]
		assert.True(t, singleResult.GetStatus(nil).IsFailed(),
			"a single input holds both namespaces, so the RoleBinding join fires")
	})

	t.Run("partitioned eager", func(t *testing.T) {
		t.Setenv("LARGE_CLUSTER_SIZE", "1")
		opap := newProcessor()
		require.Greater(t, len(opap.evaluationScopes()), 1, "fixture must be split into per-namespace scopes")
		require.NoError(t, opap.Process(context.Background(), policies, nil))
		require.Contains(t, opap.ResourcesResult, podID)
		partitionedResult := opap.ResourcesResult[podID]
		assert.True(t, partitionedResult.GetStatus(nil).IsFailed(),
			"whole-cluster control must be evaluated once after the scopes merge, so the cross-namespace binding is still caught")
	})
}
