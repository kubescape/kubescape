package opaprocessor

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
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
	frameworks := []reporthandling.Framework{{Controls: []reporthandling.Control{control}}}
	policies := convertFrameworksToPolicies(
		frameworks,
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
		ConvertFrameworksToSummaryDetails(&opap.Report.SummaryDetails, frameworks, policies)
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

	t.Run("policy projected", func(t *testing.T) {
		t.Setenv("LARGE_CLUSTER_SIZE", "1")
		opap := newProcessor()
		opap.SetWholeClusterPolicy(cautils.WholeClusterPolicyProjected)
		require.NoError(t, opap.Process(context.Background(), policies, nil))
		require.Contains(t, opap.ResourcesResult, podID)
		res := opap.ResourcesResult[podID]
		assert.True(t, res.GetStatus(nil).IsFailed(), "projected policy must detect cross-namespace binding")
	})

	t.Run("policy fallback", func(t *testing.T) {
		t.Setenv("LARGE_CLUSTER_SIZE", "1")
		opap := newProcessor()
		opap.SetWholeClusterPolicy(cautils.WholeClusterPolicyFallback)
		require.NoError(t, opap.Process(context.Background(), policies, nil))
		require.Contains(t, opap.ResourcesResult, podID)
		res := opap.ResourcesResult[podID]
		assert.True(t, res.GetStatus(nil).IsFailed(), "fallback policy must detect cross-namespace binding")
	})

	t.Run("policy skip", func(t *testing.T) {
		t.Setenv("LARGE_CLUSTER_SIZE", "1")
		opap := newProcessor()
		opap.SetWholeClusterPolicy(cautils.WholeClusterPolicySkip)
		require.NoError(t, opap.Process(context.Background(), policies, nil))
		// Control should be skipped, not evaluated
		assert.Contains(t, opap.skippedWholeClusterControls, "C-0261")
		if ctrl, ok := opap.Report.SummaryDetails.Controls["C-0261"]; assert.True(t, ok, "C-0261 must exist in SummaryDetails.Controls") {
			assert.True(t, ctrl.GetStatus().IsSkipped(), "control must have skipped status")
			assert.Equal(t, apis.SubStatusNotEvaluated, ctrl.GetStatus().GetSubStatus())
			assert.Contains(t, ctrl.GetStatus().Info(), "skipped by execution policy")
		}
		if res, ok := opap.ResourcesResult[podID]; ok {
			assert.False(t, res.GetStatus(nil).IsFailed(), "pod must not fail for skipped whole-cluster control")
		}
	})

	t.Run("policy verify", func(t *testing.T) {
		t.Setenv("LARGE_CLUSTER_SIZE", "1")
		opap := newProcessor()
		opap.SetWholeClusterPolicy(cautils.WholeClusterPolicyVerify)
		require.NoError(t, opap.Process(context.Background(), policies, nil))
		require.Contains(t, opap.ResourcesResult, podID)
		res := opap.ResourcesResult[podID]
		assert.True(t, res.GetStatus(nil).IsFailed(), "verify policy must pass parity check and detect failure")
	})
}

// TestProcess_WholeClusterPolicy_NoiseIsolation verifies that when a cluster contains
// hundreds of unrelated resources (ConfigMaps, Secrets), the projected whole-cluster scope
// successfully filters them out and retains only matching resources while catching the join.
func TestProcess_WholeClusterPolicy_NoiseIsolation(t *testing.T) {
	control := saTokenBindingControl("C-0261")
	policies := convertFrameworksToPolicies(
		[]reporthandling.Framework{{Controls: []reporthandling.Control{control}}},
		nil, reporthandling.ScopeCluster,
	)

	const podID = "/v1/ns-a/Pod/app"
	k8sResources, allResources := saTokenBindingFixture()

	// Inject 500 mock ConfigMaps
	for i := 0; i < 500; i++ {
		cmRaw := fmt.Sprintf(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cm-%d","namespace":"ns-a"}}`, i)
		var obj map[string]any
		require.NoError(t, json.Unmarshal([]byte(cmRaw), &obj))
		wl := workloadinterface.NewWorkloadObj(obj)
		allResources[wl.GetID()] = wl
		k8sResources["/v1/configmaps"] = append(k8sResources["/v1/configmaps"], wl.GetID())
	}

	sessionObj := cautils.NewOPASessionObjMock()
	sessionObj.K8SResources = k8sResources
	sessionObj.AllResources = allResources
	opap := NewOPAProcessor(sessionObj, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	opap.AllPolicies = policies
	opap.SetWholeClusterPolicy(cautils.WholeClusterPolicyProjected)

	t.Setenv("LARGE_CLUSTER_SIZE", "1")
	require.NoError(t, opap.Process(context.Background(), policies, nil))
	require.Contains(t, opap.ResourcesResult, podID)
	res := opap.ResourcesResult[podID]
	assert.True(t, res.GetStatus(nil).IsFailed(), "cross-namespace join must fire even with 500 noise configmaps")

	// Verify the projection filtered out ConfigMaps
	matchers := compileWholeClusterMatchers(policies, []string{"C-0261"})
	projected := filterProjectedBatch(k8sResources, nil, allResources, matchers)
	assert.NotContains(t, projected.K8SResources, "/v1/configmaps", "projected batch must not contain configmaps")
	assert.Len(t, projected.AllResources, 3, "projected batch should only retain Pod, ServiceAccount, and RoleBinding")
}

// TestProcessWithStreaming_WholeClusterPolicies verifies that ProcessWithStreaming respects
// all whole-cluster execution policies (projected, fallback, skip, verify).
func TestProcessWithStreaming_WholeClusterPolicies(t *testing.T) {
	control := saTokenBindingControl("C-0261")
	policies := convertFrameworksToPolicies(
		[]reporthandling.Framework{{Controls: []reporthandling.Control{control}}},
		nil, reporthandling.ScopeCluster,
	)

	const podID = "/v1/ns-a/Pod/app"

	runStreamingWithPolicy := func(policy cautils.WholeClusterExecutionPolicy) *OPAProcessor {
		t.Setenv("LARGE_CLUSTER_SIZE", "1")
		k8sResources, allResources := saTokenBindingFixture()
		sessionObj := cautils.NewOPASessionObjMock()
		sessionObj.Policies = []reporthandling.Framework{{Controls: []reporthandling.Control{control}}}

		opap := NewOPAProcessor(sessionObj, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
		opap.AllPolicies = policies
		opap.SetWholeClusterPolicy(policy)

		resident, batches := cautils.PartitionResources(len(allResources), k8sResources, nil, allResources, 1)

		batchChan := make(chan *cautils.ResourceBatch, len(batches)+1)
		errChan := make(chan error, 1)
		close(errChan)
		batchChan <- resident
		for _, batch := range batches {
			batchChan <- batch
		}
		close(batchChan)

		err := opap.ProcessWithStreaming(context.Background(), batchChan, errChan, cautils.NewProgressHandler(""), len(batches))
		require.NoError(t, err)
		return opap
	}

	t.Run("streaming projected", func(t *testing.T) {
		opap := runStreamingWithPolicy(cautils.WholeClusterPolicyProjected)
		require.Contains(t, opap.ResourcesResult, podID)
		res := opap.ResourcesResult[podID]
		assert.True(t, res.GetStatus(nil).IsFailed())
	})

	t.Run("streaming fallback", func(t *testing.T) {
		opap := runStreamingWithPolicy(cautils.WholeClusterPolicyFallback)
		require.Contains(t, opap.ResourcesResult, podID)
		res := opap.ResourcesResult[podID]
		assert.True(t, res.GetStatus(nil).IsFailed())
	})

	t.Run("streaming skip", func(t *testing.T) {
		opap := runStreamingWithPolicy(cautils.WholeClusterPolicySkip)
		assert.Contains(t, opap.skippedWholeClusterControls, "C-0261")
		// Verify coverage accounting
		found := false
		for _, ne := range opap.ScanCoverage.NotEvaluatedControls {
			if ne.ControlID == "C-0261" {
				found = true
				assert.Contains(t, ne.Reason, "policy: skip")
			}
		}
		assert.True(t, found, "C-0261 must be in NotEvaluatedControls when skipped")
	})

	t.Run("streaming verify", func(t *testing.T) {
		opap := runStreamingWithPolicy(cautils.WholeClusterPolicyVerify)
		require.Contains(t, opap.ResourcesResult, podID)
		res := opap.ResourcesResult[podID]
		assert.True(t, res.GetStatus(nil).IsFailed())
	})
}

func TestAppendSkippedWholeClusterControlsToCoverage_DeterministicOrder(t *testing.T) {
	opap := &OPAProcessor{
		OPASessionObj: cautils.NewOPASessionObjMock(),
		skippedWholeClusterControls: map[string]string{
			"C-0272": "skipped 272",
			"C-0261": "skipped 261",
			"C-0266": "skipped 266",
			"C-0267": "skipped 267",
		},
	}
	opap.appendSkippedWholeClusterControlsToCoverage()
	require.Len(t, opap.ScanCoverage.NotEvaluatedControls, 4)
	assert.Equal(t, "C-0261", opap.ScanCoverage.NotEvaluatedControls[0].ControlID)
	assert.Equal(t, "C-0266", opap.ScanCoverage.NotEvaluatedControls[1].ControlID)
	assert.Equal(t, "C-0267", opap.ScanCoverage.NotEvaluatedControls[2].ControlID)
	assert.Equal(t, "C-0272", opap.ScanCoverage.NotEvaluatedControls[3].ControlID)
}

func TestVerifyWholeClusterControl_ReturnsEvaluationErrors(t *testing.T) {
	deployment := mocks.MockDevelopmentWithHostpath()
	k8sResources := make(cautils.K8SResources)
	k8sResources["apps/v1/deployments"] = workloadinterface.ListMetaIDs([]workloadinterface.IMetadata{deployment})

	opaSessionObj := cautils.NewOPASessionObjMock()
	opaSessionObj.K8SResources = k8sResources
	opaSessionObj.AllResources[deployment.GetID()] = deployment
	const controlID = "C-TEST-ERR"
	policies := &cautils.Policies{
		Controls: map[string]reporthandling.Control{
			controlID: {
				PortalBase: armotypes.PortalBase{
					Name: "erroring whole-cluster control",
					Attributes: map[string]any{
						ControlAttributeRequiresWholeClusterInput: true,
					},
				},
				ControlID: controlID,
				Rules: []reporthandling.PolicyRule{
					{
						Rule: "invalid rego syntax (((",
						Match: []reporthandling.RuleMatchObjects{
							{
								APIGroups:   []string{"apps"},
								APIVersions: []string{"v1"},
								Resources:   []string{"Deployment"},
							},
						},
						RuleQuery:    "data",
						RuleLanguage: reporthandling.RegoLanguage,
					},
				},
			},
		},
	}

	opap := NewOPAProcessor(opaSessionObj, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	opap.AllPolicies = policies
	opap.SetWholeClusterPolicy(cautils.WholeClusterPolicyVerify)

	err := opap.Process(context.Background(), policies, nil)
	require.Error(t, err, "verify mode must propagate evaluation errors")
}

func TestVerifyWholeCluster_MismatchDetection(t *testing.T) {
	control := saTokenBindingControl("C-0261")
	policies := convertFrameworksToPolicies(
		[]reporthandling.Framework{{Controls: []reporthandling.Control{control}}},
		nil, reporthandling.ScopeCluster,
	)

	const podID = "/v1/ns-a/Pod/app"
	k8sResources, allResources := saTokenBindingFixture()

	sessionObj := cautils.NewOPASessionObjMock()
	sessionObj.K8SResources = k8sResources
	sessionObj.AllResources = allResources
	opap := NewOPAProcessor(sessionObj, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	opap.AllPolicies = policies

	fallbackScope := opap.wholeClusterScope()

	// Deliberately construct an incomplete projected batch that omits the RoleBinding,
	// so projected evaluates the Pod as passed while fallback evaluates it as failed.
	incompleteBatch := cautils.NewResourceBatch(cautils.ClusterScope)
	incompleteBatch.K8SResources["/v1/pods"] = []string{podID}
	incompleteBatch.AllResources[podID] = allResources[podID]
	projectedScope := newEvaluationScope(cautils.ClusterScope, nil, newResidentIndex(incompleteBatch))

	err := opap.verifyAndProcessWholeCluster(context.Background(), policies, []string{"C-0261"}, projectedScope, fallbackScope, nil)
	require.NoError(t, err, "verify mode logs parity mismatches at error level but does not return an error (exit code 0)")

	// Parity verification records results from projectedScope
	require.Contains(t, opap.ResourcesResult, podID)
	res := opap.ResourcesResult[podID]
	assert.True(t, res.GetStatus(nil).IsPassed(), "projected scope without RoleBinding evaluates to passed")
}

func TestProcess_WholeClusterControl_NoMatchers_FailsClosed(t *testing.T) {
	const controlID = "C-TEST-NOMATCH"
	policies := &cautils.Policies{
		Controls: map[string]reporthandling.Control{
			controlID: {
				PortalBase: armotypes.PortalBase{
					Name: "whole-cluster control with no matchers",
					Attributes: map[string]any{
						ControlAttributeRequiresWholeClusterInput: true,
					},
				},
				ControlID: controlID,
				Rules: []reporthandling.PolicyRule{
					{
						Rule:         saTokenBindingRule,
						RuleQuery:    "armo_builtins",
						RuleLanguage: reporthandling.RegoLanguage,
						Match:        nil,
						DynamicMatch: nil,
					},
				},
			},
		},
	}

	t.Run("process projected policy", func(t *testing.T) {
		k8sResources, allResources := saTokenBindingFixture()
		sessionObj := cautils.NewOPASessionObjMock()
		sessionObj.K8SResources = k8sResources
		sessionObj.AllResources = allResources
		opap := NewOPAProcessor(sessionObj, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
		opap.AllPolicies = policies
		opap.SetWholeClusterPolicy(cautils.WholeClusterPolicyProjected)

		err := opap.Process(context.Background(), policies, nil)
		require.NoError(t, err)
		opap.appendSkippedWholeClusterControlsToCoverage()

		assert.Contains(t, opap.skippedWholeClusterControls, controlID)
		found := false
		for _, ne := range opap.ScanCoverage.NotEvaluatedControls {
			if ne.ControlID == controlID {
				found = true
				assert.Contains(t, ne.Reason, "no Match or DynamicMatch declared for projected evaluation")
				assert.Contains(t, ne.Reason, "policy: projected")
			}
		}
		assert.True(t, found, "control without matchers must be in NotEvaluatedControls (fail closed)")
	})

	t.Run("process verify policy", func(t *testing.T) {
		k8sResources, allResources := saTokenBindingFixture()
		sessionObj := cautils.NewOPASessionObjMock()
		sessionObj.K8SResources = k8sResources
		sessionObj.AllResources = allResources
		opap := NewOPAProcessor(sessionObj, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
		opap.AllPolicies = policies
		opap.SetWholeClusterPolicy(cautils.WholeClusterPolicyVerify)

		err := opap.Process(context.Background(), policies, nil)
		require.NoError(t, err)
		opap.appendSkippedWholeClusterControlsToCoverage()

		assert.Contains(t, opap.skippedWholeClusterControls, controlID)
		found := false
		for _, ne := range opap.ScanCoverage.NotEvaluatedControls {
			if ne.ControlID == controlID {
				found = true
				assert.Contains(t, ne.Reason, "no Match or DynamicMatch declared for projected evaluation")
				assert.Contains(t, ne.Reason, "policy: verify")
			}
		}
		assert.True(t, found, "control without matchers must be in NotEvaluatedControls under verify policy")
	})

	t.Run("streaming projected policy", func(t *testing.T) {
		k8sResources, allResources := saTokenBindingFixture()
		sessionObj := cautils.NewOPASessionObjMock()
		sessionObj.Policies = []reporthandling.Framework{{Controls: []reporthandling.Control{policies.Controls[controlID]}}}

		opap := NewOPAProcessor(sessionObj, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
		opap.AllPolicies = policies
		opap.SetWholeClusterPolicy(cautils.WholeClusterPolicyProjected)

		resident, batches := cautils.PartitionResources(len(allResources), k8sResources, nil, allResources, 1)

		batchChan := make(chan *cautils.ResourceBatch, len(batches)+1)
		errChan := make(chan error, 1)
		close(errChan)
		batchChan <- resident
		for _, batch := range batches {
			batchChan <- batch
		}
		close(batchChan)

		err := opap.ProcessWithStreaming(context.Background(), batchChan, errChan, cautils.NewProgressHandler(""), len(batches))
		require.NoError(t, err)

		assert.Contains(t, opap.skippedWholeClusterControls, controlID)
		found := false
		for _, ne := range opap.ScanCoverage.NotEvaluatedControls {
			if ne.ControlID == controlID {
				found = true
				assert.Contains(t, ne.Reason, "no Match or DynamicMatch declared for projected evaluation")
			}
		}
		assert.True(t, found, "control without matchers must be in NotEvaluatedControls for streaming")
	})
}
