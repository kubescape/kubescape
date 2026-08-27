package opaprocessor

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Parity harness for scope-partitioned evaluation.
//
// Process visits scopes in the outer loop and controls in the inner one, so a
// resource that is part of several scopes accumulates its verdict through
// mergeAssociatedControls instead of through a single result map owned by one
// rule. These tests pin that the rearrangement is observationally equivalent:
//
//   - against the previous evaluation order (control-outer, rule-outer), and
//   - against evaluating the whole cluster as one scope, which is what
//     clusters below the large-cluster threshold still do.

// crossScopeRule fails every ClusterRole in its input and reports a path
// naming the namespace of a Pod that shares the input. It therefore produces a
// different verdict per namespace scope for the same cluster-scoped resource,
// which is the case cross-scope merging has to get right.
const crossScopeRule = `package armo_builtins

deny[msga] {
    cr := input[_]
    cr.kind == "ClusterRole"
    pod := input[_]
    pod.kind == "Pod"
    msga := {
        "alertMessage": "cluster role reachable from namespace",
        "packagename":  "armo_builtins",
        "alertScore":   5,
        "fixPaths":     [],
        "reviewPaths":  [sprintf("metadata.annotations.bound-by-%s", [pod.metadata.namespace])],
        "alertObject":  {"k8sApiObjects": [cr]},
    }
}
`

func parityFixture() (cautils.K8SResources, map[string]workloadinterface.IMetadata) {
	raw := []string{
		`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"ns-a"}}`,
		`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"ns-b"}}`,
		`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"wide-open"}}`,
	}
	for _, namespace := range []string{"ns-a", "ns-b"} {
		raw = append(raw,
			// fails C-0048 (hostPath) and C-0013 (non-root)
			fmt.Sprintf(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"hostpath","namespace":%q},"spec":{"selector":{"matchLabels":{"app":"nginx"}},"template":{"metadata":{"labels":{"app":"nginx"}},"spec":{"containers":[{"name":"server","image":"nginx","securityContext":{"runAsUser":0},"volumeMounts":[{"mountPath":"/test-pd","name":"test-volume"}]}],"volumes":[{"name":"test-volume","hostPath":{"path":"/data","type":"Directory"}}]}}}}`, namespace),
			// passes both
			fmt.Sprintf(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"clean","namespace":%q},"spec":{"containers":[{"name":"app","image":"nginx","securityContext":{"runAsUser":1000,"runAsGroup":1000,"runAsNonRoot":true}}]}}`, namespace),
		)
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
		case "Deployment":
			groupResource = "apps/v1/deployments"
		case "ClusterRole":
			groupResource = "rbac.authorization.k8s.io/v1/clusterroles"
		}
		k8sResources[groupResource] = append(k8sResources[groupResource], workload.GetID())
	}
	for groupResource := range k8sResources {
		sort.Strings(k8sResources[groupResource])
	}

	return k8sResources, allResources
}

// parityFrameworks returns the frameworks used by the parity harness:
// two real controls plus one that correlates a cluster-scoped resource with
// namespaced ones.
func parityFrameworks(withCrossScopeControl bool) []reporthandling.Framework {
	frameworks := []reporthandling.Framework{*mocks.MockFramework_0006_0013()}
	if withCrossScopeControl {
		crossScope := reporthandling.Control{
			ControlID: "C-CROSS",
			Rules: []reporthandling.PolicyRule{
				{
					Rule:         crossScopeRule,
					RuleLanguage: reporthandling.RegoLanguage,
					Match: []reporthandling.RuleMatchObjects{
						{
							APIGroups:   []string{"rbac.authorization.k8s.io"},
							APIVersions: []string{"v1"},
							Resources:   []string{"ClusterRole"},
						},
						{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"Pod"},
						},
					},
				},
			},
		}
		crossScope.Name = "cross scope control"
		crossScope.Rules[0].Name = "cross-scope-rule"
		frameworks = append(frameworks, reporthandling.Framework{
			Controls: []reporthandling.Control{crossScope},
		})
	}

	return frameworks
}

func parityPolicies(withCrossScopeControl bool) *cautils.Policies {
	return convertFrameworksToPolicies(parityFrameworks(withCrossScopeControl), nil, reporthandling.ScopeCluster)
}

func newParityProcessor(policies *cautils.Policies) *OPAProcessor {
	k8sResources, allResources := parityFixture()

	sessionObj := cautils.NewOPASessionObjMock()
	sessionObj.K8SResources = k8sResources
	sessionObj.AllResources = allResources

	opap := NewOPAProcessor(sessionObj, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	opap.AllPolicies = policies
	return opap
}

// referenceProcess reproduces the evaluation order Process used before scopes
// became the outer loop: every control is taken to completion across all
// scopes before the next one starts.
func referenceProcess(t *testing.T, opap *OPAProcessor, policies *cautils.Policies) map[string]resourcesresults.Result {
	t.Helper()

	results := make(map[string]resourcesresults.Result)
	for _, controlID := range sortedControlIDs(policies) {
		control := policies.Controls[controlID]

		associated := make(map[string]resourcesresults.ResourceAssociatedControl)
		for i := range control.Rules {
			ruleResults, err := opap.processRule(context.Background(), &control.Rules[i], control.FixedInput, evaluationScope{}, &control)
			require.NoError(t, err)

			for resourceID, ruleResult := range ruleResults {
				controlResult := associated[resourceID]
				controlResult.SetID(control.ControlID)
				controlResult.SetName(control.Name)
				if ruleResult != nil {
					controlResult.ResourceAssociatedRules = append(controlResult.ResourceAssociatedRules, *ruleResult)
				}
				controlResult.SetStatus(control)
				associated[resourceID] = controlResult
			}
		}

		for resourceID, controlResult := range associated {
			result, ok := results[resourceID]
			if !ok {
				result = resourcesresults.Result{ResourceID: resourceID}
			}
			result.AssociatedControls = append(result.AssociatedControls, controlResult)
			results[resourceID] = result
		}
	}

	return results
}

// normalize makes two result sets comparable. Control ordering is guaranteed
// deterministic by the processor (sortAssociatedControls), but rule ordering
// reflects the order scopes first saw each rule and path ordering reflects the
// order Rego yielded a rule's findings — both are sets, so they are sorted here
// before comparison.
func normalize(results map[string]resourcesresults.Result) map[string]resourcesresults.Result {
	for resourceID, result := range results {
		for i := range result.AssociatedControls {
			rules := result.AssociatedControls[i].ResourceAssociatedRules
			sort.Slice(rules, func(a, b int) bool { return rules[a].Name < rules[b].Name })
			for j := range rules {
				paths := rules[j].Paths
				sort.Slice(paths, func(a, b int) bool {
					return fmt.Sprint(paths[a]) < fmt.Sprint(paths[b])
				})
			}
		}
		results[resourceID] = result
	}
	return results
}

// TestProcess_ScopeOuterMatchesRuleOuter is the core parity check: the same
// policies over the same resources must produce the same results whether
// scopes or controls are the outer loop.
func TestProcess_ScopeOuterMatchesRuleOuter(t *testing.T) {
	t.Setenv("LARGE_CLUSTER_SIZE", "1") // force one scope per namespace

	policies := parityPolicies(true)

	batched := newParityProcessor(policies)
	require.NoError(t, batched.Process(context.Background(), policies, nil))

	reference := newParityProcessor(policies)
	expected := referenceProcess(t, reference, policies)

	require.NotEmpty(t, expected)
	assert.Equal(t, normalize(expected), normalize(batched.ResourcesResult))
}

// TestProcess_PartitioningMatchesSingleScope pins the property the whole
// design rests on: for this fixture, evaluating the cluster as one input and
// evaluating it namespace by namespace reach the same verdicts. It holds for
// any rule that assesses a resource on its own, and for correlating rules
// whose findings are a union over namespaces — but not for rules that
// aggregate across namespaces (see
// TestProcess_PartitioningChangesCrossNamespaceAggregation).
func TestProcess_PartitioningMatchesSingleScope(t *testing.T) {
	policies := parityPolicies(true)

	t.Setenv("LARGE_CLUSTER_SIZE", "100000")
	single := newParityProcessor(policies)
	require.NoError(t, single.Process(context.Background(), policies, nil))
	require.Len(t, single.evaluationScopes(), 1, "fixture must fit in a single scope")

	t.Setenv("LARGE_CLUSTER_SIZE", "1")
	partitioned := newParityProcessor(policies)
	require.NoError(t, partitioned.Process(context.Background(), policies, nil))
	require.Greater(t, len(partitioned.evaluationScopes()), 1, "fixture must be split into scopes")

	require.NotEmpty(t, single.ResourcesResult)
	assert.Equal(t, normalize(single.ResourcesResult), normalize(partitioned.ResourcesResult))
}

// TestProcess_ResidentVerdictsMergeAcrossScopes covers the resource kind that
// only scope partitioning can get wrong: a cluster-scoped resource, which is
// part of the input of every scope. Its verdicts must accumulate into one
// control entry rather than one entry per scope.
func TestProcess_ResidentVerdictsMergeAcrossScopes(t *testing.T) {
	t.Setenv("LARGE_CLUSTER_SIZE", "1")

	policies := parityPolicies(true)
	opap := newParityProcessor(policies)
	require.NoError(t, opap.Process(context.Background(), policies, nil))

	const clusterRoleID = "rbac.authorization.k8s.io/v1//ClusterRole/wide-open"
	result, ok := opap.ResourcesResult[clusterRoleID]
	require.True(t, ok, "cluster-scoped resource missing from results: %v", slicesOfKeys(opap.ResourcesResult))

	var crossScope []resourcesresults.ResourceAssociatedControl
	for _, control := range result.AssociatedControls {
		if control.ControlID == "C-CROSS" {
			crossScope = append(crossScope, control)
		}
	}
	require.Len(t, crossScope, 1, "a control evaluated in several scopes must yield one entry per resource")
	require.Len(t, crossScope[0].ResourceAssociatedRules, 1, "a rule evaluated in several scopes must yield one entry per control")

	// the resident scope is evaluated on its own, with no Pod in the input, so
	// the rule passes there: a pass in one scope must not mask a failure found
	// in another
	assert.Equal(t, apis.StatusFailed, crossScope[0].ResourceAssociatedRules[0].Status,
		"failure in one scope must survive a pass in another")
	assert.True(t, crossScope[0].GetStatus(nil).IsFailed(), "merged control status must be recomputed from the merged rules")

	paths := map[string]bool{}
	for _, path := range crossScope[0].ResourceAssociatedRules[0].Paths {
		paths[path.ReviewPath] = true
	}
	assert.True(t, paths["metadata.annotations.bound-by-ns-a"], "ns-a verdict lost, got %v", paths)
	assert.True(t, paths["metadata.annotations.bound-by-ns-b"], "ns-b verdict lost, got %v", paths)
}

// residentOnlyRule matches nothing a namespace owns and emits one path per
// evaluation, so the number of paths reveals how often it ran.
const residentOnlyRule = `package armo_builtins

deny[msga] {
    cr := input[_]
    cr.kind == "ClusterRole"
    msga := {
        "alertMessage": "cluster role",
        "packagename":  "armo_builtins",
        "alertScore":   1,
        "fixPaths":     [],
        "reviewPaths":  ["metadata.name"],
        "alertObject":  {"k8sApiObjects": [cr]},
    }
}
`

// TestProcess_ResidentOnlyRuleEvaluatedOnce guards the cost of making scopes
// the outer loop: a rule that matches only resident resources must not be
// re-evaluated on identical input once per namespace.
func TestProcess_ResidentOnlyRuleEvaluatedOnce(t *testing.T) {
	t.Setenv("LARGE_CLUSTER_SIZE", "1")

	control := reporthandling.Control{
		ControlID: "C-RESIDENT",
		Rules: []reporthandling.PolicyRule{
			{
				Rule:         residentOnlyRule,
				RuleLanguage: reporthandling.RegoLanguage,
				Match: []reporthandling.RuleMatchObjects{
					{
						APIGroups:   []string{"rbac.authorization.k8s.io"},
						APIVersions: []string{"v1"},
						Resources:   []string{"ClusterRole"},
					},
				},
			},
		},
	}
	control.Name = "resident only control"
	control.Rules[0].Name = "resident-only-rule"
	policies := convertFrameworksToPolicies(
		[]reporthandling.Framework{{Controls: []reporthandling.Control{control}}},
		nil, reporthandling.ScopeCluster,
	)

	opap := newParityProcessor(policies)
	require.Greater(t, len(opap.evaluationScopes()), 1, "fixture must be split into scopes")
	require.NoError(t, opap.Process(context.Background(), policies, nil))

	result, ok := opap.ResourcesResult["rbac.authorization.k8s.io/v1//ClusterRole/wide-open"]
	require.True(t, ok)
	require.Len(t, result.AssociatedControls, 1)
	require.Len(t, result.AssociatedControls[0].ResourceAssociatedRules, 1)
	assert.Len(t, result.AssociatedControls[0].ResourceAssociatedRules[0].Paths, 1,
		"rule re-ran on identical resident-only input once per namespace")
}

// aggregatingRule fires only when the input holds more than one Pod. It is the
// shape of rule that namespace partitioning genuinely changes: the pods of the
// cluster are never in the same input again.
const aggregatingRule = `package armo_builtins

deny[msga] {
    pods := [p | p := input[_]; p.kind == "Pod"]
    count(pods) > 1
    msga := {
        "alertMessage": "more than one pod in scope",
        "packagename":  "armo_builtins",
        "alertScore":   1,
        "fixPaths":     [],
        "reviewPaths":  [],
        "alertObject":  {"k8sApiObjects": [pods[_]]},
    }
}
`

// TestProcess_PartitioningChangesCrossNamespaceAggregation documents the known
// limitation of evaluating namespace by namespace, rather than leaving it for
// someone to discover: a rule that aggregates over resources from several
// namespaces sees only one namespace at a time and reaches a different verdict.
//
// This is pre-existing behaviour — clusters above the large-cluster threshold
// have been evaluated per namespace for a long time — and scope partitioning
// neither introduces nor fixes it.
func TestProcess_PartitioningChangesCrossNamespaceAggregation(t *testing.T) {
	control := reporthandling.Control{
		ControlID: "C-AGGREGATE",
		Rules: []reporthandling.PolicyRule{
			{
				Rule:         aggregatingRule,
				RuleLanguage: reporthandling.RegoLanguage,
				Match: []reporthandling.RuleMatchObjects{
					{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"}},
				},
			},
		},
	}
	control.Name = "aggregating control"
	control.Rules[0].Name = "aggregating-rule"
	policies := convertFrameworksToPolicies(
		[]reporthandling.Framework{{Controls: []reporthandling.Control{control}}},
		nil, reporthandling.ScopeCluster,
	)

	const podID = "/v1/ns-a/Pod/clean"

	t.Setenv("LARGE_CLUSTER_SIZE", "100000")
	single := newParityProcessor(policies)
	require.NoError(t, single.Process(context.Background(), policies, nil))
	require.Contains(t, single.ResourcesResult, podID)
	singleResult := single.ResourcesResult[podID]
	assert.True(t, singleResult.GetStatus(nil).IsFailed(),
		"a single input holds the pods of every namespace, so the rule fires")

	t.Setenv("LARGE_CLUSTER_SIZE", "1")
	partitioned := newParityProcessor(policies)
	require.NoError(t, partitioned.Process(context.Background(), policies, nil))
	require.Contains(t, partitioned.ResourcesResult, podID)
	partitionedResult := partitioned.ResourcesResult[podID]
	assert.True(t, partitionedResult.GetStatus(nil).IsPassed(),
		"each namespace holds one pod, so the rule never fires: known divergence")
}

func slicesOfKeys(results map[string]resourcesresults.Result) []string {
	keys := make([]string, 0, len(results))
	for key := range results {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// wholeClusterAggregatingControl is the aggregating control fixture marked
// requiresWholeClusterInput, so it must be evaluated once against the whole
// cluster regardless of how the scan is partitioned.
func wholeClusterAggregatingControl() reporthandling.Control {
	control := reporthandling.Control{
		ControlID: "C-AGGREGATE",
		Rules: []reporthandling.PolicyRule{
			{
				Rule:         aggregatingRule,
				RuleLanguage: reporthandling.RegoLanguage,
				Match: []reporthandling.RuleMatchObjects{
					{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"}},
				},
			},
		},
	}
	control.Name = "aggregating control"
	control.Rules[0].Name = "aggregating-rule"
	control.Attributes = map[string]interface{}{
		ControlAttributeRequiresWholeClusterInput: true,
	}
	return control
}

func wholeClusterAggregatingPolicies() (*cautils.Policies, []reporthandling.Framework) {
	frameworks := []reporthandling.Framework{{Controls: []reporthandling.Control{wholeClusterAggregatingControl()}}}
	return convertFrameworksToPolicies(frameworks, nil, reporthandling.ScopeCluster), frameworks
}

// TestWholeClusterControlParityAcrossPaths pins the fix for #2871: a control
// that joins objects across namespaces must reach the same verdict whether the
// cluster is evaluated as a single input, partitioned per namespace (eager), or
// streamed namespace by namespace. The aggregating rule only fires when more
// than one Pod is in the input, so it silently passes under per-namespace
// evaluation unless the control is deferred to a whole-cluster pass.
func TestWholeClusterControlParityAcrossPaths(t *testing.T) {
	policies, frameworks := wholeClusterAggregatingPolicies()
	const podID = "/v1/ns-a/Pod/clean"

	t.Run("single scope", func(t *testing.T) {
		t.Setenv("LARGE_CLUSTER_SIZE", "100000")
		opap := newParityProcessor(policies)
		require.NoError(t, opap.Process(context.Background(), policies, nil))
		require.Contains(t, opap.ResourcesResult, podID)
		singleResult := opap.ResourcesResult[podID]
		require.True(t, singleResult.GetStatus(nil).IsFailed(),
			"single input holds every namespace's pods, so the rule fires")
	})

	t.Run("partitioned eager", func(t *testing.T) {
		t.Setenv("LARGE_CLUSTER_SIZE", "1")
		opap := newParityProcessor(policies)
		require.Greater(t, len(opap.evaluationScopes()), 1, "fixture must be split into scopes")
		require.NoError(t, opap.Process(context.Background(), policies, nil))
		require.Contains(t, opap.ResourcesResult, podID)
		partitionedResult := opap.ResourcesResult[podID]
		require.True(t, partitionedResult.GetStatus(nil).IsFailed(),
			"whole-cluster control must be evaluated once after the scopes merge")
	})

	t.Run("streaming", func(t *testing.T) {
		t.Setenv("LARGE_CLUSTER_SIZE", "1")

		k8sResources, allResources := parityFixture()
		sessionObj := cautils.NewOPASessionObjMock()
		sessionObj.Policies = frameworks
		sessionObj.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{}

		opap := NewOPAProcessor(sessionObj, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)

		resident, batches := cautils.PartitionResources(len(allResources), k8sResources, nil, allResources)
		require.NotEmpty(t, batches, "fixture must be split into namespace batches")

		batchChan := make(chan *cautils.ResourceBatch, len(batches)+1)
		errChan := make(chan error, 1)
		close(errChan)
		batchChan <- resident
		for _, batch := range batches {
			batchChan <- batch
		}
		close(batchChan)

		require.NoError(t, opap.ProcessWithStreaming(context.Background(), batchChan, errChan, cautils.NewProgressHandler(""), len(batches)))
		require.Contains(t, opap.ResourcesResult, podID)
		streamingResult := opap.ResourcesResult[podID]
		require.True(t, streamingResult.GetStatus(nil).IsFailed(),
			"whole-cluster control must be evaluated once after streaming merges every batch")
	})
}

func TestControlRequiresWholeClusterInput(t *testing.T) {
	withAttr := func(controlID string, value any) *reporthandling.Control {
		c := &reporthandling.Control{ControlID: controlID}
		c.Attributes = map[string]interface{}{ControlAttributeRequiresWholeClusterInput: value}
		return c
	}

	tests := []struct {
		name    string
		control *reporthandling.Control
		want    bool
	}{
		{name: "nil control", control: nil, want: false},
		{
			name:    "no attribute, no fallback",
			control: &reporthandling.Control{ControlID: "C-0001"},
			want:    false,
		},
		{name: "boolean attribute true", control: withAttr("C-X", true), want: true},
		{name: "boolean attribute false", control: withAttr("C-X", false), want: false},
		{name: "string attribute true", control: withAttr("C-X", "true"), want: true},
		{name: "string attribute false", control: withAttr("C-X", "false"), want: false},
		{
			name:    "fallback control ID",
			control: &reporthandling.Control{ControlID: "C-0267"},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, controlRequiresWholeClusterInput(tt.control))
		})
	}
}
