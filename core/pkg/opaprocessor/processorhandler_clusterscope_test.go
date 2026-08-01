package opaprocessor

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"
)

// TestProcessRule_ClusterScopedPathsAcrossNamespaces guards against a
// regression where the per-namespace pre-seed inside processRule
// unconditionally overwrites the result entry of a cluster-scoped resource,
// silently dropping Paths and Status accumulated by earlier namespace
// iterations.
//
// Setup: large-cluster mode (each namespace becomes its own bucket in
// resourcesPerNS) with one cluster-scoped ClusterRole and one Pod in each
// of two namespaces. The Rego fails the ClusterRole and emits a failedPath
// that contains the namespace of the Pod present in the iteration's input,
// so iteration over ns-a and ns-b produces two distinct paths. Both must
// survive in the final result.
func TestProcessRule_ClusterScopedPathsAcrossNamespaces(t *testing.T) {
	origLarge := largeClusterSize
	largeClusterSize = 1
	t.Cleanup(func() { largeClusterSize = origLarge })

	clusterRole := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata":   map[string]any{"name": "wide-open"},
	})
	podA := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "pa", "namespace": "ns-a"},
	})
	podB := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "pb", "namespace": "ns-b"},
	})

	sess := cautils.NewOPASessionObjMock()
	sess.K8SResources = cautils.K8SResources{
		"rbac.authorization.k8s.io/v1/clusterroles": {clusterRole.GetID()},
		"/v1/pods": {podA.GetID(), podB.GetID()},
	}
	sess.AllResources[clusterRole.GetID()] = clusterRole
	sess.AllResources[podA.GetID()] = podA
	sess.AllResources[podB.GetID()] = podB

	opap := NewOPAProcessor(sess, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)

	rule := &reporthandling.PolicyRule{
		Rule: `package armo_builtins
import rego.v1

deny contains msga if {
    cr := input[_]
    cr.kind == "ClusterRole"
    pod := input[_]
    pod.kind == "Pod"
    failPath := [sprintf("metadata.annotations.bound-by-%s", [pod.metadata.namespace])]
    msga := {
        "alertMessage": "wide-open binds pod",
        "packagename":  "armo_builtins",
        "alertScore":   5,
        "fixPaths":     [],
        "failedPaths":  failPath,
        "alertObject":  {"k8sApiObjects": [cr]},
    }
}
`,
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
	}
	rule.Name = "cluster-role-path-accumulation"

	got, err := opap.processRule(context.Background(), rule, nil, "")
	assert.NoError(t, err)

	crResult, ok := got[clusterRole.GetID()]
	assert.True(t, ok, "ClusterRole must appear in results")
	if !ok {
		return
	}

	failed := map[string]bool{}
	for _, p := range crResult.Paths {
		if p.FailedPath != "" {
			failed[p.FailedPath] = true
		}
	}
	assert.True(t, failed["metadata.annotations.bound-by-ns-a"],
		"ns-a path missing — pre-seed overwrite regressed; got paths=%v", crResult.Paths)
	assert.True(t, failed["metadata.annotations.bound-by-ns-b"],
		"ns-b path missing — pre-seed overwrite regressed; got paths=%v", crResult.Paths)
}

func TestProcessRule_EnumeratorOutputsDoNotMutateAllResources(t *testing.T) {
	origLarge := largeClusterSize
	largeClusterSize = 2
	t.Cleanup(func() { largeClusterSize = origLarge })

// TestProcessRule_NamespaceBucketingStableAcrossAggregatorGrowth guards
// against a regression where the large-cluster namespace-bucketing decision
// (getNamespaceName) was recomputed from the live size of opap.AllResources
// on every rule. A subject-role-rolebinding aggregator rule writes newly
// synthesized subject objects back into opap.AllResources (see the write-back
// in processRule), which can push the live count past largeClusterSize
// mid-scan. A later, unrelated rule would then see per-namespace bucketing
// instead of the whole-cluster bucketing every earlier rule saw, even though
// the cluster itself never changed.
//
// Setup: the initial resource count (RoleBinding + Role + two Pods, one per
// namespace) sits exactly at largeClusterSize, so bucketing starts as
// whole-cluster. The aggregator rule expands one RoleBinding/Role pair into
// two synthetic subject objects, growing AllResources past the threshold. A
// second rule then evaluates the two Pods, denying any Pod evaluated without
// its sibling in the same batch — which only happens if the two Pods are
// split into separate per-namespace batches. Both Pods must still pass,
// proving the second rule was evaluated with the frozen initial count, not
// the grown live count.
func TestProcessRule_NamespaceBucketingStableAcrossAggregatorGrowth(t *testing.T) {
	origLarge := largeClusterSize
	largeClusterSize = 4
	t.Cleanup(func() { largeClusterSize = origLarge })

	binding := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "RoleBinding",
		"metadata":   map[string]any{"name": "rb", "namespace": "ns-a"},
		"roleRef":    map[string]any{"kind": "Role", "name": "my-role"},
		"subjects": []any{
			map[string]any{"kind": "ServiceAccount", "name": "sa1", "namespace": "ns-a"},
			map[string]any{"kind": "ServiceAccount", "name": "sa2", "namespace": "ns-a"},
		},
	})
	role := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "Role",
		"metadata":   map[string]any{"name": "my-role", "namespace": "ns-a"},
	})
	podA := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "pa", "namespace": "ns-a"},
	})
	podB := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "pb", "namespace": "ns-b"},
	})
	syntheticA := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "kubescape.io/v1",
		"kind":       "AggregatedResource",
		"metadata":   map[string]any{"name": "pa-aggregate", "namespace": "ns-a"},
	})
	syntheticB := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "kubescape.io/v1",
		"kind":       "AggregatedResource",
		"metadata":   map[string]any{"name": "pb-aggregate", "namespace": "ns-b"},
	})

	sess := cautils.NewOPASessionObjMock()
	sess.K8SResources = cautils.K8SResources{
		"/v1/pods": {podA.GetID(), podB.GetID()},
	}

	sess := cautils.NewOPASessionObjMock()
	sess.K8SResources = cautils.K8SResources{
		"rbac.authorization.k8s.io/v1/rolebindings": {binding.GetID()},
		"rbac.authorization.k8s.io/v1/roles":        {role.GetID()},
		"/v1/pods":                                  {podA.GetID(), podB.GetID()},
	}
	sess.AllResources[binding.GetID()] = binding
	sess.AllResources[role.GetID()] = role
	sess.AllResources[podA.GetID()] = podA
	sess.AllResources[podB.GetID()] = podB

	opap := NewOPAProcessor(sess, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)

	rule := &reporthandling.PolicyRule{
		ResourceEnumerator: `package armo_builtins
import rego.v1

deny contains msga if {
    pod := input[_]
    synthetic := {
        "apiVersion": "kubescape.io/v1",
        "kind":       "AggregatedResource",
        "metadata": {
            "name":      sprintf("%s-aggregate", [pod.metadata.name]),
            "namespace": pod.metadata.namespace,
        },
    }
    msga := {
        "alertMessage": "enumerated resource",
        "packagename":  "armo_builtins",
        "alertObject":  {"k8sApiObjects": [synthetic]},
    }
}
`,
		Rule: `package armo_builtins
import rego.v1

deny contains msga if {
    false
    msga := {}
	opap.initialResourceCount = len(sess.AllResources)

	assert.False(t, isLargeCluster(opap.initialResourceCount), "test setup must start below the large-cluster threshold")

	aggregatorRule := &reporthandling.PolicyRule{
		Rule:         "package armo_builtins\n\ndeny[msga] {\n    false\n    msga := {\"alertMessage\": \"unused\"}\n}\n",
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{
			{
				APIGroups:   []string{"rbac.authorization.k8s.io"},
				APIVersions: []string{"v1"},
				Resources:   []string{"RoleBinding", "Role"},
			},
		},
	}
	aggregatorRule.Name = "subject-role-rolebinding-aggregator"
	aggregatorRule.Attributes = map[string]interface{}{"resourcesAggregator": "subject-role-rolebinding"}

	_, err := opap.processRule(context.Background(), aggregatorRule, nil, "")
	assert.NoError(t, err)

	assert.True(t, isLargeCluster(len(opap.AllResources)),
		"aggregator write-back must grow AllResources past the threshold for this test to be meaningful")

	podRule := &reporthandling.PolicyRule{
		Rule: `package armo_builtins

deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    pods := [p | p := input[_]; p.kind == "Pod"]
    count(pods) < 2
    msga := {
        "alertMessage": "pod evaluated without its sibling",
        "packagename":  "armo_builtins",
        "alertScore":   5,
        "fixPaths":     [],
        "failedPaths":  [],
        "alertObject":  {"k8sApiObjects": [pod]},
    }
}
`,
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{
			{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"Pod"},
			},
		},
	}
	podRule.Name = "pods-evaluated-together"

	got, err := opap.processRule(context.Background(), podRule, nil, "")
	assert.NoError(t, err)

	podAResult, ok := got[podA.GetID()]
	assert.True(t, ok, "podA must appear in results")
	if ok {
		assert.Equal(t, apis.StatusPassed, podAResult.Status,
			"podA was evaluated in isolation -- bucketing drifted mid-scan; got=%+v", podAResult)
	}
	podBResult, ok := got[podB.GetID()]
	assert.True(t, ok, "podB must appear in results")
	if ok {
		assert.Equal(t, apis.StatusPassed, podBResult.Status,
			"podB was evaluated in isolation -- bucketing drifted mid-scan; got=%+v", podBResult)
	}
}

// TestProcess_NamespaceBucketingWiredFromConstruction drives the real
// production path -- NewOPAProcessor followed by Process() -- instead of
// hand-assigning opap.initialResourceCount, so that deleting the snapshot
// assignment in NewOPAProcessor causes this test to fail. Two Pods, one per
// namespace, are the only resources at construction time; the single control's
// rule denies any Pod evaluated without its sibling in the same batch, which
// only happens if per-namespace bucketing split them into separate batches.
func TestProcess_NamespaceBucketingWiredFromConstruction(t *testing.T) {
	origLarge := largeClusterSize
	largeClusterSize = 1
	t.Cleanup(func() { largeClusterSize = origLarge })

	podA := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "pa", "namespace": "ns-a"},
	})
	podB := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "pb", "namespace": "ns-b"},
	})

	sess := cautils.NewOPASessionObjMock()
	sess.K8SResources = cautils.K8SResources{
		"/v1/pods": {podA.GetID(), podB.GetID()},
	}
	sess.AllResources[podA.GetID()] = podA
	sess.AllResources[podB.GetID()] = podB

	opap := NewOPAProcessor(sess, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)

	podRule := reporthandling.PolicyRule{
		Rule: `package armo_builtins

deny[msga] {
    pod := input[_]
    pod.kind == "Pod"
    pods := [p | p := input[_]; p.kind == "Pod"]
    count(pods) < 2
    msga := {
        "alertMessage": "pod evaluated without its sibling",
        "packagename":  "armo_builtins",
        "alertScore":   5,
        "fixPaths":     [],
        "failedPaths":  [],
        "alertObject":  {"k8sApiObjects": [pod]},
    }
}
`,
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{
			{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"Pod"},
			},
		},
	}
	rule.Name = "enumerated-resource-snapshot"

	got, err := opap.processRule(context.Background(), rule, nil, "")
	assert.NoError(t, err)

	assert.Len(t, opap.AllResources, 2)
	assert.NotContains(t, opap.AllResources, syntheticA.GetID())
	assert.NotContains(t, opap.AllResources, syntheticB.GetID())
	assert.Contains(t, opap.evaluatedResources, syntheticA.GetID())
	assert.Contains(t, opap.evaluatedResources, syntheticB.GetID())

	for _, synthetic := range []workloadinterface.IMetadata{syntheticA, syntheticB} {
		result, ok := got[synthetic.GetID()]
		assert.True(t, ok, "enumerated resource %s must be represented in rule results", synthetic.GetID())
		if ok {
			assert.Equal(t, apis.StatusPassed, result.Status)
	podRule.Name = "pods-evaluated-together"

	control := reporthandling.Control{ControlID: "C-TEST", Rules: []reporthandling.PolicyRule{podRule}}
	policies := &cautils.Policies{Controls: map[string]reporthandling.Control{"C-TEST": control}}
	opap.AllPolicies = policies

	err := opap.Process(context.Background(), policies, nil)
	assert.NoError(t, err)

	podAResult, ok := opap.ResourcesResult[podA.GetID()]
	assert.True(t, ok, "podA must appear in results")
	if ok {
		assert.Equal(t, 1, len(podAResult.AssociatedControls))
		if len(podAResult.AssociatedControls) == 1 {
			assert.Equal(t, 1, len(podAResult.AssociatedControls[0].ResourceAssociatedRules))
			if len(podAResult.AssociatedControls[0].ResourceAssociatedRules) == 1 {
				assert.Equal(t, apis.StatusFailed, podAResult.AssociatedControls[0].ResourceAssociatedRules[0].Status,
					"podA was not evaluated in its own per-namespace batch -- initialResourceCount is not wired from NewOPAProcessor")
			}
		}
	}
	podBResult, ok := opap.ResourcesResult[podB.GetID()]
	assert.True(t, ok, "podB must appear in results")
	if ok {
		assert.Equal(t, 1, len(podBResult.AssociatedControls))
		if len(podBResult.AssociatedControls) == 1 {
			assert.Equal(t, 1, len(podBResult.AssociatedControls[0].ResourceAssociatedRules))
			if len(podBResult.AssociatedControls[0].ResourceAssociatedRules) == 1 {
				assert.Equal(t, apis.StatusFailed, podBResult.AssociatedControls[0].ResourceAssociatedRules[0].Status,
					"podB was not evaluated in its own per-namespace batch -- initialResourceCount is not wired from NewOPAProcessor")
			}
		}
	}
}
