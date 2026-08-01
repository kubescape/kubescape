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
		}
	}
}
