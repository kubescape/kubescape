package opaprocessor

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/scancache"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/require"
)

// passEveryPodRule never denies, so every in-scope Pod lands as a pass and
// the only thing under test is the coverage substatus on restored verdicts.
//
//nolint:gosec // G101: this is a Rego rule fixture, not a hardcoded credential
const passEveryPodRule = `package armo_builtins
import rego.v1

deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	pod.metadata.name == "definitely-no-such-pod"
	msga := {
		"alertMessage": sprintf("pod %v denied", [pod.metadata.name]),
		"packagename":  "armo_builtins",
		"alertScore":   5,
		"failPaths":    [],
		"failedPaths":  [],
		"alertObject":  {"k8sApiObjects": [pod]},
	}
}
`

func coverageCacheControl() *reporthandling.Control {
	rule := reporthandling.PolicyRule{
		Rule:         passEveryPodRule,
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{
			{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"}},
		},
	}
	rule.Name = "pass-every-pod"
	ctrl := &reporthandling.Control{ControlID: "C-PARTIAL", Rules: []reporthandling.PolicyRule{rule}}
	ctrl.Name = "pass every pod"
	return ctrl
}

func coverageCacheSession(t *testing.T) (*cautils.OPASessionObj, string) {
	t.Helper()
	pod := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "p", "namespace": "default"},
	})

	sess := cautils.NewOPASessionObjMock()
	sess.K8SResources = cautils.K8SResources{"/v1/pods": {pod.GetID()}}
	sess.AllResources[pod.GetID()] = pod
	sess.ResourceToControlsMap = map[string][]string{"/v1/pods": {"C-PARTIAL"}}

	ctrl := coverageCacheControl()
	sess.AllPolicies = cautils.NewPolicies()
	sess.AllPolicies.Controls[ctrl.ControlID] = *ctrl

	return sess, pod.GetID()
}

// TestIncrementalCache_CompleteToPartialRefreshesSubstatus: a pass cached
// while collection was complete must gain IncompleteCoverage when a later
// scan reuses it under a partial gap.
func TestIncrementalCache_CompleteToPartialRefreshesSubstatus(t *testing.T) {
	dir := t.TempDir()

	sess1, podID := coverageCacheSession(t)
	store1, err := scancache.Load(dir, "v1")
	require.NoError(t, err)
	opap1 := NewOPAProcessor(sess1, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	opap1.SetIncrementalCache(store1)

	got1, err := opap1.processControl(context.Background(), coverageCacheControl(), evaluationScope{})
	require.NoError(t, err)
	require.Contains(t, got1, podID)
	require.NoError(t, store1.Flush())

	sess2, _ := coverageCacheSession(t)
	sess2.PartialGVRFailures = []cautils.PartialGVRPull{
		{GVR: "/v1/pods", Selector: "conversion", Error: "node-agent reported 2 Pods but only 1 could be read"},
	}
	store2, err := scancache.Load(dir, "v1")
	require.NoError(t, err)
	opap2 := NewOPAProcessor(sess2, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	opap2.SetIncrementalCache(store2)

	got2, err := opap2.processControl(context.Background(), coverageCacheControl(), evaluationScope{})
	require.NoError(t, err)
	res, ok := got2[podID]
	require.True(t, ok, "cached pass must be served")
	require.Equal(t, apis.StatusPassed, res.GetStatus(nil).Status())
	require.Equal(t, apis.SubStatusIncompleteCoverage, res.GetStatus(nil).GetSubStatus(),
		"restored pass must gain IncompleteCoverage under the current scan's partial gap")
}

// TestIncrementalCache_PartialToCompleteClearsSubstatus: a pass cached with
// IncompleteCoverage must come back clean once collection recovers.
func TestIncrementalCache_PartialToCompleteClearsSubstatus(t *testing.T) {
	dir := t.TempDir()

	sess1, podID := coverageCacheSession(t)
	sess1.PartialGVRFailures = []cautils.PartialGVRPull{
		{GVR: "/v1/pods", Selector: "conversion", Error: "node-agent reported 2 Pods but only 1 could be read"},
	}
	store1, err := scancache.Load(dir, "v1")
	require.NoError(t, err)
	opap1 := NewOPAProcessor(sess1, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	opap1.SetIncrementalCache(store1)

	got1, err := opap1.processControl(context.Background(), coverageCacheControl(), evaluationScope{})
	require.NoError(t, err)
	require.Contains(t, got1, podID)
	require.NoError(t, store1.Flush())

	sess2, _ := coverageCacheSession(t)
	store2, err := scancache.Load(dir, "v1")
	require.NoError(t, err)
	opap2 := NewOPAProcessor(sess2, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	opap2.SetIncrementalCache(store2)

	got2, err := opap2.processControl(context.Background(), coverageCacheControl(), evaluationScope{})
	require.NoError(t, err)
	res, ok := got2[podID]
	require.True(t, ok, "cached pass must be served")
	require.Equal(t, apis.StatusPassed, res.GetStatus(nil).Status())
	require.NotEqual(t, apis.SubStatusIncompleteCoverage, res.GetStatus(nil).GetSubStatus(),
		"restored pass must not keep a stale IncompleteCoverage after recovery")
}
