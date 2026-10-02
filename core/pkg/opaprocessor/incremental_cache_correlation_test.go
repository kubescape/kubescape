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

// sharedCARule is a cut-down copy of regolibrary's etcd-unique-ca (C-0159):
// it matches a single kind (Pod), so it is cache eligible, yet each Pod's
// verdict depends on another Pod in the same input. It fails both control
// plane Pods when etcd trusts the CA that the API server uses for clients.
const sharedCARule = `package armo_builtins
import rego.v1

deny contains msga if {
	etcd := [p | p := input[_]; p.metadata.labels.component == "etcd"][0]
	api := [p | p := input[_]; p.metadata.labels.component == "kube-apiserver"][0]
	etcd.metadata.annotations.ca == api.metadata.annotations.ca
	msga := {
		"alertMessage": "etcd and the API server share a CA",
		"packagename":  "armo_builtins",
		"alertScore":   8,
		"failedPaths":  [],
		"fixPaths":     [],
		"alertObject":  {"k8sApiObjects": [etcd, api]},
	}
}
`

// perPodCARule judges each Pod on its own, so it stays cache eligible.
const perPodCARule = `package armo_builtins
import rego.v1

deny contains msga if {
	pod := input[_]
	pod.metadata.annotations.ca == "/pki/shared.crt"
	msga := {
		"alertMessage": "pod uses the shared CA",
		"packagename":  "armo_builtins",
		"alertScore":   1,
		"failedPaths":  [],
		"fixPaths":     [],
		"alertObject":  {"k8sApiObjects": [pod]},
	}
}
`

// denyEveryInputRule replaces perPodCARule under the same rule name to show
// whether a verdict was served from the cache instead of being evaluated.
const denyEveryInputRule = `package armo_builtins
import rego.v1

deny contains msga if {
	pod := input[_]
	msga := {
		"alertMessage": "denied",
		"packagename":  "armo_builtins",
		"alertScore":   1,
		"failedPaths":  [],
		"fixPaths":     [],
		"alertObject":  {"k8sApiObjects": [pod]},
	}
}
`

func sharedCAControl(rego string) *reporthandling.Control {
	rule := reporthandling.PolicyRule{
		Rule:         rego,
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{
			{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"}},
		},
	}
	rule.Name = "etcd-unique-ca"
	ctrl := &reporthandling.Control{ControlID: "C-SHAREDCA", Rules: []reporthandling.PolicyRule{rule}}
	ctrl.Name = "etcd and API server use different CAs"
	return ctrl
}

func controlPlanePod(component, ca string) workloadinterface.IMetadata {
	return workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":        component + "-cp",
			"namespace":   "kube-system",
			"labels":      map[string]any{"component": component},
			"annotations": map[string]any{"ca": ca},
		},
	})
}

// sharedCAVerdicts evaluates the control over pods, through store when it is
// not nil, and returns each Pod's status keyed by resource ID.
func sharedCAVerdicts(t *testing.T, rego string, store *scancache.Store, pods ...workloadinterface.IMetadata) map[string]apis.ScanningStatus {
	t.Helper()
	sess := cautils.NewOPASessionObjMock()
	ids := make([]string, 0, len(pods))
	for _, p := range pods {
		ids = append(ids, p.GetID())
		sess.AllResources[p.GetID()] = p
	}
	sess.K8SResources = cautils.K8SResources{"/v1/pods": ids}
	ctrl := sharedCAControl(rego)
	sess.AllPolicies = cautils.NewPolicies()
	sess.AllPolicies.Controls[ctrl.ControlID] = *ctrl

	opap := NewOPAProcessor(sess, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	if store != nil {
		opap.SetIncrementalCache(store)
	}
	got, err := opap.processControl(context.Background(), ctrl, evaluationScope{})
	require.NoError(t, err)

	out := make(map[string]apis.ScanningStatus, len(got))
	for id, r := range got {
		out[id] = r.GetStatus(nil).Status()
	}
	return out
}

// TestIncrementalCache_CorrelatedRuleMatchesUncachedScan pins the contract
// that the incremental cache must never change a verdict. A rule that relates
// two objects of the same kind sees its whole input on a cold scan; a warm
// scan must reach the same verdicts after a peer changes, appears or goes away.
func TestIncrementalCache_CorrelatedRuleMatchesUncachedScan(t *testing.T) {
	const etcdCA, clusterCA = "/pki/etcd/ca.crt", "/pki/ca.crt"
	etcd := controlPlanePod("etcd", etcdCA)

	tests := []struct {
		name  string
		first []workloadinterface.IMetadata // scan that primes the cache
		then  []workloadinterface.IMetadata // scan under test
	}{
		{
			name:  "peer changes to share the CA",
			first: []workloadinterface.IMetadata{etcd, controlPlanePod("kube-apiserver", clusterCA)},
			then:  []workloadinterface.IMetadata{etcd, controlPlanePod("kube-apiserver", etcdCA)},
		},
		{
			name:  "peer sharing the CA appears",
			first: []workloadinterface.IMetadata{etcd},
			then:  []workloadinterface.IMetadata{etcd, controlPlanePod("kube-apiserver", etcdCA)},
		},
		{
			name:  "peer sharing the CA goes away",
			first: []workloadinterface.IMetadata{etcd, controlPlanePod("kube-apiserver", etcdCA)},
			then:  []workloadinterface.IMetadata{etcd},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			want := sharedCAVerdicts(t, sharedCARule, nil, tc.then...)

			dir := t.TempDir()
			primed, err := scancache.Load(dir, "v1")
			require.NoError(t, err)
			sharedCAVerdicts(t, sharedCARule, primed, tc.first...)
			require.NoError(t, primed.Flush())

			warm, err := scancache.Load(dir, "v1")
			require.NoError(t, err)
			got := sharedCAVerdicts(t, sharedCARule, warm, tc.then...)

			require.Equal(t, want, got, "a warm scan must reach the same verdicts as a cold one")
		})
	}
}

// TestIncrementalCache_PerObjectRuleIsStillServedFromCache guards the other
// side of the contract: excluding correlated rules must not stop the cache from
// serving rules that judge each object on its own. The second scan swaps in a
// rule that denies every Pod; only cached verdicts can still pass.
func TestIncrementalCache_PerObjectRuleIsStillServedFromCache(t *testing.T) {
	require.False(t, ruleCorrelatesInput(perPodCARule))
	require.False(t, ruleCorrelatesInput(denyEveryInputRule))
	require.True(t, ruleCorrelatesInput(sharedCARule))

	pods := []workloadinterface.IMetadata{
		controlPlanePod("etcd", "/pki/etcd/ca.crt"),
		controlPlanePod("kube-apiserver", "/pki/ca.crt"),
	}
	dir := t.TempDir()
	primed, err := scancache.Load(dir, "v1")
	require.NoError(t, err)
	first := sharedCAVerdicts(t, perPodCARule, primed, pods...)
	require.NoError(t, primed.Flush())
	require.Len(t, first, len(pods))
	for id, status := range first {
		require.Equal(t, apis.StatusPassed, status, id)
	}

	warm, err := scancache.Load(dir, "v1")
	require.NoError(t, err)
	got := sharedCAVerdicts(t, denyEveryInputRule, warm, pods...)
	require.Equal(t, first, got, "an unchanged resource must be served from the cache")
}
