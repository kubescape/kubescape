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

// positionalRule builds a rule that judges the Pod at index 1 of input. Its
// selection is the only thing that varies, so each way of observing an
// element's position can be run through the same warm and cold scans.
func positionalRule(selection string) string {
	return `package armo_builtins
import rego.v1

deny contains msga if {
` + selection + `
	pod.metadata.annotations.ca == "/pki/shared.crt"
	msga := {
		"alertMessage": "the second pod uses the shared CA",
		"packagename":  "armo_builtins",
		"alertScore":   1,
		"failedPaths":  [],
		"fixPaths":     [],
		"alertObject":  {"k8sApiObjects": [pod]},
	}
}
`
}

// TestIncrementalCache_PositionalRuleMatchesUncachedScan covers rules that
// pick an element of input by its position. A cache hit is left out of the
// input, which moves every later object down: with the first Pod served from
// the cache, the changed second Pod sits at index 0 and a rule looking at
// index 1 no longer sees it. Such a rule must not be cached.
func TestIncrementalCache_PositionalRuleMatchesUncachedScan(t *testing.T) {
	const ownCA, sharedCA = "/pki/own.crt", "/pki/shared.crt"
	first := controlPlanePod("first", ownCA)
	second := controlPlanePod("second", ownCA)
	changed := controlPlanePod("second", sharedCA)

	tests := []struct {
		name      string
		selection string
	}{
		{
			name:      "index bound to a constant",
			selection: "\ti := 1\n\tpod := input[i]",
		},
		{
			name:      "indexed membership with a constrained index",
			selection: "\tsome i, pod in input\n\ti == 1",
		},
		{
			name:      "declared index compared after the lookup",
			selection: "\tsome i\n\tpod := input[i]\n\ti > 0",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rego := positionalRule(tc.selection)
			require.True(t, ruleCorrelatesInput(rego))

			want := sharedCAVerdicts(t, rego, nil, first, changed)
			require.Equal(t, apis.StatusPassed, want[first.GetID()])
			require.Equal(t, apis.StatusFailed, want[changed.GetID()], "the rule must judge the Pod at index 1")

			dir := t.TempDir()
			primed, err := scancache.Load(dir, "v1")
			require.NoError(t, err)
			for id, status := range sharedCAVerdicts(t, rego, primed, first, second) {
				require.Equal(t, apis.StatusPassed, status, id)
			}
			require.NoError(t, primed.Flush())

			warm, err := scancache.Load(dir, "v1")
			require.NoError(t, err)
			got := sharedCAVerdicts(t, rego, warm, first, changed)

			require.Equal(t, want, got, "a warm scan must reach the same verdicts as a cold one")
		})
	}
}

// aliasedSharedCARule is sharedCARule reading input through an import alias,
// which hides every read of input behind another name.
const aliasedSharedCARule = `package armo_builtins
import rego.v1
import input as pods

deny contains msga if {
	etcd := [p | p := pods[_]; p.metadata.labels.component == "etcd"][0]
	api := [p | p := pods[_]; p.metadata.labels.component == "kube-apiserver"][0]
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

// TestIncrementalCache_AliasedInputRuleMatchesUncachedScan repeats the shared
// CA scenario for a rule that reaches input through an import alias. The etcd
// Pod is unchanged between the scans, so a cached pass would be served for it
// although the API server now shares its CA.
func TestIncrementalCache_AliasedInputRuleMatchesUncachedScan(t *testing.T) {
	const etcdCA, clusterCA = "/pki/etcd/ca.crt", "/pki/ca.crt"
	require.True(t, ruleCorrelatesInput(aliasedSharedCARule))

	etcd := controlPlanePod("etcd", etcdCA)
	api := controlPlanePod("kube-apiserver", clusterCA)
	changed := controlPlanePod("kube-apiserver", etcdCA)

	want := sharedCAVerdicts(t, aliasedSharedCARule, nil, etcd, changed)
	require.Equal(t, apis.StatusFailed, want[etcd.GetID()])
	require.Equal(t, apis.StatusFailed, want[changed.GetID()])

	dir := t.TempDir()
	primed, err := scancache.Load(dir, "v1")
	require.NoError(t, err)
	for id, status := range sharedCAVerdicts(t, aliasedSharedCARule, primed, etcd, api) {
		require.Equal(t, apis.StatusPassed, status, id)
	}
	require.NoError(t, primed.Flush())

	warm, err := scancache.Load(dir, "v1")
	require.NoError(t, err)
	got := sharedCAVerdicts(t, aliasedSharedCARule, warm, etcd, changed)

	require.Equal(t, want, got, "a warm scan must reach the same verdicts as a cold one")
}
