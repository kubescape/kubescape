package opaprocessor

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/scancache"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/require"
)

// denyEveryPodRule fails every Pod it is given, so each pod's presence or
// absence in the result map is purely a question of whether it was scoped in.
const denyEveryPodRule = `package armo_builtins
import rego.v1

deny contains msga if {
	pod := input[_]
	pod.kind == "Pod"
	msga := {
		"alertMessage": sprintf("pod %v denied", [pod.metadata.name]),
		"packagename":  "armo_builtins",
		"alertScore":   5,
		"fixPaths":     [],
		"failedPaths":  [],
		"alertObject":  {"k8sApiObjects": [pod]},
	}
}
`

func nsCacheControl() *reporthandling.Control {
	rule := reporthandling.PolicyRule{
		Rule:         denyEveryPodRule,
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{
			{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"}},
		},
	}
	rule.Name = "deny-every-pod"
	ctrl := &reporthandling.Control{ControlID: "C-NSCACHE", Rules: []reporthandling.PolicyRule{rule}}
	ctrl.Name = "deny every pod"
	return ctrl
}

// nsCacheSession builds a session holding one Pod in "prod" and one in "dev".
func nsCacheSession(t *testing.T) (sess *cautils.OPASessionObj, prodID, devID string) {
	t.Helper()
	podProd := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "p-prod", "namespace": "prod"},
	})
	podDev := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "p-dev", "namespace": "dev"},
	})

	sess = cautils.NewOPASessionObjMock()
	sess.K8SResources = cautils.K8SResources{"/v1/pods": {podProd.GetID(), podDev.GetID()}}
	sess.AllResources[podProd.GetID()] = podProd
	sess.AllResources[podDev.GetID()] = podDev

	ctrl := nsCacheControl()
	sess.AllPolicies = cautils.NewPolicies()
	sess.AllPolicies.Controls[ctrl.ControlID] = *ctrl

	return sess, podProd.GetID(), podDev.GetID()
}

// TestIncrementalCache_NoCacheHonorsExcludedNamespace is the baseline: without
// the incremental cache, a resource in an excluded namespace never reaches the
// result map. This pins the contract the cached path must match.
func TestIncrementalCache_NoCacheHonorsExcludedNamespace(t *testing.T) {
	sess, prodID, devID := nsCacheSession(t)
	opap := NewOPAProcessor(sess, resources.NewRegoDependenciesDataMock(), "test", "dev", "", false, nil)

	got, err := opap.processControl(context.Background(), nsCacheControl(), evaluationScope{})
	require.NoError(t, err)

	_, hasProd := got[prodID]
	_, hasDev := got[devID]
	t.Logf("no cache, --exclude-namespaces dev -> prod=%v dev=%v", hasProd, hasDev)

	require.True(t, hasProd, "prod pod is in scope and must be evaluated")
	require.False(t, hasDev, "dev pod is in an excluded namespace and must be absent")
}

// TestIncrementalCache_HonorsExcludedNamespaceOnCacheHit proves that attaching
// the incremental cache must not change which namespaces are in scope.
//
// The cache-read loop in processRuleOnScope writes a cached verdict straight
// into the result map and removes the resource from resourceToScan, so the
// skipNamespace guards further down the function never see it. A resource
// cached by an earlier unfiltered scan is therefore resurrected into a later
// scan that explicitly excluded its namespace.
func TestIncrementalCache_HonorsExcludedNamespaceOnCacheHit(t *testing.T) {
	dir := t.TempDir()

	// Scan 1: no namespace filter, cache attached. Primes the cache with both pods.
	sess1, _, _ := nsCacheSession(t)
	store1, err := scancache.Load(dir, "v1")
	require.NoError(t, err)
	opap1 := NewOPAProcessor(sess1, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	opap1.SetIncrementalCache(store1)

	got1, err := opap1.processControl(context.Background(), nsCacheControl(), evaluationScope{})
	require.NoError(t, err)
	require.Len(t, got1, 2, "unfiltered scan must evaluate both pods")
	require.NoError(t, store1.Flush())

	// Scan 2: same resources, same cache, now with --exclude-namespaces dev.
	sess2, prodID, devID := nsCacheSession(t)
	store2, err := scancache.Load(dir, "v1")
	require.NoError(t, err)
	opap2 := NewOPAProcessor(sess2, resources.NewRegoDependenciesDataMock(), "test", "dev", "", false, nil)
	opap2.SetIncrementalCache(store2)

	got2, err := opap2.processControl(context.Background(), nsCacheControl(), evaluationScope{})
	require.NoError(t, err)

	_, hasProd := got2[prodID]
	devResult, hasDev := got2[devID]
	t.Logf("with cache, --exclude-namespaces dev -> prod=%v dev=%v", hasProd, hasDev)
	if hasDev {
		t.Logf("dev pod served from cache with status=%q", devResult.GetStatus(nil).Status())
	}

	require.True(t, hasProd, "prod pod is in scope and must be evaluated")
	require.False(t, hasDev,
		"dev pod is in an excluded namespace: the incremental cache must not resurrect it")
}
