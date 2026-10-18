package opaprocessor

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/scancache"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/require"
)

func TestDynamicStatusCache_ComputedKeyIsNotCacheSafe(t *testing.T) {
	source := `package dynamic_status
deny contains node if {
  node := input[_]
  key := concat("", ["sta", "tus"])
  object.get(node, key, {}) != {}
}`
	require.False(t, ruleCorrelatesInput(source))
	require.True(t, ruleReadsStatus(source), "a computed key can read status even without the literal appearing in source")
}

func dynamicLookupModule(statements string) string {
	return "package dynamic_lookup\ndeny contains node if {\nnode := input[_]\n" + statements + "\n}"
}

func TestDynamicStatusCache_ComputedLookupFormsAreConservative(t *testing.T) {
	for _, lookup := range []struct {
		name string
		code string
	}{
		{"concat key", `key := concat("", ["sta", "tus"]); object.get(node, key, {}) != {}`},
		{"sprintf key", `key := sprintf("%s%s", ["sta", "tus"]); object.get(node, key, {}) != {}`},
		{"lower key", `key := lower("STATUS"); object.get(node, key, {}) != {}`},
		{"runtime annotation", `key := node.metadata.annotations.field; object.get(node, key, {}) != {}`},
		{"variable path", `path := [concat("", ["sta", "tus"]), "ready"]; object.get(node, path, false)`},
		{"path with variable", `key := lower("STATUS"); object.get(node, [key, "ready"], false)`},
		{"whole object", `json.marshal(object.get(node, [], {})) != "{}"`},
		{"reference key", `object.get(node, node.metadata.annotations.field, {}) != {}`},
		{"nested call key", `object.get(node, concat("", ["sta", "tus"]), {}) != {}`},
	} {
		t.Run(lookup.name, func(t *testing.T) {
			source := dynamicLookupModule(lookup.code)
			require.True(t, ruleReadsStatus(source))
			rule := cacheEligibilityRule("dynamic", "deny contains node if { node := input[_]; "+lookup.code+" }", "Pod")
			require.False(t, ruleCacheEligible(&reporthandling.Control{}, &rule))
		})
	}
}

func TestDynamicStatusCache_LiteralKeysRemainCacheSafe(t *testing.T) {
	for _, code := range []string{
		`object.get(node, "spec", {}) != {}`,
		`object.get(node, "metadata", {}) != {}`,
		`object.get(node, ["metadata", "name"], "") != ""`,
		`object.get(node, ["spec", "hostPID"], false)`,
		`value := object.get(node, "kind", "Pod"); value == "Pod"`,
		`object.get(node, "statusMessage", "") != ""`,
	} {
		t.Run(code, func(t *testing.T) {
			source := dynamicLookupModule(code)
			require.False(t, ruleReadsStatus(source))
			rule := cacheEligibilityRule("literal", "deny contains node if { node := input[_]; "+code+" }", "Pod")
			require.True(t, ruleCacheEligible(&reporthandling.Control{}, &rule))
		})
	}
}

func TestDynamicStatusCache_StandaloneCallWithOutputArgument(t *testing.T) {
	source := dynamicLookupModule(`key := concat("", ["sta", "tus"])
object.get(node, key, {}, result)
result != {}`)
	require.True(t, ruleReadsStatus(source))
	require.False(t, ruleCorrelatesInput(source))
}

func TestDynamicStatusCache_NestedCallInComparison(t *testing.T) {
	source := dynamicLookupModule(`key := lower("STATUS")
object.get(object.get(node, key, {}), "ready", true) == false`)
	require.True(t, ruleReadsStatus(source))
	require.False(t, ruleCorrelatesInput(source))
}

func TestDynamicStatusCache_DynamicPathInsideAssignment(t *testing.T) {
	source := dynamicLookupModule(`key := concat("", ["sta", "tus"])
value := object.get(node, [key, "ready"], true)
value == false`)
	require.True(t, ruleReadsStatus(source))
	require.False(t, ruleCorrelatesInput(source))
}

func TestDynamicStatusCache_EmptyLookupPathReturnsWholeResource(t *testing.T) {
	source := dynamicLookupModule(`whole := object.get(node, [], {})
contains(json.marshal(whole), "ready")`)
	require.True(t, ruleReadsStatus(source))
	require.False(t, ruleCorrelatesInput(source))
}

func TestDynamicStatusCache_DynamicPathCannotBeClearedBySafePrefix(t *testing.T) {
	source := dynamicLookupModule(`field := node.metadata.annotations.field
object.get(node, ["metadata", field], {}) != {}`)
	require.True(t, ruleReadsStatus(source), "unknown lookup keys deliberately sacrifice cache hits rather than guess")
}

func TestDynamicStatusCache_LiteralDefaultsAreNotLookupKeys(t *testing.T) {
	source := dynamicLookupModule(`object.get(node, "spec", "status") != {}`)
	require.False(t, ruleReadsStatus(source))
}

func TestDynamicStatusCache_OneUnsafeRuleDisqualifiesWholeControl(t *testing.T) {
	safe := cacheEligibilityRule("safe", `deny contains node if { node := input[_]; object.get(node, "spec", {}) != {} }`, "Pod")
	unsafe := cacheEligibilityRule("dynamic", `deny contains node if { node := input[_]; key := lower("STATUS"); object.get(node, key, {}) != {} }`, "Pod")
	control := &reporthandling.Control{Rules: []reporthandling.PolicyRule{safe, unsafe}}
	require.True(t, ruleCacheEligible(control, &safe))
	require.False(t, ruleCacheEligible(control, &unsafe))
	require.False(t, controlCacheEligible(control))
}

func dynamicVerdictRule(keyExpression string) string {
	return `package armo_builtins
import rego.v1
deny contains msga if {
  pod := input[_]
  key := ` + keyExpression + `
  state := object.get(pod, key, {})
  object.get(state, "ready", true) == false
  msga := {
    "alertMessage": "pod is not ready",
    "packagename": "armo_builtins",
    "alertScore": 5,
    "failedPaths": [],
    "fixPaths": [],
    "alertObject": {"k8sApiObjects": [pod]}
  }
}`
}

func dynamicStatusPod(ready bool) workloadinterface.IMetadata {
	pod := controlPlanePod("test", "fixture")
	object := pod.GetObject()
	object["status"] = map[string]any{"ready": ready}
	pod.SetObject(object)
	return pod
}

func TestDynamicStatusCache_WarmAndColdScansAgreeAfterStatusOnlyChange(t *testing.T) {
	for _, key := range []string{`concat("", ["sta", "tus"])`, `lower("STATUS")`, `sprintf("%s%s", ["sta", "tus"])`} {
		for _, initiallyReady := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/from-%t", key, initiallyReady), func(t *testing.T) {
				source := dynamicVerdictRule(key)
				first := dynamicStatusPod(initiallyReady)
				second := dynamicStatusPod(!initiallyReady)
				require.Equal(t, scancache.ResourceHash(first.GetObject()), scancache.ResourceHash(second.GetObject()))
				store, err := scancache.Load(t.TempDir(), "policy")
				require.NoError(t, err)
				sharedCAVerdicts(t, source, store, first)
				require.NoError(t, store.Flush())
				warm := sharedCAVerdicts(t, source, store, second)
				cold := sharedCAVerdicts(t, source, nil, second)
				require.Equal(t, cold, warm)
				want := apis.StatusPassed
				if initiallyReady {
					want = apis.StatusFailed
				}
				require.Equal(t, want, warm[second.GetID()])
			})
		}
	}
}

func TestDynamicStatusCache_UnsafeRuleDoesNotPopulateCache(t *testing.T) {
	source := dynamicVerdictRule(`lower("STATUS")`)
	pod := dynamicStatusPod(false)
	store, err := scancache.Load(t.TempDir(), "policy")
	require.NoError(t, err)
	result := sharedCAVerdicts(t, source, store, pod)
	require.Equal(t, apis.StatusFailed, result[pod.GetID()])
	_, hit := store.Get("C-SHAREDCA", pod.GetID(), scancache.ResourceHash(pod.GetObject()))
	require.False(t, hit)
}

func TestDynamicStatusCache_PreexistingVerdictIsIgnored(t *testing.T) {
	pod := dynamicStatusPod(false)
	store, err := scancache.Load(t.TempDir(), "policy")
	require.NoError(t, err)
	// Prime the same control/rule identifiers with an older passing verdict.
	sharedCAVerdicts(t, perPodCARule, store, pod)
	require.NoError(t, store.Flush())
	got := sharedCAVerdicts(t, dynamicVerdictRule(`lower("STATUS")`), store, pod)
	require.Equal(t, apis.StatusFailed, got[pod.GetID()])
}

func TestDynamicStatusCache_DetectionIsSafeUnderConcurrentCalls(t *testing.T) {
	source := dynamicVerdictRule(`concat("", ["sta", "tus"])`)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if !ruleReadsStatus(source) {
					t.Error("computed lookup was incorrectly cleared")
				}
			}
		}()
	}
	wg.Wait()
}

func TestDynamicStatusCache_AliasedPathReturnedByHelperIsNotCleared(t *testing.T) {
	source := `package helper_lookup
field := concat("", ["sta", "tus"])
deny contains node if {
  node := input[_]
  object.get(node, field, {}) != {}
}`
	require.True(t, ruleReadsStatus(source))
	require.False(t, ruleCorrelatesInput(source))
}

func TestDynamicStatusCache_ObjectLookupInsideComprehension(t *testing.T) {
	source := dynamicLookupModule(`key := lower("STATUS")
values := [value | value := object.get(node, key, {})]
count(values) > 0`)
	require.True(t, ruleReadsStatus(source))
}

func TestDynamicStatusCache_ElseBranchLookupIsDetected(t *testing.T) {
	source := `package else_lookup
decision := true if { false } else := result if {
  node := input[_]
  key := concat("", ["sta", "tus"])
  result := object.get(node, key, {})
}`
	require.True(t, ruleReadsStatus(source))
}

func TestDynamicStatusCache_FunctionArgumentKeyCannotBeAssumedLiteral(t *testing.T) {
	source := `package function_lookup
lookup(node, key) := object.get(node, key, {})
deny contains node if {
  node := input[_]
  lookup(node, concat("", ["sta", "tus"])) != {}
}`
	require.True(t, ruleReadsStatus(source))
}

func TestDynamicStatusCache_UnknownGlobalDataKeyIsNotCleared(t *testing.T) {
	source := dynamicLookupModule(`object.get(node, data.parameters.field, {}) != {}`)
	require.True(t, ruleReadsStatus(source))
}

func TestDynamicStatusCache_DynamicDefaultDoesNotDisqualifyLiteralKey(t *testing.T) {
	source := dynamicLookupModule(`fallback := concat("", ["sta", "tus"])
object.get(node, "spec", fallback) != {}`)
	require.False(t, ruleReadsStatus(source))
}

func TestDynamicStatusCache_LiteralKeyInStandaloneCallRemainsSafe(t *testing.T) {
	source := dynamicLookupModule(`object.get(node, "spec", {}, result)
result != {}`)
	require.False(t, ruleReadsStatus(source))
	require.False(t, ruleCorrelatesInput(source))
}

func TestDynamicStatusCache_LiteralPathInNestedCallRemainsSafe(t *testing.T) {
	source := dynamicLookupModule(`value := object.get(node, ["spec", "hostPID"], false)
value == true`)
	require.False(t, ruleReadsStatus(source))
}

func TestDynamicStatusCache_CaseSensitiveLiteralDoesNotReadStatus(t *testing.T) {
	for _, key := range []string{"STATUS", "Status", "statusCode", "statuses"} {
		source := dynamicLookupModule(fmt.Sprintf(`object.get(node, %q, {}) != {}`, key))
		require.False(t, ruleReadsStatus(source), "literal %q is not the lowercase status field", key)
	}
}

func TestDynamicStatusCache_LiteralStatusStillDetectedInBothCallShapes(t *testing.T) {
	for _, code := range []string{
		`object.get(node, "status", {}) != {}`,
		`object.get(node, "status", {}, value); value != {}`,
		`value := object.get(node, ["status", "ready"], false); value == false`,
	} {
		require.True(t, ruleReadsStatus(dynamicLookupModule(code)))
	}
}

func TestDynamicStatusCache_EmptyPathInStandaloneCallIsNotCacheSafe(t *testing.T) {
	source := dynamicLookupModule(`object.get(node, [], {}, whole)
whole != {}`)
	require.True(t, ruleReadsStatus(source))
}

func TestDynamicStatusCache_UnknownPathCannotHideInsideConditionalDefault(t *testing.T) {
	source := dynamicLookupModule(`key := node.metadata.annotations.field
object.get(node, key, object.get(node, "spec", {})) != {}`)
	require.True(t, ruleReadsStatus(source))
}

func TestDynamicStatusCache_AnyUnsafeRulePositionDisqualifiesControl(t *testing.T) {
	for _, unsafeFirst := range []bool{true, false} {
		safe := cacheEligibilityRule("safe", `deny contains node if { node := input[_]; node.kind == "Pod" }`, "Pod")
		unsafe := cacheEligibilityRule("unsafe", `deny contains node if { node := input[_]; k := lower("STATUS"); object.get(node, k, {}) != {} }`, "Pod")
		rules := []reporthandling.PolicyRule{safe, unsafe}
		if unsafeFirst {
			rules = []reporthandling.PolicyRule{unsafe, safe}
		}
		require.False(t, controlCacheEligible(&reporthandling.Control{Rules: rules}))
	}
}

func TestDynamicStatusCache_DynamicKeyAnalysisDoesNotAlterWholeClusterGuard(t *testing.T) {
	rule := cacheEligibilityRule("dynamic", `deny contains node if { node := input[_]; k := lower("STATUS"); object.get(node, k, {}) != {} }`, "Pod")
	rule.Match = append(rule.Match, reporthandling.RuleMatchObjects{Resources: []string{"Node"}})
	require.False(t, ruleCacheEligible(&reporthandling.Control{}, &rule))
	require.False(t, controlCacheEligible(&reporthandling.Control{Rules: []reporthandling.PolicyRule{rule}}))
}

func TestDynamicStatusCache_AggregatorRemainsUncacheable(t *testing.T) {
	rule := cacheEligibilityRule("aggregator", `deny contains node if { node := input[_]; object.get(node, "spec", {}) != {} }`, "Pod")
	rule.Attributes["resourcesAggregator"] = true
	require.False(t, ruleCacheEligible(&reporthandling.Control{}, &rule))
}

func TestDynamicStatusCache_StatusOnlyChangeReallyLeavesHashUnchanged(t *testing.T) {
	before := dynamicStatusPod(true)
	after := dynamicStatusPod(false)
	require.Equal(t, before.GetID(), after.GetID())
	require.Equal(t, scancache.ResourceHash(before.GetObject()), scancache.ResourceHash(after.GetObject()))
	require.NotEqual(t, before.GetObject()["status"], after.GetObject()["status"])
}

func TestDynamicStatusCache_DiskReloadCannotReviveUnsafePass(t *testing.T) {
	dir := t.TempDir()
	store, err := scancache.Load(dir, "policy")
	require.NoError(t, err)
	pod := dynamicStatusPod(true)
	source := dynamicVerdictRule(`concat("", ["sta", "tus"])`)
	first := sharedCAVerdicts(t, source, store, pod)
	require.Equal(t, apis.StatusPassed, first[pod.GetID()])
	require.NoError(t, store.Flush())
	loaded, err := scancache.Load(dir, "policy")
	require.NoError(t, err)
	changed := dynamicStatusPod(false)
	warm := sharedCAVerdicts(t, source, loaded, changed)
	cold := sharedCAVerdicts(t, source, nil, changed)
	require.Equal(t, cold, warm)
	require.Equal(t, apis.StatusFailed, warm[changed.GetID()])
}

func TestDynamicStatusCache_SafeLiteralRulesStillReadExistingCache(t *testing.T) {
	pod := dynamicStatusPod(true)
	store, err := scancache.Load(t.TempDir(), "policy")
	require.NoError(t, err)
	first := sharedCAVerdicts(t, perPodCARule, store, pod)
	require.Equal(t, apis.StatusPassed, first[pod.GetID()])
	second := sharedCAVerdicts(t, denyEveryInputRule, store, pod)
	require.Equal(t, first, second, "the fix must not disable ordinary per-object cache hits")
}

func TestDynamicStatusCache_RepeatedAnalysisKeepsBothAnswers(t *testing.T) {
	unsafe := dynamicVerdictRule(`lower("STATUS")`)
	safe := dynamicLookupModule(`object.get(node, "spec", {}) != {}`)
	for i := 0; i < 20; i++ {
		require.True(t, ruleReadsStatus(unsafe))
		require.False(t, ruleReadsStatus(safe))
	}
}

func TestDynamicStatusCache_UnparseableRuleIsNotCleared(t *testing.T) {
	for _, source := range []string{"package broken\ndeny {", "not rego", "package broken\ndeny := object.get("} {
		require.True(t, ruleReadsStatus(source))
	}
}

func TestDynamicStatusCache_ReadOnlyDetectionDoesNotChangeRule(t *testing.T) {
	rule := cacheEligibilityRule("dynamic", `deny contains node if { node := input[_]; k := lower("STATUS"); object.get(node, k, {}) != {} }`, "Pod")
	before := rule.Rule
	require.False(t, ruleCacheEligible(&reporthandling.Control{}, &rule))
	require.Equal(t, before, rule.Rule)
	require.Equal(t, "dynamic", rule.Name)
}

func TestDynamicStatusCache_AnnotationSelectedKeyCannotReuseOldVerdict(t *testing.T) {
	before := dynamicStatusPod(true)
	after := dynamicStatusPod(false)
	for _, pod := range []workloadinterface.IMetadata{before, after} {
		object := pod.GetObject()
		metadata := object["metadata"].(map[string]any)
		metadata["annotations"].(map[string]any)["field"] = "status"
		pod.SetObject(object)
	}
	source := dynamicVerdictRule(`pod.metadata.annotations.field`)
	store, err := scancache.Load(t.TempDir(), "policy")
	require.NoError(t, err)
	sharedCAVerdicts(t, source, store, before)
	got := sharedCAVerdicts(t, source, store, after)
	want := sharedCAVerdicts(t, source, nil, after)
	require.Equal(t, want, got)
	require.Equal(t, apis.StatusFailed, got[after.GetID()])
}

func TestDynamicStatusCache_ComputedArrayPathUsesCurrentStatus(t *testing.T) {
	source := dynamicVerdictRule(`lower("STATUS")`)
	source = strings.Replace(source, `state := object.get(pod, key, {})`, `state := object.get(pod, [key, "ready"], true)`, 1)
	source = strings.Replace(source, `object.get(state, "ready", true) == false`, `state == false`, 1)
	before := dynamicStatusPod(true)
	after := dynamicStatusPod(false)
	store, err := scancache.Load(t.TempDir(), "policy")
	require.NoError(t, err)
	sharedCAVerdicts(t, source, store, before)
	got := sharedCAVerdicts(t, source, store, after)
	require.Equal(t, apis.StatusFailed, got[after.GetID()])
	require.Equal(t, sharedCAVerdicts(t, source, nil, after), got)
}

func TestDynamicStatusCache_WholeObjectLookupUsesCurrentStatus(t *testing.T) {
	source := dynamicVerdictRule(`"spec"`)
	source = strings.Replace(source, "state := object.get(pod, key, {})\n  object.get(state, \"ready\", true) == false", `contains(json.marshal(object.get(pod, [], {})), "\"ready\":false")`, 1)
	before := dynamicStatusPod(true)
	after := dynamicStatusPod(false)
	store, err := scancache.Load(t.TempDir(), "policy")
	require.NoError(t, err)
	sharedCAVerdicts(t, source, store, before)
	got := sharedCAVerdicts(t, source, store, after)
	require.Equal(t, apis.StatusFailed, got[after.GetID()])
	require.Equal(t, sharedCAVerdicts(t, source, nil, after), got)
}

func TestDynamicStatusCache_ConstantAliasIsConservativelyExcluded(t *testing.T) {
	source := dynamicLookupModule(`key := "spec"; object.get(node, key, {}) != {}`)
	require.True(t, ruleReadsStatus(source), "without scope-aware constant propagation, variable keys are intentionally excluded")
}

func TestDynamicStatusCache_LiteralStringContainingStatusIsNotAKeyRead(t *testing.T) {
	source := dynamicLookupModule(`message := "status changed"; object.get(node, "spec", message) != {}`)
	require.False(t, ruleReadsStatus(source))
}

func TestDynamicStatusCache_MultipleLiteralLookupsRemainSafe(t *testing.T) {
	source := dynamicLookupModule(`object.get(node, "spec", {}) != {}
object.get(node, ["metadata", "name"], "") != ""
object.get(node, "kind", "") == "Pod"`)
	require.False(t, ruleReadsStatus(source))
	require.False(t, ruleCorrelatesInput(source))
}

func TestDynamicStatusCache_OneDynamicLookupAmongSafeCallsIsDetected(t *testing.T) {
	source := dynamicLookupModule(`object.get(node, "spec", {}) != {}
key := lower("STATUS")
object.get(node, key, {}) != {}
object.get(node, "kind", "") == "Pod"`)
	require.True(t, ruleReadsStatus(source))
}

func TestDynamicStatusCache_ControlWithOnlyLiteralLookupIsEligible(t *testing.T) {
	rule := cacheEligibilityRule("literal", `deny contains node if {
node := input[_]
object.get(node, "spec", {}) != {}
}`, "Pod")
	control := &reporthandling.Control{Rules: []reporthandling.PolicyRule{rule}}
	require.False(t, ruleReadsStatus(rule.Rule))
	require.False(t, ruleCorrelatesInput(rule.Rule))
	require.True(t, ruleCacheEligible(control, &rule))
	require.True(t, controlCacheEligible(control))
}
