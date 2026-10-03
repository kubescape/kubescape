package opaprocessor

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/resources"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleTestRuleRego = `
package armo_builtins
import rego.v1

deny contains msga if {
	some pod in input
	pod.kind == "Pod"
	pod.metadata.name == "bad-pod"
	msga := {
		"alertMessage": "bad pod found",
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [pod]}
	}
}
`

const sampleTestRuleRegoWithDeps = `
package armo_builtins
import rego.v1

deny contains msga if {
	some pod in input
	pod.kind == "Pod"
	some allowed in data.postureControlInputs.allowedNames
	pod.metadata.name == allowed
	msga := {
		"alertMessage": "allowed name matched",
		"packagename": "armo_builtins",
		"alertScore": 5,
		"failedPaths": [],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [pod]}
	}
}
`

func testMakeRule(name, regoText string) *reporthandling.PolicyRule {
	return &reporthandling.PolicyRule{
		PortalBase:   armotypes.PortalBase{Name: name},
		RuleLanguage: reporthandling.RegoLanguage,
		Rule:         regoText,
	}
}

// TestPreparedQueryCache_Hit verifies that repeated calls for the same rule and dependencies
// reuse the cached PreparedEvalQuery and do not prepare repeatedly.
func TestPreparedQueryCache_Hit(t *testing.T) {
	opap := NewOPAProcessor(nil, nil, "test", "", "", false, nil)
	ctx := context.Background()
	rule := testMakeRule("test-rule-hit", sampleTestRuleRego)
	deps := resources.RegoDependenciesData{
		PostureControlInputs: map[string][]string{"allowedNames": {"good-pod"}},
	}

	// First call: cache miss, compiles and prepares
	pq1, err := opap.getPreparedQuery(ctx, rule.Name, rule.Rule, deps)
	require.NoError(t, err)

	opap.preparedMu.RLock()
	cacheSize1 := len(opap.preparedQueries)
	opap.preparedMu.RUnlock()
	assert.Equal(t, 1, cacheSize1, "expected 1 entry in cache after first prepare")

	// Second call: cache hit, should return without expanding the cache
	pq2, err := opap.getPreparedQuery(ctx, rule.Name, rule.Rule, deps)
	require.NoError(t, err)

	opap.preparedMu.RLock()
	cacheSize2 := len(opap.preparedQueries)
	opap.preparedMu.RUnlock()
	assert.Equal(t, 1, cacheSize2, "expected cache size to stay 1 on hit")

	// Verify both queries function and give identical eval results
	pod := []map[string]any{{"kind": "Pod", "metadata": map[string]any{"name": "bad-pod", "namespace": "default"}}}
	res1, err := opap.regoEval(ctx, pod, pq1)
	require.NoError(t, err)
	res2, err := opap.regoEval(ctx, pod, pq2)
	require.NoError(t, err)
	assert.Equal(t, res1, res2)
	assert.Len(t, res1, 1)
}

// TestPreparedQueryCache_DifferentRulesAndInputs verifies that different rules and
// different configInputs obtain separate cache entries.
func TestPreparedQueryCache_DifferentRulesAndInputs(t *testing.T) {
	opap := NewOPAProcessor(nil, nil, "test", "", "", false, nil)
	ctx := context.Background()

	ruleA := testMakeRule("rule-a", sampleTestRuleRego)
	ruleB := testMakeRule("rule-b", sampleTestRuleRegoWithDeps)

	deps1 := resources.RegoDependenciesData{
		PostureControlInputs: map[string][]string{"allowedNames": {"foo"}},
	}
	deps2 := resources.RegoDependenciesData{
		PostureControlInputs: map[string][]string{"allowedNames": {"bar"}},
	}

	// Rule A with deps1
	_, err := opap.getPreparedQuery(ctx, ruleA.Name, ruleA.Rule, deps1)
	require.NoError(t, err)

	// Rule B with deps1 (different rule)
	_, err = opap.getPreparedQuery(ctx, ruleB.Name, ruleB.Rule, deps1)
	require.NoError(t, err)

	// Rule B with deps2 (same rule, different configInputs)
	_, err = opap.getPreparedQuery(ctx, ruleB.Name, ruleB.Rule, deps2)
	require.NoError(t, err)

	opap.preparedMu.RLock()
	cacheSize := len(opap.preparedQueries)
	opap.preparedMu.RUnlock()

	assert.Equal(t, 3, cacheSize, "expected 3 distinct entries in cache")
}

// TestPreparedQueryCache_Concurrent verifies concurrent calls across N goroutines
// safely evaluate using the cached PreparedEvalQuery without races.
func TestPreparedQueryCache_Concurrent(t *testing.T) {
	opap := NewOPAProcessor(nil, nil, "test", "", "", false, nil)
	ctx := context.Background()
	rule := testMakeRule("concurrent-rule", sampleTestRuleRego)
	deps := resources.RegoDependenciesData{}
	getRuleData := func(r *reporthandling.PolicyRule) string { return r.Rule }

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errs := make([]error, numGoroutines)
	counts := make([]int, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			var podName string
			if idx%2 == 0 {
				podName = "bad-pod"
			} else {
				podName = "good-pod"
			}
			objects := []map[string]any{
				{"kind": "Pod", "metadata": map[string]any{"name": podName, "namespace": fmt.Sprintf("ns-%d", idx)}},
			}
			res, err := opap.runRegoOnK8s(ctx, rule, objects, getRuleData, deps, "C-0001")
			if err != nil {
				errs[idx] = err
				return
			}
			counts[idx] = len(res)
		}(i)
	}

	wg.Wait()

	for i := 0; i < numGoroutines; i++ {
		require.NoError(t, errs[i], "goroutine %d failed", i)
		if i%2 == 0 {
			assert.Equal(t, 1, counts[i], "bad-pod should fail")
		} else {
			assert.Equal(t, 0, counts[i], "good-pod should pass")
		}
	}

	// Cache should have exactly 1 entry for this rule
	opap.preparedMu.RLock()
	cacheSize := len(opap.preparedQueries)
	opap.preparedMu.RUnlock()
	assert.Equal(t, 1, cacheSize)
}

// TestPreparedQueryCache_ErrorNotCached verifies that preparation failures (e.g. syntax error
// or canceled context) are not cached.
func TestPreparedQueryCache_ErrorNotCached(t *testing.T) {
	opap := NewOPAProcessor(nil, nil, "test", "", "", false, nil)
	deps := resources.RegoDependenciesData{}

	// 1. Canceled context
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	validRule := testMakeRule("valid-rule", sampleTestRuleRego)

	_, err := opap.getPreparedQuery(canceledCtx, validRule.Name, validRule.Rule, deps)
	require.Error(t, err)

	opap.preparedMu.RLock()
	assert.Empty(t, opap.preparedQueries, "error from canceled context must not be cached")
	opap.preparedMu.RUnlock()

	// 2. Syntax error in rule
	syntaxErrRule := testMakeRule("syntax-err-rule", "package armo_builtins\ninvalid syntax !!!")
	_, err = opap.getPreparedQuery(context.Background(), syntaxErrRule.Name, syntaxErrRule.Rule, deps)
	require.Error(t, err)

	opap.preparedMu.RLock()
	assert.Empty(t, opap.preparedQueries, "error from invalid rule must not be cached")
	opap.preparedMu.RUnlock()

	// 3. Subsequent call with valid rule and context succeeds and populates cache
	_, err = opap.getPreparedQuery(context.Background(), validRule.Name, validRule.Rule, deps)
	require.NoError(t, err)

	opap.preparedMu.RLock()
	cacheSizeAfter := len(opap.preparedQueries)
	opap.preparedMu.RUnlock()
	assert.Equal(t, 1, cacheSizeAfter, "valid prepare must populate cache")
}

// BenchmarkRunRegoAcrossScopes_Uncached evaluates the same rule across 20 scopes using the uncached baseline
// (rego.New + PrepareForEval per scope, matching the pre-optimization code path).
func BenchmarkRunRegoAcrossScopes_Uncached(b *testing.B) {
	opap := NewOPAProcessor(nil, nil, "test", "", "", false, nil)
	ctx := context.Background()
	rule := testMakeRule("bench-rule-uncached", sampleTestRuleRego)
	deps := resources.RegoDependenciesData{}
	ruleData := rule.Rule

	const numScopes = 20
	scopes := make([][]map[string]any, numScopes)
	for s := 0; s < numScopes; s++ {
		scopes[s] = []map[string]any{
			{"kind": "Pod", "metadata": map[string]any{"name": fmt.Sprintf("pod-%d", s), "namespace": fmt.Sprintf("ns-%d", s)}},
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for s := 0; s < numScopes; s++ {
			compiled, regoVersion, err := opap.getCompiledRule(ctx, rule.Name, ruleData, opap.printEnabled)
			if err != nil {
				b.Fatalf("getCompiledRule failed: %v", err)
			}
			store, err := deps.TOStorage()
			if err != nil {
				b.Fatalf("TOStorage failed: %v", err)
			}
			regoInst := rego.New(
				rego.SetRegoVersion(regoVersion),
				rego.Query("data.armo_builtins"),
				rego.Compiler(compiled),
				rego.Store(store),
				rego.EnablePrintStatements(opap.printEnabled),
				rego.PrintHook(opap),
			)
			pq, err := regoInst.PrepareForEval(ctx)
			if err != nil {
				b.Fatalf("PrepareForEval failed: %v", err)
			}
			_, err = opap.regoEval(ctx, scopes[s], pq)
			if err != nil {
				b.Fatalf("regoEval failed: %v", err)
			}
		}
	}
}

// BenchmarkRunRegoAcrossScopes_Cached evaluates the same rule across 20 scopes using the cached PreparedEvalQuery.
func BenchmarkRunRegoAcrossScopes_Cached(b *testing.B) {
	opap := NewOPAProcessor(nil, nil, "test", "", "", false, nil)
	ctx := context.Background()
	rule := testMakeRule("bench-rule-cached", sampleTestRuleRego)
	deps := resources.RegoDependenciesData{}
	getRuleData := func(r *reporthandling.PolicyRule) string { return r.Rule }

	const numScopes = 20
	scopes := make([][]map[string]any, numScopes)
	for s := 0; s < numScopes; s++ {
		scopes[s] = []map[string]any{
			{"kind": "Pod", "metadata": map[string]any{"name": fmt.Sprintf("pod-%d", s), "namespace": fmt.Sprintf("ns-%d", s)}},
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for s := 0; s < numScopes; s++ {
			_, err := opap.runRegoOnK8s(ctx, rule, scopes[s], getRuleData, deps, "C-0001")
			if err != nil {
				b.Fatalf("runRegoOnK8s failed: %v", err)
			}
		}
	}
}
