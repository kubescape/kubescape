package opaprocessor

import (
	"context"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/scancache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// substitutingEnumerator puts each Pod in scope as itself, unless it carries
// "includes": then it puts the object it carries in scope instead. The
// enumerator's output is written into the catalog under the output's own
// identity, so a Pod carrying an object with another Pod's identity replaces
// that Pod's catalog entry.
const substitutingEnumerator = `package armo_builtins
import rego.v1

deny contains msga if {
	pod := input[_]
	not pod.includes
	msga := {"alertMessage": "in scope", "packagename": "armo_builtins", "alertScore": 0, "failedPaths": [], "fixPaths": [], "alertObject": {"k8sApiObjects": [pod]}}
}

deny contains msga if {
	pod := input[_]
	msga := {"alertMessage": "in scope", "packagename": "armo_builtins", "alertScore": 0, "failedPaths": [], "fixPaths": [], "alertObject": {"k8sApiObjects": [pod.includes]}}
}
`

func substitutingControl(t *testing.T) *cacheScenario {
	t.Helper()
	rule := alertRule(`deny contains msga if {
	pod := input[_]
	pod.spec.hostPID == true
	msga := ` + reportingAlert("pod", `["spec.hostPID"]`) + `
}`)
	control := regoControl("C-SUBST", "subst", rule, "Pod")
	control.Rules[0].ResourceEnumerator = substitutingEnumerator
	require.True(t, controlCacheEligible(&control))
	return newCacheScenario(t, control)
}

// c is evaluated and verified as it is, while n's enumeration replaces c's
// catalog entry with an object of c's identity and other content. c's verdict
// must not be stored under the hash of that other object: once c really has
// that content, it would be replayed with a verdict computed from c's old
// content.
func TestIncrementalCacheDoesNotStoreAVerdictUnderASubstitutedObjectsHash(t *testing.T) {
	scenario := substitutingControl(t)
	c := scenario.put("/v1/pods", podObject("prod", "c", map[string]any{}))
	failingC := podObject("prod", "c", map[string]any{"hostPID": true})
	nPod := podObject("prod", "n", map[string]any{})
	nPod["includes"] = cloneObject(t, failingC)
	n := scenario.put("/v1/pods", nPod)

	full, incremental := scenario.step()
	require.Equal(t, "passed", full[c].Status)
	assert.Equal(t, full, incremental)
	_, storedUnderSubstitute := scenario.loadStore().Get("C-SUBST", c, scancache.ResourceHash(failingC))
	assert.False(t, storedUnderSubstitute, "c's verdict is stored under the hash of n's substitute")

	// c now really has the substitute's content; n carries nothing.
	scenario.objects[c]["spec"] = map[string]any{"hostPID": true}
	delete(scenario.objects[n], "includes")
	full, incremental = scenario.step()
	require.Equal(t, "failed", full[c].Status)
	assert.Equal(t, full, incremental, "c's old verdict must not be replayed for its new content")
}

// The same substitution while c's verdict is replayed from the cache: the
// replayed verdict must not be stored again under the substitute's hash.
func TestIncrementalCacheDoesNotRestoreAReplayedVerdictUnderASubstitutedObjectsHash(t *testing.T) {
	scenario := substitutingControl(t)
	c := scenario.put("/v1/pods", podObject("prod", "c", map[string]any{}))
	full, incremental := scenario.step()
	require.Equal(t, full, incremental)
	require.True(t, scenario.cached(c))

	failingC := podObject("prod", "c", map[string]any{"hostPID": true})
	nPod := podObject("prod", "n", map[string]any{})
	nPod["includes"] = cloneObject(t, failingC)
	n := scenario.put("/v1/pods", nPod)
	full, incremental = scenario.step()
	require.Equal(t, full, incremental)
	_, storedUnderSubstitute := scenario.loadStore().Get("C-SUBST", c, scancache.ResourceHash(failingC))
	assert.False(t, storedUnderSubstitute, "c's replayed verdict is stored under the hash of n's substitute")

	scenario.objects[c]["spec"] = map[string]any{"hostPID": true}
	delete(scenario.objects[n], "includes")
	full, incremental = scenario.step()
	require.Equal(t, "failed", full[c].Status)
	assert.Equal(t, full, incremental, "c's old verdict must not be replayed for its new content")
}

// Binding a stored verdict to the hash its object was looked up with must not
// reject a valid one: a cache hit, including a control whose every object is a
// hit, and an evaluated object are still candidates, under their own hashes.
func TestIncrementalCacheStillStoresHitsAndEvaluatedObjectsUnderTheirHashes(t *testing.T) {
	scenario := substitutingControl(t)
	a := scenario.put("/v1/pods", podObject("prod", "a", map[string]any{}))
	b := scenario.put("/v1/pods", podObject("prod", "b", map[string]any{"hostPID": true}))

	full, incremental := scenario.step()
	require.Equal(t, full, incremental)
	require.True(t, scenario.cached(a))
	require.True(t, scenario.cached(b))

	candidateHashes := func() map[string]string {
		t.Helper()
		opap := scenario.newProcessor(scenario.loadStore())
		control := scenario.control
		cacheWrite := &cacheWriteState{deferred: true}
		_, err := opap.processControl(context.Background(), &control, evaluationScope{cacheWrite: cacheWrite})
		require.NoError(t, err)
		require.NotNil(t, cacheWrite.candidate)
		hashes := map[string]string{}
		for _, entry := range cacheWrite.candidate.entries {
			hashes[entry.resourceID] = entry.hash
		}
		return hashes
	}
	ownHashes := func() map[string]string {
		return map[string]string{
			a: scancache.ResourceHash(scenario.objects[a]),
			b: scancache.ResourceHash(scenario.objects[b]),
		}
	}

	// Every object is a cache hit, so no rule evaluates anything.
	assert.Equal(t, ownHashes(), candidateHashes(), "warm scan")

	// a is a hit and b, changed, is evaluated.
	scenario.objects[b]["spec"] = map[string]any{}
	assert.Equal(t, ownHashes(), candidateHashes(), "a replayed, b evaluated")

	full, incremental = scenario.step()
	assert.Equal(t, full, incremental)
	assert.True(t, scenario.cached(a))
	assert.True(t, scenario.cached(b))
}

// An object looked up with two different hashes in one control's evaluation,
// or whose hash could not be computed, has no hash its verdict can be stored
// under.
func TestCacheWriteStateBindsOneLookupHashPerObject(t *testing.T) {
	var state cacheWriteState
	state.observeLookup("a", "h1")
	state.observeLookup("a", "h1")
	state.observeLookup("b", "h1")
	state.observeLookup("b", "h2")
	state.observeLookup("b", "h1")
	state.observeLookup("c", "")

	hash, ok := state.lookupHash("a")
	assert.True(t, ok)
	assert.Equal(t, "h1", hash)
	_, ok = state.lookupHash("b")
	assert.False(t, ok, "b was looked up with two hashes")
	_, ok = state.lookupHash("c")
	assert.False(t, ok, "c has no hash")
	_, ok = state.lookupHash("d")
	assert.False(t, ok, "d was never looked up")

	var unset *cacheWriteState
	unset.observeLookup("a", "h1") // must not panic
	_, ok = unset.lookupHash("a")
	assert.False(t, ok)
}
