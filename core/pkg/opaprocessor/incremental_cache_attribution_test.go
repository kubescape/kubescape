package opaprocessor

import (
	"context"
	"fmt"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/scancache"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// alertRule wraps deny bodies in a module. Each body binds one input element,
// so every rule here passes the existing input-correlation analysis.
func alertRule(bodies string) string {
	return "package armo_builtins\nimport rego.v1\n\n" + bodies
}

func reportingAlert(objects, paths string) string {
	return fmt.Sprintf(`{"alertMessage": "finding", "alertScore": 1, "packagename": "armo_builtins", "failedPaths": %s, "fixPaths": [], "alertObject": {"k8sApiObjects": [%s]}}`, paths, objects)
}

func labelledPod(namespace, name string, labels map[string]any, spec map[string]any) map[string]any {
	pod := podObject(namespace, name, spec)
	pod["metadata"].(map[string]any)["labels"] = labels
	return pod
}

// Pod "a" reports a renamed copy of itself, which is identical to its sibling
// "b": the reported object matches an evaluated input in identity and
// content, yet "b" did not produce the finding.
func TestIncrementalCacheRejectsAnExactCopyOfASibling(t *testing.T) {
	rule := alertRule(`deny contains msga if {
	pod := input[_]
	pod.metadata.name == "a"
	pod.spec.x == "bad"
	twin := json.patch(pod, [{"op": "replace", "path": "/metadata/name", "value": pod.metadata.labels.twin}])
	msga := ` + reportingAlert("twin", "[]") + `
}`)
	scenario := newCacheScenario(t, regoControl("C-TWIN", "twin", rule, "Pod"))
	scenario.put("/v1/pods", labelledPod("prod", "a", map[string]any{"twin": "b"}, map[string]any{"x": "bad"}))
	b := scenario.put("/v1/pods", labelledPod("prod", "b", map[string]any{"twin": "b"}, map[string]any{"x": "bad"}))

	full, incremental := scenario.step()
	require.Equal(t, "failed", full[b].Status)
	assert.Equal(t, full, incremental)

	scenario.objects["/v1/prod/Pod/a"]["spec"].(map[string]any)["x"] = "good"
	full, incremental = scenario.step()
	require.Equal(t, "passed", full[b].Status)
	assert.Equal(t, full, incremental, "b's failure came from a and must not be replayed")
}

// The same attack with the copy carried in the reporter's own data.
func TestIncrementalCacheRejectsACopyEmbeddedInAnotherObject(t *testing.T) {
	rule := alertRule(`deny contains msga if {
	pod := input[_]
	pod.metadata.name == "a"
	pod.spec.x == "bad"
	msga := ` + reportingAlert("pod.alertcopy", "[]") + `
}`)
	scenario := newCacheScenario(t, regoControl("C-EMBED", "embedded", rule, "Pod"))
	b := podObject("prod", "b", map[string]any{"x": "bad"})
	a := podObject("prod", "a", map[string]any{"x": "bad"})
	a["alertcopy"] = cloneObject(t, b)
	scenario.put("/v1/pods", a)
	bID := scenario.put("/v1/pods", b)

	full, incremental := scenario.step()
	require.Equal(t, "failed", full[bID].Status)
	assert.Equal(t, full, incremental)

	scenario.objects["/v1/prod/Pod/a"]["spec"].(map[string]any)["x"] = "good"
	full, incremental = scenario.step()
	require.Equal(t, "passed", full[bID].Status)
	assert.Equal(t, full, incremental)
}

// A Pod-only rule reports the Pod's owning ReplicaSet. Without the check the
// ReplicaSet's finding is lost once the Pod is replayed from the cache.
func TestIncrementalCacheKeepsAFindingAttributedToTheOwner(t *testing.T) {
	rule := alertRule(`deny contains msga if {
	pod := input[_]
	pod.spec.privileged == true
	owner := pod.metadata.ownerReferences[_]
	rs := {"apiVersion": "apps/v1", "kind": owner.kind, "metadata": {"name": owner.name, "namespace": pod.metadata.namespace}}
	msga := ` + reportingAlert("rs", "[]") + `
}`)
	scenario := newCacheScenario(t, regoControl("C-OWNER", "owner", rule, "Pod"))
	rs := scenario.put("apps/v1/replicasets", map[string]any{
		"apiVersion": "apps/v1", "kind": "ReplicaSet",
		"metadata": map[string]any{"name": "web", "namespace": "prod"},
	})
	pod := podObject("prod", "web-abcde", map[string]any{"privileged": true})
	pod["metadata"].(map[string]any)["ownerReferences"] = []any{map[string]any{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "web"}}
	podID := scenario.put("/v1/pods", pod)

	for _, step := range []string{"cold", "warm"} {
		full, incremental := scenario.step()
		require.Equal(t, "failed", full[rs].Status, step)
		assert.Equal(t, full, incremental, step)
	}
	assert.False(t, scenario.cached(podID), "results that are not attributable per object are not stored")

	scenario.objects[podID]["spec"].(map[string]any)["privileged"] = false
	full, incremental := scenario.step()
	assert.Equal(t, full, incremental)
}

// The audit-policy-content (C-0161) pattern: a host-sensor envelope reports a
// synthesized object whose identity no evaluated object has.
func TestIncrementalCacheKeepsAFindingOnASynthesizedIdentity(t *testing.T) {
	rule := alertRule(`deny contains msga if {
	obj := input[_]
	obj.kind == "ControlPlaneInfo"
	contains(obj.data.APIServerInfo.cmdLine, "--audit-policy-file")
	policy := {"apiVersion": "audit.k8s.io/v1", "kind": "Policy", "metadata": {"name": sprintf("%s - Audit policy file", [obj.metadata.name])}}
	msga := {"alertMessage": "audit policy", "alertScore": 5, "packagename": "armo_builtins", "failedPaths": [], "fixPaths": [], "alertObject": {"externalObjects": policy}}
}`)
	control := regoControl("C-AUDIT", "audit-policy", rule, "APIServerInfo")
	control.Rules[0].Match = []reporthandling.RuleMatchObjects{{APIGroups: []string{"hostdata.kubescape.cloud"}, APIVersions: []string{"v1beta0"}, Resources: []string{"APIServerInfo"}}}
	scenario := newCacheScenario(t, control)
	scenario.put("hostdata.kubescape.cloud/v1beta0/APIServerInfo", map[string]any{
		"apiVersion": "hostdata.kubescape.cloud/v1beta0",
		"kind":       "ControlPlaneInfo",
		"metadata":   map[string]any{"name": "cp-node-1"},
		"data": map[string]any{"APIServerInfo": map[string]any{
			"cmdLine": "kube-apiserver --audit-policy-file=/etc/kubernetes/audit.yaml",
		}},
	})
	const policyID = "audit.k8s.io/v1//Policy/cp-node-1 - Audit policy file"

	for _, step := range []string{"cold", "warm"} {
		full, incremental := scenario.step()
		require.Equal(t, "failed", full[policyID].Status, step)
		assert.Equal(t, full, incremental, step)
	}
}

// Pod "reporter" attributes a finding to Pod "x". Depending on the step, x is
// replayed from the cache (not evaluated) while reporter is evaluated.
const targetRule = `deny contains msga if {
	pod := input[_]
	target := pod.metadata.labels.target
	namespace := object.get(pod.metadata.labels, "targetNamespace", pod.metadata.namespace)
	victim := {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": target, "namespace": namespace}}
	msga := {"alertMessage": "targeted", "alertScore": 1, "packagename": "armo_builtins", "failedPaths": ["metadata.labels.target"], "fixPaths": [], "alertObject": {"k8sApiObjects": [victim]}}
}`

func TestIncrementalCacheDoesNotMixAFindingIntoAReplayedVerdict(t *testing.T) {
	scenario := newCacheScenario(t, regoControl("C-TARGET", "target", alertRule(targetRule), "Pod"))
	x := scenario.put("/v1/pods", labelledPod("prod", "x", map[string]any{}, map[string]any{}))
	reporter := scenario.put("/v1/pods", labelledPod("prod", "reporter", map[string]any{}, map[string]any{}))

	full, incremental := scenario.step()
	require.Equal(t, "passed", full[x].Status)
	assert.Equal(t, full, incremental)
	require.True(t, scenario.cached(x))

	// reporter changes, x does not: x is replayed while reporter blames it.
	scenario.objects[reporter]["metadata"].(map[string]any)["labels"] = map[string]any{"target": "x"}
	store := scenario.loadStore()
	opap := scenario.newProcessor(store)
	opap.InfoMap = map[string]apis.StatusInfo{} // as in a real scan; markResourcesSkipped skips a nil map
	control := scenario.control
	got, err := opap.processControl(context.Background(), &control, evaluationScope{})
	require.NoError(t, err)
	incremental = scenarioVerdicts(got)
	require.NoError(t, store.Flush())
	full = scenario.evaluate(nil)
	require.Equal(t, "failed", full[x].Status)
	assert.Equal(t, full, incremental)
	assert.Empty(t, opap.InfoMap, "re-evaluating without the cache leaves no state of the first evaluation")

	scenario.objects[reporter]["metadata"].(map[string]any)["labels"] = map[string]any{}
	full, incremental = scenario.step()
	require.Equal(t, "passed", full[x].Status)
	assert.Equal(t, full, incremental)
}

// scopeEnumerator puts every evaluated Pod in the rule's enumerated scope.
const scopeEnumerator = `package armo_builtins
import rego.v1

deny contains msga if {
	pod := input[_]
	msga := {"alertMessage": "in scope", "packagename": "armo_builtins", "alertScore": 0, "failedPaths": [], "fixPaths": [], "alertObject": {"k8sApiObjects": [pod]}}
}
`

// The enumerated scope is built from the objects evaluated in this scan,
// which excludes cache hits. A finding against a cached object must not be
// filtered out of the attribution check by that scope.
func TestIncrementalCacheKeepsAFindingAgainstACachedObjectOutsideTheEnumeratedScope(t *testing.T) {
	control := regoControl("C-ENUMSCOPE", "target", alertRule(targetRule), "Pod")
	control.Rules[0].ResourceEnumerator = scopeEnumerator
	require.True(t, controlCacheEligible(&control))

	scenario := newCacheScenario(t, control)
	x := scenario.put("/v1/pods", labelledPod("prod", "x", map[string]any{}, map[string]any{}))
	reporter := scenario.put("/v1/pods", labelledPod("prod", "reporter", map[string]any{}, map[string]any{}))

	full, incremental := scenario.step()
	require.Equal(t, "passed", full[x].Status)
	assert.Equal(t, full, incremental)
	require.True(t, scenario.cached(x), "x is replayed from the cache in the next scan")

	scenario.objects[reporter]["metadata"].(map[string]any)["labels"] = map[string]any{"target": "x"}
	full, incremental = scenario.step()
	require.Equal(t, "failed", full[x].Status)
	assert.Equal(t, full, incremental, "the reporter's finding against the cached x must be kept")
}

// pathlessBlameRule fails a Pod with hostPID on its own, and also lets a Pod
// blame the Pod its "target" label names, with a finding that carries no
// paths. Such a finding changes nothing in the paths of a Pod that also
// fails on its own, so only checking the blamed Pod cannot see it.
const pathlessBlameRule = `deny contains msga if {
	pod := input[_]
	pod.spec.hostPID == true
	msga := {"alertMessage": "hostPID", "alertScore": 1, "packagename": "armo_builtins", "failedPaths": ["spec.hostPID"], "fixPaths": [], "alertObject": {"k8sApiObjects": [pod]}}
}

deny contains msga if {
	pod := input[_]
	target := pod.metadata.labels.target
	victim := {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": target, "namespace": pod.metadata.namespace}}
	msga := {"alertMessage": "blamed", "alertScore": 1, "packagename": "armo_builtins", "failedPaths": [], "fixPaths": [], "alertObject": {"k8sApiObjects": [victim]}}
}`

// A Pod that passes but blames another must not be cached: once replayed,
// it is not evaluated, and its finding against the other Pod is lost.
func TestIncrementalCacheDoesNotCacheAPassingReporter(t *testing.T) {
	scenario := newCacheScenario(t, regoControl("C-REPORTER", "reporter", alertRule(pathlessBlameRule), "Pod"))
	x := scenario.put("/v1/pods", labelledPod("prod", "x", map[string]any{}, map[string]any{"hostPID": true}))
	y := scenario.put("/v1/pods", labelledPod("prod", "y", map[string]any{"target": "x"}, map[string]any{}))

	full, incremental := scenario.step()
	require.Equal(t, "failed", full[x].Status)
	require.Equal(t, "passed", full[y].Status)
	assert.Equal(t, full, incremental)
	assert.False(t, scenario.cached(y), "y's own evaluation reports x")

	// x is fixed and y is unchanged: y still blames x.
	scenario.objects[x]["spec"] = map[string]any{}
	full, incremental = scenario.step()
	require.Equal(t, "failed", full[x].Status, "y blames x")
	assert.Equal(t, full, incremental)
}

// A reporter that also fails on its own has the same verdict alone as in the
// batch, since its finding against x lands on x. It still must not be cached:
// its own evaluation reports another object.
func TestIncrementalCacheDoesNotCacheAFailingReporter(t *testing.T) {
	scenario := newCacheScenario(t, regoControl("C-REPORTER", "reporter", alertRule(pathlessBlameRule), "Pod"))
	x := scenario.put("/v1/pods", labelledPod("prod", "x", map[string]any{}, map[string]any{"hostPID": true}))
	y := scenario.put("/v1/pods", labelledPod("prod", "y", map[string]any{"target": "x"}, map[string]any{"hostPID": true}))

	full, incremental := scenario.step()
	require.Equal(t, "failed", full[y].Status)
	assert.Equal(t, full, incremental)
	assert.False(t, scenario.cached(y), "y's own evaluation reports x")

	// x is fixed and y is unchanged: y still blames x.
	scenario.objects[x]["spec"] = map[string]any{}
	full, incremental = scenario.step()
	require.Equal(t, "failed", full[x].Status, "y blames x")
	assert.Equal(t, full, incremental)
}

// reviewPathBlameRule is pathlessBlameRule with paths that are stored: a Pod
// with hostPID fails with one review path, and a Pod blames the Pod its
// "target" label names with another. failedPaths are not stored, so they
// could not tell the two findings apart.
const reviewPathBlameRule = `deny contains msga if {
	pod := input[_]
	pod.spec.hostPID == true
	msga := {"alertMessage": "hostPID", "alertScore": 1, "packagename": "armo_builtins", "failedPaths": [], "reviewPaths": ["spec.hostPID"], "fixPaths": [], "alertObject": {"k8sApiObjects": [pod]}}
}

deny contains msga if {
	pod := input[_]
	target := pod.metadata.labels.target
	victim := {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": target, "namespace": pod.metadata.namespace}}
	msga := {"alertMessage": "blamed", "alertScore": 1, "packagename": "armo_builtins", "failedPaths": [], "reviewPaths": ["metadata.labels"], "fixPaths": [], "alertObject": {"k8sApiObjects": [victim]}}
}`

// x fails on its own, and y's finding against x adds a path to x's verdict.
// x's status is the same alone and in the batch; only its paths differ. x
// must not be stored with the path y added: once y stops blaming x, an
// unchanged x would be replayed with it.
func TestIncrementalCacheDoesNotStorePathsAddedByAnotherObject(t *testing.T) {
	scenario := newCacheScenario(t, regoControl("C-PATHS", "paths", alertRule(reviewPathBlameRule), "Pod"))
	x := scenario.put("/v1/pods", labelledPod("prod", "x", map[string]any{}, map[string]any{"hostPID": true}))
	y := scenario.put("/v1/pods", labelledPod("prod", "y", map[string]any{"target": "x"}, map[string]any{}))
	ownPath := []armotypes.PosturePaths{{ResourceID: x, ReviewPath: "spec.hostPID"}}

	full, incremental := scenario.step()
	require.Equal(t, "failed", full[x].Status)
	require.Len(t, full[x].Rules, 1)
	require.Len(t, full[x].Rules[0].Paths, 2, "x has its own path and the one y's finding adds")
	assert.Equal(t, full, incremental)
	assert.False(t, scenario.cached(x), "x's paths alone differ from its paths in the batch")
	assert.False(t, scenario.cached(y), "y's own evaluation reports x")

	// y stops blaming x; x is unchanged and still fails on its own.
	scenario.objects[y]["metadata"].(map[string]any)["labels"] = map[string]any{}
	full, incremental = scenario.step()
	require.Equal(t, ownPath, full[x].Rules[0].Paths)
	assert.Equal(t, full, incremental, "x must not be replayed with the path y's finding added")

	// Nothing else blames x now, so its verdict is stored, with its own path.
	stored, ok := scenario.loadStore().Get("C-PATHS", x, scancache.ResourceHash(scenario.objects[x]))
	require.True(t, ok)
	require.Len(t, stored.ResourceAssociatedRules, 1)
	assert.Equal(t, ownPath, stored.ResourceAssociatedRules[0].Paths)

	full, incremental = scenario.step()
	assert.Equal(t, full, incremental, "warm")
}

// A cache candidate is not readable until it is verified, and a candidate
// that fails verification never becomes readable.
func TestIncrementalCacheCandidatesAreNotReadableBeforeVerification(t *testing.T) {
	scenario := newCacheScenario(t, regoControl("C-CANDIDATE", "candidate", alertRule(pathlessBlameRule), "Pod"))
	web := scenario.put("/v1/pods", labelledPod("prod", "web", map[string]any{}, map[string]any{"hostPID": true}))
	api := scenario.put("/v1/pods", labelledPod("prod", "api", map[string]any{}, map[string]any{}))
	reporter := scenario.put("/v1/pods", labelledPod("prod", "reporter", map[string]any{"target": "api"}, map[string]any{}))

	store := scenario.loadStore()
	opap := scenario.newProcessor(store)
	control := scenario.control
	cacheWrite := &cacheWriteState{deferred: true}
	_, err := opap.processControl(context.Background(), &control, evaluationScope{cacheWrite: cacheWrite})
	require.NoError(t, err)
	require.NotNil(t, cacheWrite.candidate)

	readable := func(id string) bool {
		_, ok := store.Get(control.ControlID, id, scancache.ResourceHash(scenario.objects[id]))
		return ok
	}
	for _, id := range []string{web, api, reporter} {
		assert.False(t, readable(id), "%s is readable before verification", id)
	}

	opap.storeVerifiedCandidate(context.Background(), cacheWrite.candidate)
	assert.True(t, readable(web), "web fails on its own and is verified")
	assert.False(t, readable(reporter), "reporter's own evaluation reports api")
	assert.False(t, readable(api), "api's verdict comes from reporter")
}

// Through Process, the control's cache candidate is verified and stored by
// processScope after the control's timed window, one scope at a time. The
// reporter and the Pod it blames are never stored, and every scan matches a
// full scan.
func TestIncrementalCacheProcessStoresOnlyVerifiedVerdicts(t *testing.T) {
	t.Setenv("LARGE_CLUSTER_SIZE", "1") // one scope per namespace
	control := regoControl("C-PROCESS", "process", alertRule(pathlessBlameRule), "Pod")
	scenario := newCacheScenario(t, control)
	x := scenario.put("/v1/pods", labelledPod("b", "x", map[string]any{}, map[string]any{"hostPID": true}))
	y := scenario.put("/v1/pods", labelledPod("b", "y", map[string]any{"target": "x"}, map[string]any{}))
	z := scenario.put("/v1/pods", labelledPod("a", "z", map[string]any{}, map[string]any{"hostPID": true}))

	run := func(store *scancache.Store) map[string]string {
		opap := scenario.newProcessor(store)
		policies := &cautils.Policies{Controls: map[string]reporthandling.Control{control.ControlID: control}}
		opap.AllPolicies = policies
		require.NoError(t, opap.Process(context.Background(), policies, nil))
		out := map[string]string{}
		for id, result := range opap.ResourcesResult {
			for _, c := range result.AssociatedControls {
				if c.ControlID == control.ControlID {
					out[id] = string(c.GetStatus(nil).Status())
				}
			}
		}
		return out
	}
	step := func(label string) {
		store := scenario.loadStore()
		full, incremental := run(nil), run(store)
		require.NoError(t, store.Flush())
		assert.Equal(t, full, incremental, label)
	}

	step("cold")
	assert.False(t, scenario.cached(y), "the reporter's own evaluation reports x")
	// x fails on its own with the same paths it gets in the batch (y's finding
	// carries none), so its own verdict is verified and stored.
	assert.True(t, scenario.cached(x))
	assert.True(t, scenario.cached(z), "z is verified in its own scope and stored")

	// x is replayed and y, never stored, is evaluated and blames it: the
	// finding against a replayed Pod makes the rule evaluate without the cache.
	step("warm")

	scenario.objects[x]["spec"] = map[string]any{} // y still blames x
	step("x fixed, y unchanged")
}

// includingEnumerator puts in scope the Pod each Pod carries in "includes",
// rather than the Pod itself. Carrying an exact copy of another Pod keeps that
// Pod's identity and content, so its hash is unchanged.
const includingEnumerator = `package armo_builtins
import rego.v1

deny contains msga if {
	pod := input[_]
	msga := {"alertMessage": "in scope", "packagename": "armo_builtins", "alertScore": 0, "failedPaths": [], "fixPaths": [], "alertObject": {"k8sApiObjects": [pod.includes]}}
}
`

// An object that passes only because another object's enumeration put it in
// scope must not be cached as passed.
func TestIncrementalCacheDoesNotCacheAPassGrantedByAnotherObjectsEnumeration(t *testing.T) {
	rule := alertRule(`deny contains msga if {
	pod := input[_]
	pod.spec.hostPID == true
	msga := ` + reportingAlert("pod", `["spec.hostPID"]`) + `
}`)
	control := regoControl("C-INCLUDE", "include", rule, "Pod")
	control.Rules[0].ResourceEnumerator = includingEnumerator
	require.True(t, controlCacheEligible(&control))

	scenario := newCacheScenario(t, control)
	ePod := podObject("prod", "e", map[string]any{})
	e := scenario.put("/v1/pods", ePod)
	fPod := podObject("prod", "f", map[string]any{})
	fPod["includes"] = cloneObject(t, ePod)
	f := scenario.put("/v1/pods", fPod)

	full, incremental := scenario.step()
	require.Equal(t, "passed", full[e].Status, "f's enumeration puts e in scope")
	assert.Equal(t, full, incremental)
	assert.False(t, scenario.cached(e), "e is not in scope on its own")

	// f no longer includes e; e is unchanged.
	delete(scenario.objects[f], "includes")
	full, incremental = scenario.step()
	_, inFullScan := full[e]
	require.False(t, inFullScan, "nothing puts e in scope any more")
	assert.Equal(t, full, incremental, "e must not be replayed as passed")
}

// g puts f in scope and f puts e in scope. f passes in the batch, and would
// pass alone if its own enumeration's output were taken as itself; but its
// own enumeration names e, so its pass comes from g. f must not be cached.
func TestIncrementalCacheDoesNotCacheAnObjectWhoseEnumerationNamesAnother(t *testing.T) {
	rule := alertRule(`deny contains msga if {
	pod := input[_]
	pod.spec.hostPID == true
	msga := ` + reportingAlert("pod", `["spec.hostPID"]`) + `
}`)
	control := regoControl("C-CHAIN", "chain", rule, "Pod")
	control.Rules[0].ResourceEnumerator = includingEnumerator
	require.True(t, controlCacheEligible(&control))

	scenario := newCacheScenario(t, control)
	ePod := podObject("prod", "e", map[string]any{})
	scenario.put("/v1/pods", ePod)
	fPod := podObject("prod", "f", map[string]any{})
	fPod["includes"] = cloneObject(t, ePod)
	f := scenario.put("/v1/pods", fPod)
	gPod := podObject("prod", "g", map[string]any{})
	gPod["includes"] = cloneObject(t, fPod)
	g := scenario.put("/v1/pods", gPod)

	full, incremental := scenario.step()
	require.Equal(t, "passed", full[f].Status, "g's enumeration puts f in scope")
	assert.Equal(t, full, incremental)
	assert.False(t, scenario.cached(f), "f's own enumeration names e, not f")

	// g no longer includes f; f is unchanged.
	delete(scenario.objects[g], "includes")
	full, incremental = scenario.step()
	_, inFullScan := full[f]
	require.False(t, inFullScan, "nothing puts f in scope any more")
	assert.Equal(t, full, incremental, "f must not be replayed as passed")
}

// With namespaces evaluated as separate scopes (the streaming and
// large-cluster layout), a reporter in one namespace blames a Pod in another.
func TestIncrementalCacheAcrossNamespaceScopes(t *testing.T) {
	scenario := newCacheScenario(t, regoControl("C-TARGET", "target", alertRule(targetRule), "Pod"))
	scenario.partitioned = true
	x := scenario.put("/v1/pods", labelledPod("b", "x", map[string]any{}, map[string]any{}))
	reporter := scenario.put("/v1/pods", labelledPod("a", "reporter", map[string]any{}, map[string]any{}))
	scenario.put("/v1/pods", labelledPod("b", "bystander", map[string]any{}, map[string]any{}))

	full, incremental := scenario.step()
	assert.Equal(t, full, incremental)

	scenario.objects[reporter]["metadata"].(map[string]any)["labels"] = map[string]any{"target": "x", "targetNamespace": "b"}
	full, incremental = scenario.step()
	require.Equal(t, "failed", full[x].Status)
	assert.Equal(t, full, incremental)

	scenario.objects[reporter]["metadata"].(map[string]any)["labels"] = map[string]any{}
	full, incremental = scenario.step()
	require.Equal(t, "passed", full[x].Status)
	assert.Equal(t, full, incremental)
}

// An attribution into an excluded namespace is dropped by the same filter
// for the batch and for the check, so it does not stop caching.
func TestIncrementalCacheAttributionCheckUsesTheNamespaceFilter(t *testing.T) {
	scenario := newCacheScenario(t, regoControl("C-TARGET", "target", alertRule(targetRule), "Pod"))
	scenario.excludedNamespaces = "kube-system"
	reporter := scenario.put("/v1/pods", labelledPod("prod", "reporter", map[string]any{"target": "dns", "targetNamespace": "kube-system"}, map[string]any{}))

	for _, step := range []string{"cold", "warm"} {
		full, incremental := scenario.step()
		require.Equal(t, "passed", full[reporter].Status, step)
		assert.Equal(t, full, incremental, step)
	}
	assert.True(t, scenario.cached(reporter))
}

func TestIncrementalCacheStillStoresAttributableFindings(t *testing.T) {
	tests := []struct {
		name string
		rule string
	}{
		{
			name: "several findings for one object",
			rule: alertRule(`deny contains msga if {
	pod := input[_]
	pod.spec.hostPID == true
	msga := ` + reportingAlert("pod", `["spec.hostPID"]`) + `
}

deny contains msga if {
	pod := input[_]
	pod.spec.hostIPC == true
	msga := ` + reportingAlert("pod", `["spec.hostIPC"]`) + `
}`),
		},
		{
			name: "a modified copy of the object itself",
			rule: alertRule(`deny contains msga if {
	pod := input[_]
	pod.spec.hostPID == true
	marked := json.patch(pod, [{"op": "add", "path": "/metadata/annotations", "value": {"flagged": "true"}}])
	msga := ` + reportingAlert("marked", `["spec.hostPID"]`) + `
}`),
		},
		{
			name: "the object itself as an external object",
			rule: alertRule(`deny contains msga if {
	pod := input[_]
	pod.spec.hostPID == true
	msga := {"alertMessage": "finding", "alertScore": 1, "packagename": "armo_builtins", "failedPaths": ["spec.hostPID"], "fixPaths": [], "alertObject": {"externalObjects": pod}}
}`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scenario := newCacheScenario(t, regoControl("C-OWN", "own", tt.rule, "Pod"))
			id := scenario.put("/v1/pods", podObject("prod", "web", map[string]any{"hostPID": true, "hostIPC": true}))
			scenario.put("/v1/pods", podObject("prod", "quiet", map[string]any{}))

			full, incremental := scenario.step()
			require.Equal(t, "failed", full[id].Status)
			assert.Equal(t, full, incremental)
			assert.True(t, scenario.cached(id), "an attributable finding is still cached")

			full, incremental = scenario.step()
			assert.Equal(t, full, incremental)

			scenario.objects[id]["spec"] = map[string]any{}
			full, incremental = scenario.step()
			require.Equal(t, "passed", full[id].Status)
			assert.Equal(t, full, incremental)
		})
	}
}

func TestIncrementalCacheDoesNotStoreFindingsWithRelatedObjects(t *testing.T) {
	rule := alertRule(`deny contains msga if {
	pod := input[_]
	pod.spec.hostPID == true
	msga := {"alertMessage": "finding", "alertScore": 1, "packagename": "armo_builtins", "failedPaths": ["spec.hostPID"], "fixPaths": [], "alertObject": {"k8sApiObjects": [pod]}, "relatedObjects": [{"object": pod, "failedPaths": ["spec"]}]}
}`)
	scenario := newCacheScenario(t, regoControl("C-RELATED", "related", rule, "Pod"))
	id := scenario.put("/v1/pods", podObject("prod", "web", map[string]any{"hostPID": true}))

	full, incremental := scenario.step()
	require.Equal(t, "failed", full[id].Status)
	assert.Equal(t, full, incremental)
	assert.False(t, scenario.cached(id))
}

// The uncached re-evaluation can fail where the cached one did not: here a
// planted, stale verdict hides an object whose evaluation errors. The error
// outcome must be returned, never the replayed verdict, and InfoMap must only
// hold what the re-evaluation recorded.
func TestIncrementalCacheReturnsTheRerunErrorOutcome(t *testing.T) {
	rule := alertRule(`f(p) := 1 if p.metadata.name == "boom"

f(p) := 2 if p.metadata.name == "boom"

deny contains msga if {
	pod := input[_]
	f(pod) == 1
	msga := ` + reportingAlert("pod", "[]") + `
}

deny contains msga if {
	pod := input[_]
	pod.metadata.name == "reporter"
	ghost := {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "ghost", "namespace": "prod"}}
	msga := ` + reportingAlert("ghost", "[]") + `
}`)
	scenario := newCacheScenario(t, regoControl("C-ERR", "err", rule, "Pod"))
	boom := scenario.put("/v1/pods", podObject("prod", "boom", map[string]any{}))
	reporter := scenario.put("/v1/pods", podObject("prod", "reporter", map[string]any{}))

	store := scenario.loadStore()
	planted := resourcesresults.ResourceAssociatedControl{
		ControlID:               "C-ERR",
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Name: "err", Status: apis.StatusPassed}},
	}
	store.Put("C-ERR", boom, scancache.ResourceHash(scenario.objects[boom]), planted)

	opap := scenario.newProcessor(store)
	opap.InfoMap = map[string]apis.StatusInfo{} // as in a real scan; markResourcesSkipped skips a nil map
	control := scenario.control
	got, err := opap.processControl(context.Background(), &control, evaluationScope{})
	require.Error(t, err)
	require.Contains(t, got, boom)
	assert.Equal(t, apis.StatusSkipped, got[boom].ResourceAssociatedRules[0].Status, "the planted verdict must not be returned")
	assert.Equal(t, apis.StatusSkipped, opap.InfoMap[boom].InnerStatus)
	assert.Equal(t, apis.StatusSkipped, opap.InfoMap[reporter].InnerStatus)
	assert.Len(t, opap.InfoMap, 2)
}

func TestPrecheckCacheAttributionRejectsUnidentifiableInput(t *testing.T) {
	opap := NewOPAProcessor(newCacheScenario(t, reporthandling.Control{}).session(), resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	pod := podObject("prod", "web", map[string]any{})

	_, ok, reason := opap.precheckCacheAttribution([]map[string]any{pod, cloneObject(t, pod)}, nil)
	assert.False(t, ok)
	assert.Contains(t, reason, "share the identity")

	unidentifiable := map[string]any{"not": "a resource"}
	require.Nil(t, objectsenvelopes.NewObject(unidentifiable))
	_, ok, reason = opap.precheckCacheAttribution([]map[string]any{unidentifiable}, nil)
	assert.False(t, ok)
	assert.Contains(t, reason, "no resource identity")
}

func TestSamePosturePaths(t *testing.T) {
	a := armotypes.PosturePaths{ResourceID: "r", FailedPath: "spec.a"}
	b := armotypes.PosturePaths{ResourceID: "r", FixPath: armotypes.FixPath{Path: "spec.b", Value: "x"}}
	c := armotypes.PosturePaths{ResourceID: "r", FixPath: armotypes.FixPath{Path: "spec.b", Value: "y"}}

	assert.True(t, samePosturePaths(nil, nil))
	assert.True(t, samePosturePaths([]armotypes.PosturePaths{a, b}, []armotypes.PosturePaths{b, a}), "order does not matter")
	assert.False(t, samePosturePaths([]armotypes.PosturePaths{a, a}, []armotypes.PosturePaths{a}), "multiplicity matters")
	assert.False(t, samePosturePaths([]armotypes.PosturePaths{a, b}, []armotypes.PosturePaths{a, c}), "every field matters")
}

// The per-object verification must evaluate with the same rule source and
// policy inputs as the batch it checks. Here the finding exists only because
// of a control input: a verification that saw other inputs would not
// reproduce web's verdict, and web would not be stored.
func TestVerifyCacheAttributionEvaluatesWithTheBatchInputs(t *testing.T) {
	rule := alertRule(`deny contains msga if {
	pod := input[_]
	pod.metadata.name in data.postureControlInputs.forbiddenNames
	msga := ` + reportingAlert("pod", `["metadata.name"]`) + `
}`)
	control := regoControl("C-INPUTS", "forbidden-names", rule, "Pod")
	control.FixedInput = map[string][]string{"forbiddenNames": {"web"}}
	scenario := newCacheScenario(t, control)
	web := scenario.put("/v1/pods", podObject("prod", "web", map[string]any{}))
	scenario.put("/v1/pods", podObject("prod", "api", map[string]any{}))

	opap := scenario.newProcessor(scenario.loadStore())
	evaluated := 0
	for _, scope := range opap.evaluationScopes() {
		results, attribution, err := opap.evaluateRuleOnScope(context.Background(), &control.Rules[0], control.FixedInput, scope, &control, true)
		require.NoError(t, err)
		if result, ok := results[web]; ok {
			evaluated++
			require.Equal(t, apis.StatusFailed, result.Status, "the control input makes web fail")
		}
		assert.False(t, attribution.unsafe, attribution.reason)
	}
	require.Equal(t, 1, evaluated)

	full, incremental := scenario.step()
	require.Equal(t, "failed", full[web].Status)
	assert.Equal(t, full, incremental)
	assert.True(t, scenario.cached(web), "an attributable finding that depends on a control input is cached")
}
