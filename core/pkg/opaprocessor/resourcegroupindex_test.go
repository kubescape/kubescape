package opaprocessor

import (
	"fmt"
	"sync"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestWorkload(apiVersion, kind, name string) workloadinterface.IMetadata {
	return workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]any{
			"name":      name,
			"namespace": "default",
		},
	})
}

func TestNewResourceGroupIndexSortsGroupsAndParsesKeys(t *testing.T) {
	deployment := newTestWorkload("apps/v1", "Deployment", "d")
	pod := newTestWorkload("v1", "Pod", "p")

	// Insertion order is deliberately the reverse of the sorted order; Go map
	// iteration would otherwise leave the group order undefined.
	k8sResources := cautils.K8SResources{
		"apps/v1/deployments": {deployment.GetID()},
		"/v1/pods":            {pod.GetID()},
	}
	allResources := map[string]workloadinterface.IMetadata{
		deployment.GetID(): deployment,
		pod.GetID():        pod,
	}

	index := newResourceGroupIndex(k8sResources, allResources)

	require.Len(t, index.groups, 2)
	assert.Equal(t, 2, index.objectCount)

	assert.Equal(t, "", index.groups[0].group, "%q sorts first", "/v1/pods")
	assert.Equal(t, "v1", index.groups[0].version)
	assert.Equal(t, "pods", index.groups[0].resource)

	assert.Equal(t, "apps", index.groups[1].group)
	assert.Equal(t, "v1", index.groups[1].version)
	assert.Equal(t, "deployments", index.groups[1].resource)
}

func TestNewResourceGroupIndexResolvesObjectsAndKinds(t *testing.T) {
	deployment := newTestWorkload("apps/v1", "Deployment", "d")
	k8sResources := cautils.K8SResources{"apps/v1/deployments": {deployment.GetID()}}
	allResources := map[string]workloadinterface.IMetadata{deployment.GetID(): deployment}

	index := newResourceGroupIndex(k8sResources, allResources)

	require.Len(t, index.groups, 1)
	require.Len(t, index.groups[0].objects, 1)
	assert.Same(t, deployment, index.groups[0].objects[0].object)
	assert.Equal(t, "Deployment", index.groups[0].objects[0].kind, "kind is resolved once at build time")
}

// A collected ID with no object behind it was dropped by the per-match lookup
// before the index existed; it must be dropped at build time now, and must not
// consume an ordinal.
func TestNewResourceGroupIndexDropsUnresolvableIDs(t *testing.T) {
	deployment := newTestWorkload("apps/v1", "Deployment", "d")
	k8sResources := cautils.K8SResources{
		"apps/v1/deployments": {"missing-id", deployment.GetID(), "nil-id"},
	}
	allResources := map[string]workloadinterface.IMetadata{
		deployment.GetID(): deployment,
		"nil-id":           nil,
	}

	index := newResourceGroupIndex(k8sResources, allResources)

	require.Len(t, index.groups, 1)
	require.Len(t, index.groups[0].objects, 1)
	assert.Same(t, deployment, index.groups[0].objects[0].object)
	assert.Equal(t, 1, index.objectCount)
}

// The same object can be collected under several GVR keys. Ordinals are the
// de-duplication key during matching, so both slots must share one.
func TestNewResourceGroupIndexSharesOrdinalsAcrossAliases(t *testing.T) {
	sandbox := newTestWorkload("agents.x-k8s.io/v1alpha1", "Sandbox", "s")
	k8sResources := cautils.K8SResources{
		"agents.x-k8s.io/v1alpha1/sandbox":   {sandbox.GetID()},
		"agents.x-k8s.io/v1alpha1/sandboxes": {sandbox.GetID()},
	}
	allResources := map[string]workloadinterface.IMetadata{sandbox.GetID(): sandbox}

	index := newResourceGroupIndex(k8sResources, allResources)

	require.Len(t, index.groups, 2)
	require.Len(t, index.groups[0].objects, 1)
	require.Len(t, index.groups[1].objects, 1)
	assert.Equal(t, index.groups[0].objects[0].ordinal, index.groups[1].objects[0].ordinal)
	assert.Equal(t, 1, index.objectCount, "one object, one ordinal")
}

func TestNewResourceGroupIndexEmpty(t *testing.T) {
	index := newResourceGroupIndex(cautils.K8SResources{}, map[string]workloadinterface.IMetadata{})

	assert.Empty(t, index.groups)
	assert.Equal(t, 0, index.objectCount)
	assert.Empty(t, getKubernetesObjects(index, []reporthandling.RuleMatchObjects{{
		APIGroups:   []string{"*"},
		APIVersions: []string{"*"},
		Resources:   []string{"*"},
	}}))
}

// The rule's input is an array, so the objects must come back in
// match-declaration order rather than in the index's own group order.
func TestGetKubernetesObjectsPreservesMatchDeclarationOrder(t *testing.T) {
	deployment := newTestWorkload("apps/v1", "Deployment", "d")
	pod := newTestWorkload("v1", "Pod", "p")
	k8sResources := cautils.K8SResources{
		"apps/v1/deployments": {deployment.GetID()},
		"/v1/pods":            {pod.GetID()},
	}
	allResources := map[string]workloadinterface.IMetadata{
		deployment.GetID(): deployment,
		pod.GetID():        pod,
	}
	index := newResourceGroupIndex(k8sResources, allResources)

	// "apps/v1/deployments" sorts after "/v1/pods", so an index-ordered result
	// would put the pod first.
	objects := getKubernetesObjects(index, []reporthandling.RuleMatchObjects{
		{APIGroups: []string{"apps"}, APIVersions: []string{"v1"}, Resources: []string{"deployments"}},
		{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"pods"}},
	})

	require.Len(t, objects, 2)
	assert.Same(t, deployment, objects[0])
	assert.Same(t, pod, objects[1])
}

// A match block routinely names the same object under several combinations
// (a wildcard group alongside the concrete one, say). It must be emitted once.
func TestGetKubernetesObjectsEmitsEachObjectOnce(t *testing.T) {
	deployment := newTestWorkload("apps/v1", "Deployment", "d")
	k8sResources := cautils.K8SResources{"apps/v1/deployments": {deployment.GetID()}}
	allResources := map[string]workloadinterface.IMetadata{deployment.GetID(): deployment}
	index := newResourceGroupIndex(k8sResources, allResources)

	objects := getKubernetesObjects(index, []reporthandling.RuleMatchObjects{{
		APIGroups:   []string{"apps", "*"},
		APIVersions: []string{"v1", "*"},
		Resources:   []string{"deployments", "Deployment", "*"},
	}})

	require.Len(t, objects, 1)
	assert.Same(t, deployment, objects[0])
}

// When the match names a kind rather than the collected resource name, the
// fallback compares against the object's kind, which the index caches.
func TestGetKubernetesObjectsFallsBackToObjectKind(t *testing.T) {
	deployment := newTestWorkload("apps/v1", "Deployment", "d")
	statefulSet := newTestWorkload("apps/v1", "StatefulSet", "s")
	k8sResources := cautils.K8SResources{
		"apps/v1/workloads": {deployment.GetID(), statefulSet.GetID()},
	}
	allResources := map[string]workloadinterface.IMetadata{
		deployment.GetID():  deployment,
		statefulSet.GetID(): statefulSet,
	}
	index := newResourceGroupIndex(k8sResources, allResources)

	objects := getKubernetesObjects(index, []reporthandling.RuleMatchObjects{{
		APIGroups:   []string{"apps"},
		APIVersions: []string{"v1"},
		Resources:   []string{"statefulset"}, // case-insensitive, kind-based
	}})

	require.Len(t, objects, 1)
	assert.Same(t, statefulSet, objects[0])
}

// benchIndexFixture builds a scope-sized resource set: groups distinct GVRs,
// each holding perGroup objects, shaped like what a namespace batch carries.
func benchIndexFixture(groups, perGroup int) (cautils.K8SResources, map[string]workloadinterface.IMetadata) {
	k8sResources := make(cautils.K8SResources, groups)
	allResources := make(map[string]workloadinterface.IMetadata, groups*perGroup)

	kinds := []string{"Deployment", "Pod", "Service", "ConfigMap", "Role", "StatefulSet"}
	for g := 0; g < groups; g++ {
		kind := kinds[g%len(kinds)]
		apiVersion := fmt.Sprintf("group%d.example.com/v1", g)
		ids := make([]string, 0, perGroup)
		for i := 0; i < perGroup; i++ {
			workload := newTestWorkload(apiVersion, kind, fmt.Sprintf("obj-%d-%d", g, i))
			ids = append(ids, workload.GetID())
			allResources[workload.GetID()] = workload
		}
		k8sResources[fmt.Sprintf("%s/%ss", apiVersion, kind)] = ids
	}
	return k8sResources, allResources
}

func benchIndexMatch() []reporthandling.RuleMatchObjects {
	return []reporthandling.RuleMatchObjects{
		{
			APIGroups:   []string{"apps", "*"},
			APIVersions: []string{"v1", "*"},
			Resources:   []string{"Deployment", "StatefulSet", "DaemonSet"},
		},
		{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"Pod"},
		},
	}
}

func BenchmarkNewResourceGroupIndex(b *testing.B) {
	k8sResources, allResources := benchIndexFixture(80, 25)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = newResourceGroupIndex(k8sResources, allResources)
	}
}

// BenchmarkScopeRuleMatching is one scope's share of a scan: the index is built
// once, then every rule in the framework is matched against it.
func BenchmarkScopeRuleMatching(b *testing.B) {
	const rules = 250
	k8sResources, allResources := benchIndexFixture(80, 25)
	match := benchIndexMatch()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		index := newResourceGroupIndex(k8sResources, allResources)
		for r := 0; r < rules; r++ {
			_ = getKubernetesObjects(index, match)
		}
	}
}

// Once resources partition per namespace, most rules match nothing in most
// scopes. Those calls must not pay for an emitted buffer sized to the index.
func TestGetKubernetesObjectsAllocatesNothingWhenNothingMatches(t *testing.T) {
	k8sResources, allResources := benchIndexFixture(80, 25)
	index := newResourceGroupIndex(k8sResources, allResources)
	noMatch := []reporthandling.RuleMatchObjects{{
		APIGroups:   []string{"nonexistent.example.com"},
		APIVersions: []string{"v1"},
		Resources:   []string{"widgets"},
	}}
	require.Empty(t, getKubernetesObjects(index, noMatch))

	allocs := testing.AllocsPerRun(100, func() {
		_ = getKubernetesObjects(index, noMatch)
	})
	assert.Zero(t, allocs, "a rule matching nothing must not allocate")
}

// An index is read-only once built, so one can back concurrent matching. This
// is what would let control evaluation be parallelised (#2824).
func TestGetKubernetesObjectsConcurrentReads(t *testing.T) {
	k8sResources, allResources := benchIndexFixture(40, 10)
	index := newResourceGroupIndex(k8sResources, allResources)
	match := benchIndexMatch()

	want := len(getKubernetesObjects(index, match))
	require.NotZero(t, want, "fixture must match something")

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				assert.Len(t, getKubernetesObjects(index, match), want)
			}
		}()
	}
	wg.Wait()
}
