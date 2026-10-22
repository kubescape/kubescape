package pss

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

func TestOwnerNamespaceDoesNotDropUnrelatedChild(t *testing.T) {
	parent := makeWorkloadWithUID("Deployment", "app", "prod", "")
	child := makeWorkloadWithUID("Pod", "child", "staging", "", metav1.OwnerReference{
		APIVersion: "apps/v1", Kind: "Deployment", Name: "app", Controller: boolPtr(true),
	})
	kept := DeduplicateWorkloads([]unstructured.Unstructured{parent, child})
	require.Len(t, kept, 2, "a parent in another namespace cannot represent this Pod")
}

func namespaceOwnerWorkload(kind, name, namespace, uid string, unsafe bool) unstructured.Unstructured {
	spec := map[string]any{
		"containers": []any{map[string]any{
			"name": "app", "image": "fixture:1",
			"securityContext": map[string]any{"privileged": unsafe},
		}},
	}
	version := "apps/v1"
	objectSpec := map[string]any{"template": map[string]any{"spec": spec}}
	switch kind {
	case "Pod":
		version = "v1"
		objectSpec = spec
	case "Job":
		version = "batch/v1"
	case "CronJob":
		version = "batch/v1"
		objectSpec = map[string]any{"jobTemplate": map[string]any{"spec": objectSpec}}
	}
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": version,
		"kind":       kind,
		"metadata": map[string]any{
			"namespace": namespace, "name": name, "uid": uid,
		},
		"spec": objectSpec,
	}}
}

func namespaceOwnerReference(parent unstructured.Unstructured) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion: parent.GetAPIVersion(),
		Kind:       parent.GetKind(),
		Name:       parent.GetName(),
		UID:        parent.GetUID(),
		Controller: boolPtr(true),
	}
}

func namespaceOwnerKeys(items []unstructured.Unstructured) []string {
	keys := make([]string, 0, len(items))
	for _, item := range items {
		keys = append(keys, item.GetNamespace()+"/"+item.GetKind()+"/"+item.GetName())
	}
	slices.Sort(keys)
	return keys
}

func TestOwnerNamespaceSameNameParentsAreOrderIndependent(t *testing.T) {
	for _, kind := range []string{"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet", "Job", "CronJob"} {
		t.Run(kind, func(t *testing.T) {
			prod := namespaceOwnerWorkload(kind, "app", "prod", "", true)
			staging := namespaceOwnerWorkload(kind, "app", "staging", "", true)
			child := namespaceOwnerWorkload("Pod", "child", "prod", "", true)
			child.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(prod)})
			orders := [][]unstructured.Unstructured{
				{prod, staging, child},
				{staging, prod, child},
				{child, staging, prod},
				{child, prod, staging},
				{prod, child, staging},
				{staging, child, prod},
			}
			for _, order := range orders {
				kept := DeduplicateWorkloads(order)
				require.Equal(t, namespaceOwnerKeys([]unstructured.Unstructured{prod, staging}), namespaceOwnerKeys(kept))
				result := Aggregate("", kept, Baseline)
				require.Equal(t, 2, result.TotalWorkloads)
				require.Equal(t, 2, result.FailingWorkloads)
			}
		})
	}
}

func TestOwnerNamespaceRejectsCrossNamespaceUID(t *testing.T) {
	for _, kind := range []string{"Deployment", "ReplicaSet", "Job", "CronJob"} {
		t.Run(kind, func(t *testing.T) {
			parent := namespaceOwnerWorkload(kind, "app", "prod", "parent-uid", true)
			child := namespaceOwnerWorkload("Pod", "child", "staging", "child-uid", true)
			child.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(parent)})
			for _, order := range [][]unstructured.Unstructured{{parent, child}, {child, parent}} {
				kept := DeduplicateWorkloads(order)
				require.Len(t, kept, 2)
				require.Equal(t, 2, Aggregate("", kept, Baseline).FailingWorkloads)
			}
		})
	}
}

func TestOwnerNamespaceMissingLocalParentDoesNotUseForeignOne(t *testing.T) {
	for _, childNS := range []string{"prod", "staging", "", "default"} {
		t.Run(childNS, func(t *testing.T) {
			parent := namespaceOwnerWorkload("Deployment", "app", "foreign", "", true)
			child := namespaceOwnerWorkload("Pod", "child", childNS, "", true)
			child.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(parent)})
			kept := DeduplicateWorkloads([]unstructured.Unstructured{parent, child})
			require.Len(t, kept, 2)
			require.Contains(t, namespaceOwnerKeys(kept), childNS+"/Pod/child")
		})
	}
}

func TestOwnerNamespaceDoesNotAssumeDefaultForLocalFiles(t *testing.T) {
	for _, pair := range [][2]string{{"", "default"}, {"default", ""}} {
		parent := namespaceOwnerWorkload("Deployment", "app", pair[0], "", false)
		child := namespaceOwnerWorkload("Pod", "child", pair[1], "", false)
		child.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(parent)})
		require.Len(t, DeduplicateWorkloads([]unstructured.Unstructured{parent, child}), 2)
	}
	// Two objects with the same omitted namespace can still be related.
	parent := namespaceOwnerWorkload("Deployment", "app", "", "", false)
	child := namespaceOwnerWorkload("Pod", "child", "", "", false)
	child.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(parent)})
	require.Equal(t, []string{"/Deployment/app"}, namespaceOwnerKeys(DeduplicateWorkloads([]unstructured.Unstructured{parent, child})))
}

func TestOwnerNamespaceUIDFallbackStillRequiresMatchingUID(t *testing.T) {
	for _, parentUID := range []string{"", "matching", "different"} {
		t.Run(parentUID, func(t *testing.T) {
			parent := namespaceOwnerWorkload("Deployment", "app", "prod", parentUID, false)
			foreign := namespaceOwnerWorkload("Deployment", "app", "foreign", "matching", false)
			child := namespaceOwnerWorkload("Pod", "child", "prod", "", false)
			ref := namespaceOwnerReference(parent)
			ref.UID = types.UID("matching")
			child.SetOwnerReferences([]metav1.OwnerReference{ref})
			kept := DeduplicateWorkloads([]unstructured.Unstructured{foreign, parent, child})
			want := 2
			if parentUID == "different" {
				want = 3
			}
			require.Len(t, kept, want)
		})
	}
}

func TestOwnerNamespaceEachHopStaysWithinNamespace(t *testing.T) {
	parent := namespaceOwnerWorkload("Deployment", "app", "prod", "", true)
	rs := namespaceOwnerWorkload("ReplicaSet", "revision", "staging", "", true)
	pod := namespaceOwnerWorkload("Pod", "child", "staging", "", true)
	rs.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(parent)})
	pod.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(rs)})
	kept := DeduplicateWorkloads([]unstructured.Unstructured{parent, rs, pod})
	require.Equal(t, []string{"prod/Deployment/app", "staging/ReplicaSet/revision"}, namespaceOwnerKeys(kept))
	require.Equal(t, 2, Aggregate("", kept, Baseline).FailingWorkloads)
}

func TestOwnerNamespaceParallelControllerChains(t *testing.T) {
	var input []unstructured.Unstructured
	var want []string
	for _, ns := range []string{"prod", "staging", "dev"} {
		dep := namespaceOwnerWorkload("Deployment", "app", ns, "", false)
		rs := namespaceOwnerWorkload("ReplicaSet", "revision", ns, "", false)
		pod := namespaceOwnerWorkload("Pod", "child", ns, "", false)
		rs.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(dep)})
		pod.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(rs)})
		input = append(input, pod, dep, rs)
		want = append(want, ns+"/Deployment/app")
	}
	slices.Sort(want)
	for i := 0; i < len(input); i++ {
		rotated := append(slices.Clone(input[i:]), input[:i]...)
		require.Equal(t, want, namespaceOwnerKeys(DeduplicateWorkloads(rotated)))
	}
}

func TestOwnerNamespaceRetainsDifferentChildViolations(t *testing.T) {
	parent := namespaceOwnerWorkload("Deployment", "app", "prod", "", false)
	foreign := namespaceOwnerWorkload("Deployment", "app", "foreign", "", true)
	child := namespaceOwnerWorkload("Pod", "child", "prod", "", true)
	child.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(parent)})
	for _, order := range [][]unstructured.Unstructured{{parent, foreign, child}, {foreign, parent, child}} {
		kept := DeduplicateWorkloads(order)
		require.Len(t, kept, 3, "equivalence must be checked against the actual local parent")
		result := Aggregate("", kept, Baseline)
		require.Equal(t, 1, result.PassingWorkloads)
		require.Equal(t, 2, result.FailingWorkloads)
	}
}

func TestOwnerNamespacePublicParserAndAggregation(t *testing.T) {
	parent := namespaceOwnerWorkload("Deployment", "app", "prod", "", true)
	child := namespaceOwnerWorkload("Pod", "child", "staging", "", true)
	child.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(parent)})
	path := filepath.Join(t.TempDir(), "workloads.json")
	data, err := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "List", "items": []any{parent.Object, child.Object}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	items, err := ParseLocalWorkloads([]string{path})
	require.NoError(t, err)
	result := Aggregate("", DeduplicateWorkloads(items), Baseline)
	require.Equal(t, 2, result.TotalWorkloads)
	require.Equal(t, 2, result.FailingWorkloads)
	require.Equal(t, 0, result.UnevaluatedWorkloads)
	require.False(t, result.CurrentEffectiveLevel == Restricted)
	require.Len(t, result.ToMap()["failing_workloads"], 2)
}

func TestOwnerNamespaceDeduplicationDoesNotMutateInput(t *testing.T) {
	parent := namespaceOwnerWorkload("Deployment", "app", "prod", "parent", false)
	child := namespaceOwnerWorkload("Pod", "child", "prod", "child", false)
	child.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(parent)})
	input := []unstructured.Unstructured{parent, child}
	before, err := json.Marshal(input)
	require.NoError(t, err)
	for i := 0; i < 5; i++ {
		require.Len(t, DeduplicateWorkloads(input), 1)
	}
	after, err := json.Marshal(input)
	require.NoError(t, err)
	require.JSONEq(t, string(before), string(after))
}

func TestOwnerNamespaceNonControllerReferenceDoesNotDeduplicate(t *testing.T) {
	for _, controller := range []*bool{nil, boolPtr(false)} {
		parent := namespaceOwnerWorkload("Deployment", "app", "prod", "", false)
		child := namespaceOwnerWorkload("Pod", "child", "prod", "", false)
		ref := namespaceOwnerReference(parent)
		ref.Controller = controller
		child.SetOwnerReferences([]metav1.OwnerReference{ref})
		require.Len(t, DeduplicateWorkloads([]unstructured.Unstructured{parent, child}), 2)
	}
}

func TestOwnerNamespaceNoCrossNamespaceCycle(t *testing.T) {
	a := namespaceOwnerWorkload("Deployment", "app", "prod", "", false)
	b := namespaceOwnerWorkload("Deployment", "app", "staging", "", false)
	a.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(b)})
	b.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(a)})
	for _, order := range [][]unstructured.Unstructured{{a, b}, {b, a}} {
		require.Len(t, DeduplicateWorkloads(order), 2, "unqualified names must not fabricate a cross-namespace cycle")
	}
}

func TestOwnerNamespaceDirectoryPipelineRetainsEveryNamespace(t *testing.T) {
	dir := t.TempDir()
	var expected []string
	for _, ns := range []string{"prod", "staging", "dev"} {
		parent := namespaceOwnerWorkload("Deployment", "app", ns, "", true)
		child := namespaceOwnerWorkload("Pod", "child", ns, "", true)
		child.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(parent)})
		for _, item := range []unstructured.Unstructured{parent, child} {
			data, err := json.Marshal(item.Object)
			require.NoError(t, err)
			path := filepath.Join(dir, ns+"-"+item.GetKind()+".json")
			require.NoError(t, os.WriteFile(path, data, 0o600))
		}
		expected = append(expected, ns+"/Deployment/app")
	}
	parsed, err := ParseLocalWorkloads([]string{dir})
	require.NoError(t, err)
	require.Len(t, parsed, 6)
	kept := DeduplicateWorkloads(parsed)
	slices.Sort(expected)
	require.Equal(t, expected, namespaceOwnerKeys(kept))
	result := Aggregate("", kept, Baseline)
	require.Equal(t, 3, result.TotalWorkloads)
	require.Equal(t, 3, result.FailingWorkloads)
	require.Equal(t, 0, result.PassingWorkloads)
}

func TestOwnerNamespaceRealUIDsKeepLocalHierarchy(t *testing.T) {
	var items []unstructured.Unstructured
	for _, ns := range []string{"prod", "staging"} {
		dep := namespaceOwnerWorkload("Deployment", "app", ns, ns+"-dep", false)
		rs := namespaceOwnerWorkload("ReplicaSet", "revision", ns, ns+"-rs", false)
		pod := namespaceOwnerWorkload("Pod", "child", ns, ns+"-pod", false)
		rs.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(dep)})
		pod.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(rs)})
		items = append(items, dep, rs, pod)
	}
	for i := range items {
		order := append(slices.Clone(items[i:]), items[:i]...)
		kept := DeduplicateWorkloads(order)
		require.Equal(t, []string{"prod/Deployment/app", "staging/Deployment/app"}, namespaceOwnerKeys(kept))
	}
}

func TestOwnerNamespaceRestrictedOnlyDifferenceUsesLocalParent(t *testing.T) {
	prod := namespaceOwnerWorkload("Deployment", "app", "prod", "", false)
	staging := namespaceOwnerWorkload("Deployment", "app", "staging", "", false)
	child := namespaceOwnerWorkload("Pod", "child", "prod", "", false)
	child.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(prod)})
	// Baseline permits runAsUser=0. Deduplication must still retain a child
	// whose Restricted findings differ from its own parent's template.
	require.NoError(t, unstructured.SetNestedField(child.Object, int64(0), "spec", "securityContext", "runAsUser"))
	require.NoError(t, unstructured.SetNestedField(staging.Object, int64(0), "spec", "template", "spec", "securityContext", "runAsUser"))
	for _, order := range [][]unstructured.Unstructured{{prod, staging, child}, {staging, prod, child}} {
		kept := DeduplicateWorkloads(order)
		require.Len(t, kept, 3)
		baseline := Aggregate("", kept, Baseline)
		require.Equal(t, 3, baseline.PassingWorkloads)
		require.Equal(t, 0, baseline.FailingWorkloads)
	}
}

func TestOwnerNamespaceMalformedLocalParentCannotBorrowForeignTemplate(t *testing.T) {
	parent := namespaceOwnerWorkload("Deployment", "app", "prod", "", false)
	parent.Object["spec"] = "not-a-spec"
	foreign := namespaceOwnerWorkload("Deployment", "app", "staging", "", false)
	child := namespaceOwnerWorkload("Pod", "child", "prod", "", false)
	child.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(parent)})
	for _, order := range [][]unstructured.Unstructured{{parent, foreign, child}, {foreign, parent, child}} {
		kept := DeduplicateWorkloads(order)
		require.Len(t, kept, 3)
		result := Aggregate("", kept, Baseline)
		require.Equal(t, 1, result.UnevaluatedWorkloads)
		require.Equal(t, 2, result.PassingWorkloads)
		require.Len(t, result.DecodeWarnings, 1)
	}
}

func TestOwnerNamespaceRemovalPreservesInputOrder(t *testing.T) {
	parent := namespaceOwnerWorkload("Deployment", "app", "prod", "", false)
	foreign := namespaceOwnerWorkload("Deployment", "app", "staging", "", false)
	child := namespaceOwnerWorkload("Pod", "child", "prod", "", false)
	standalone := namespaceOwnerWorkload("Pod", "standalone", "prod", "", false)
	child.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(parent)})
	orders := [][]unstructured.Unstructured{
		{standalone, child, foreign, parent},
		{foreign, child, parent, standalone},
		{child, standalone, parent, foreign},
	}
	for _, order := range orders {
		var want []string
		for _, item := range order {
			if item.GetName() != "child" {
				want = append(want, item.GetNamespace()+"/"+item.GetName())
			}
		}
		var got []string
		for _, item := range DeduplicateWorkloads(order) {
			got = append(got, item.GetNamespace()+"/"+item.GetName())
		}
		require.Equal(t, want, got)
	}
}

func TestOwnerNamespaceChildWithNoOwnerIsAlwaysRetained(t *testing.T) {
	for _, ns := range []string{"prod", "staging", ""} {
		parent := namespaceOwnerWorkload("Deployment", "app", "prod", "shared", true)
		child := namespaceOwnerWorkload("Pod", "app", ns, "", true)
		kept := DeduplicateWorkloads([]unstructured.Unstructured{parent, child})
		require.Len(t, kept, 2)
		require.Equal(t, 2, Aggregate("", kept, Baseline).FailingWorkloads)
	}
}

func TestOwnerNamespaceJobCronJobChain(t *testing.T) {
	cron := namespaceOwnerWorkload("CronJob", "schedule", "prod", "", false)
	foreign := namespaceOwnerWorkload("CronJob", "schedule", "staging", "", false)
	job := namespaceOwnerWorkload("Job", "run", "prod", "", false)
	pod := namespaceOwnerWorkload("Pod", "worker", "prod", "", false)
	job.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(cron)})
	pod.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(job)})
	kept := DeduplicateWorkloads([]unstructured.Unstructured{cron, job, foreign, pod})
	require.Equal(t, []string{"prod/CronJob/schedule", "staging/CronJob/schedule"}, namespaceOwnerKeys(kept))
}

func TestOwnerNamespaceMalformedChildRemainsUnevaluated(t *testing.T) {
	parent := namespaceOwnerWorkload("Deployment", "app", "prod", "parent", false)
	child := namespaceOwnerWorkload("Pod", "child", "staging", "child", false)
	child.SetOwnerReferences([]metav1.OwnerReference{namespaceOwnerReference(parent)})
	child.Object["spec"] = "not-a-pod-spec"
	kept := DeduplicateWorkloads([]unstructured.Unstructured{parent, child})
	require.Len(t, kept, 2)
	result := Aggregate("", kept, Baseline)
	require.Equal(t, 2, result.TotalWorkloads)
	require.Equal(t, 1, result.PassingWorkloads)
	require.Equal(t, 1, result.UnevaluatedWorkloads)
	require.Len(t, result.DecodeWarnings, 1)
}
