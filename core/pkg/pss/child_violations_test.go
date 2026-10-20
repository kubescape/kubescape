package pss

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

func pssOwnedFixture(kind, name, ownerKind, ownerName, ownerUID string) unstructured.Unstructured {
	w := makeWorkloadWithUID(kind, name, "prod", types.UID("uid-"+name))
	if ownerName != "" {
		w.SetOwnerReferences([]metav1.OwnerReference{{Kind: ownerKind, Name: ownerName, UID: types.UID(ownerUID), Controller: boolPtr(true)}})
	}
	return w
}

func TestDeduplicationPreservesChildSecurityChanges(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*unstructured.Unstructured)
		want    int
		failing int
	}{
		{name: "identical pod", want: 1},
		{name: "different image only", mutate: func(w *unstructured.Unstructured) {
			containers, _, _ := unstructured.NestedSlice(w.Object, "spec", "containers")
			containers[0].(map[string]any)["image"] = "nginx:new"
			require.NoError(t, unstructured.SetNestedSlice(w.Object, containers, "spec", "containers"))
		}, want: 1},
		{name: "injected privileged container", mutate: func(w *unstructured.Unstructured) {
			containers, _, _ := unstructured.NestedSlice(w.Object, "spec", "containers")
			containers = append(containers, map[string]any{"name": "injected", "image": "sidecar", "securityContext": map[string]any{"privileged": true}})
			require.NoError(t, unstructured.SetNestedSlice(w.Object, containers, "spec", "containers"))
		}, want: 2, failing: 1},
		{name: "host network changed", mutate: func(w *unstructured.Unstructured) {
			require.NoError(t, unstructured.SetNestedField(w.Object, true, "spec", "hostNetwork"))
		}, want: 2, failing: 1},
		{name: "annotation changed", mutate: func(w *unstructured.Unstructured) {
			w.SetAnnotations(map[string]string{"container.apparmor.security.beta.kubernetes.io/c1": "unconfined"})
		}, want: 2, failing: 1},
		{name: "restricted-only change", mutate: func(w *unstructured.Unstructured) {
			require.NoError(t, unstructured.SetNestedField(w.Object, int64(0), "spec", "securityContext", "runAsUser"))
		}, want: 2},
		{name: "undecodable child", mutate: func(w *unstructured.Unstructured) { w.Object["spec"] = "invalid" }, want: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := pssOwnedFixture("Deployment", "app", "", "", "")
			pod := pssOwnedFixture("Pod", "child", "Deployment", "app", "uid-app")
			if tc.mutate != nil {
				tc.mutate(&pod)
			}
			kept := DeduplicateWorkloads([]unstructured.Unstructured{parent, pod})
			require.Len(t, kept, tc.want)
			summary := Aggregate("prod", kept, Baseline)
			require.Equal(t, tc.failing, summary.FailingWorkloads)
			if tc.name == "undecodable child" {
				require.Equal(t, 1, summary.UnevaluatedWorkloads)
			}
		})
	}
}

func TestDeduplicationRetainsOlderReplicaSetViolations(t *testing.T) {
	parent := pssOwnedFixture("Deployment", "app", "", "", "")
	rs := pssOwnedFixture("ReplicaSet", "old-revision", "Deployment", "app", "uid-app")
	require.NoError(t, unstructured.SetNestedField(rs.Object, true, "spec", "template", "spec", "hostNetwork"))
	pod := pssOwnedFixture("Pod", "old-pod", "ReplicaSet", "old-revision", "uid-old-revision")
	require.NoError(t, unstructured.SetNestedField(pod.Object, true, "spec", "hostNetwork"))
	kept := DeduplicateWorkloads([]unstructured.Unstructured{parent, rs, pod})
	require.Len(t, kept, 2, "retain the old revision, while still deduplicating its equivalent pod")
	summary := Aggregate("prod", kept, Baseline)
	require.Equal(t, 1, summary.FailingWorkloads)
}

func TestDeduplicationRetainsDistinctResultsInOwnerCycle(t *testing.T) {
	a := pssOwnedFixture("Deployment", "a", "Deployment", "b", "uid-b")
	b := pssOwnedFixture("Deployment", "b", "Deployment", "a", "uid-a")
	require.NoError(t, unstructured.SetNestedField(b.Object, true, "spec", "template", "spec", "hostNetwork"))
	require.Len(t, DeduplicateWorkloads([]unstructured.Unstructured{a, b}), 2)
}
