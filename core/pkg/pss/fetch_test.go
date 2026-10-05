package pss

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestSupportedKinds(t *testing.T) {
	kinds := SupportedKinds()
	expected := []string{"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"}
	for _, k := range expected {
		assert.True(t, kinds[k], "expected kind %s to be supported", k)
	}
	assert.False(t, kinds["ConfigMap"], "ConfigMap should not be supported")
	assert.False(t, kinds["Service"], "Service should not be supported")
}

func TestFilterTargetsByKind(t *testing.T) {
	targets := DefaultWorkloadTargets

	filtered := FilterTargetsByKind(targets, "deployment")
	require.Len(t, filtered, 1)
	assert.Equal(t, "Deployment", filtered[0].Kind)

	filtered = FilterTargetsByKind(targets, "POD")
	require.Len(t, filtered, 1)
	assert.Equal(t, "Pod", filtered[0].Kind)

	filtered = FilterTargetsByKind(targets, "NonExistent")
	assert.Nil(t, filtered)
}

func boolPtr(b bool) *bool {
	return &b
}

func makeWorkloadWithUID(kind, name, namespace string, uid types.UID, ownerRefs ...metav1.OwnerReference) unstructured.Unstructured {
	u := unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       kind,
			"metadata": map[string]any{
				"name":      name,
				"namespace": namespace,
				"uid":       string(uid),
			},
			"spec": map[string]any{
				"template": map[string]any{
					"spec": map[string]any{
						"containers": []any{
							map[string]any{"name": "c1", "image": "nginx"},
						},
					},
				},
			},
		},
	}
	if len(ownerRefs) > 0 {
		u.SetOwnerReferences(ownerRefs)
	}
	return u
}

func TestDeduplicateWorkloads(t *testing.T) {
	depUID := types.UID("uid-dep-1")
	rsUID := types.UID("uid-rs-1")
	podUID := types.UID("uid-pod-1")
	standaloneUID := types.UID("uid-standalone-1")

	dep := makeWorkloadWithUID("Deployment", "app-dep", "default", depUID)

	rs := makeWorkloadWithUID("ReplicaSet", "app-rs", "default", rsUID, metav1.OwnerReference{
		APIVersion: "apps/v1",
		Kind:       "Deployment",
		Name:       "app-dep",
		UID:        depUID,
		Controller: boolPtr(true),
	})

	pod := makeWorkloadWithUID("Pod", "app-pod", "default", podUID, metav1.OwnerReference{
		APIVersion: "apps/v1",
		Kind:       "ReplicaSet",
		Name:       "app-rs",
		UID:        rsUID,
		Controller: boolPtr(true),
	})

	standalonePod := makeWorkloadWithUID("Pod", "standalone-pod", "default", standaloneUID)

	// Custom controller owner not in scan
	crdOwnedPod := makeWorkloadWithUID("Pod", "crd-pod", "default", "uid-crd-pod", metav1.OwnerReference{
		APIVersion: "custom.io/v1",
		Kind:       "CustomResource",
		Name:       "my-custom",
		UID:        "uid-custom",
		Controller: boolPtr(true),
	})

	workloads := []unstructured.Unstructured{dep, rs, pod, standalonePod, crdOwnedPod}
	deduped := DeduplicateWorkloads(workloads)

	assert.Len(t, deduped, 3, "should keep Deployment, standalone Pod, and CRD-owned Pod")
	names := make([]string, len(deduped))
	for i, w := range deduped {
		names[i] = w.GetName()
	}
	assert.Contains(t, names, "app-dep")
	assert.Contains(t, names, "standalone-pod")
	assert.Contains(t, names, "crd-pod")
	assert.NotContains(t, names, "app-rs")
	assert.NotContains(t, names, "app-pod")
}

func TestDeduplicateWorkloads_CycleDetection(t *testing.T) {
	// A points to B as controller, B points to A as controller (synthetic cycle)
	wA := makeWorkloadWithUID("Deployment", "workload-a", "default", "uid-a", metav1.OwnerReference{
		APIVersion: "apps/v1",
		Kind:       "Deployment",
		Name:       "workload-b",
		UID:        "uid-b",
		Controller: boolPtr(true),
	})
	wB := makeWorkloadWithUID("Deployment", "workload-b", "default", "uid-b", metav1.OwnerReference{
		APIVersion: "apps/v1",
		Kind:       "Deployment",
		Name:       "workload-a",
		UID:        "uid-a",
		Controller: boolPtr(true),
	})

	workloads := []unstructured.Unstructured{wA, wB}
	deduped := DeduplicateWorkloads(workloads)

	// Ensure cycle doesn't hang or drop both
	assert.Len(t, deduped, 1, "exactly one element in cyclic chain should be kept")
}

func TestFetchNamespaceWorkloads(t *testing.T) {
	depGVR := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

	dep := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]any{
				"name":      "my-deploy",
				"namespace": "test-ns",
			},
		},
	}
	pod := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      "my-pod",
				"namespace": "test-ns",
			},
		},
	}

	scheme := runtime.NewScheme()
	listKinds := map[schema.GroupVersionResource]string{
		depGVR: "DeploymentList",
		podGVR: "PodList",
	}

	dynClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds, dep, pod)

	targets := []WorkloadTarget{
		{GVR: depGVR, Kind: "Deployment"},
		{GVR: podGVR, Kind: "Pod"},
	}

	res, err := FetchNamespaceWorkloads(context.Background(), dynClient, "test-ns", targets)
	require.NoError(t, err)
	require.Len(t, res, 2)

	assert.Equal(t, "Deployment", res[0].GetKind())
	assert.Equal(t, "my-deploy", res[0].GetName())
	assert.Equal(t, "Pod", res[1].GetKind())
	assert.Equal(t, "my-pod", res[1].GetName())
}
