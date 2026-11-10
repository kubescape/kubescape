package resourcehandler

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

var podGVR = schema.GroupVersionResource{Version: "v1", Resource: "pods"}

func testPod(name string, labels map[string]any, owners ...any) *unstructured.Unstructured {
	metadata := map[string]any{"name": name, "namespace": "default"}
	if labels != nil {
		metadata["labels"] = labels
	}
	if len(owners) > 0 {
		metadata["ownerReferences"] = owners
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   metadata,
		"spec": map[string]any{"containers": []any{map[string]any{
			"name":            "app",
			"image":           "nginx",
			"securityContext": map[string]any{"privileged": true},
		}}},
	}}
}

func ownerRef(apiVersion, kind, name string, controller bool) map[string]any {
	return map[string]any{"apiVersion": apiVersion, "kind": kind, "name": name, "uid": name + "-uid", "controller": controller}
}

func podWithEmptyOwners() *unstructured.Unstructured {
	pod := testPod("empty-owners", hashLabel)
	pod.Object["metadata"].(map[string]any)["ownerReferences"] = []any{}
	return pod
}

var hashLabel = map[string]any{"pod-template-hash": "5d8f7c9b6"}

// ownerlessPodCases pins which pods are left to their owner and which are
// scanned on their own. pod-template-hash is only a label: anyone can set it,
// and it outlives the ReplicaSet when that is deleted with --cascade=orphan,
// so it says nothing about whether the pod still has an owner.
var ownerlessPodCases = []struct {
	name    string
	pod     *unstructured.Unstructured
	skipped bool
}{
	{"ownerless pod", testPod("plain", nil), false},
	{"ownerless pod with pod-template-hash", testPod("hashed", hashLabel), false},
	// Named the way a ReplicaSet names its pods, which also makes
	// workloadinterface.GetOwnerReferences synthesize a ReplicaSet owner.
	{"orphaned pod that kept its pod-template-hash", testPod("web-5d8f7c9b6-x7k2p", map[string]any{"app": "web", "pod-template-hash": "5d8f7c9b6"}), false},
	{"pod with an empty ownerReferences list", podWithEmptyOwners(), false},
	{"ownerless pod with empty pod-template-hash", testPod("empty-hash", map[string]any{"pod-template-hash": ""}), false},
	{"pod owned by a ReplicaSet", testPod("web-5d8f7c9b6-abcde", hashLabel, ownerRef("apps/v1", "ReplicaSet", "web-5d8f7c9b6", true)), true},
	{"pod owned by a ReplicaSet without the hash label", testPod("rs-owned-nohash", nil, ownerRef("apps/v1", "ReplicaSet", "web", true)), true},
	{"pod owned by a Job", testPod("job-owned", nil, ownerRef("batch/v1", "Job", "migrate", true)), true},
	{"pod with several owners led by its ReplicaSet", testPod("multi-owner", hashLabel, ownerRef("apps/v1", "ReplicaSet", "web", true), ownerRef("v1", "ConfigMap", "cfg", false)), true},
	{"static pod owned by its Node", testPod("static", hashLabel, ownerRef("v1", "Node", "node-1", true)), false},
	{"pod owned by a custom resource", testPod("crd-owned", hashLabel, ownerRef("argoproj.io/v1alpha1", "Rollout", "web", true)), false},
}

func TestWorkloadHasParent_OwnerlessPods(t *testing.T) {
	for _, tc := range ownerlessPodCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.skipped, workloadHasParent(tc.pod.Object))
		})
	}
}

// TestPullSingleResource_OwnerlessPods covers the path both the streaming and
// the non-streaming collectors list through.
func TestPullSingleResource_OwnerlessPods(t *testing.T) {
	objects := make([]runtime.Object, 0, len(ownerlessPodCases))
	want := []string{}
	for _, tc := range ownerlessPodCases {
		objects = append(objects, tc.pod.DeepCopy())
		if !tc.skipped {
			want = append(want, tc.pod.GetName())
		}
	}
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{podGVR: "PodList"}, objects...)
	handler := &K8sResourceHandler{k8s: &k8sinterface.KubernetesApi{DynamicClient: client}}

	result, failures := handler.pullSingleResource(context.Background(), &podGVR, "", "", &EmptySelector{}, nil)
	require.Empty(t, failures)

	got := []string{}
	for _, obj := range result {
		got = append(got, obj.GetName())
	}
	assert.ElementsMatch(t, want, got)
}

func TestFindScanObjectResource_OwnerlessPods(t *testing.T) {
	for _, tc := range ownerlessPodCases {
		t.Run(tc.name, func(t *testing.T) {
			client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{podGVR: "PodList"}, tc.pod.DeepCopy())
			handler := &K8sResourceHandler{k8s: &k8sinterface.KubernetesApi{DynamicClient: client}}
			resolver, failures := newDiscoveryResourceResolver(nil)
			require.Empty(t, failures)

			workload, err := handler.findScanObjectResource(context.Background(), scanObject("v1", "Pod", "default", tc.pod.GetName()), &EmptySelector{}, resolver)
			if tc.skipped {
				assert.ErrorIs(t, err, ErrResourceHasParent)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.pod.GetName(), workload.GetName())
		})
	}
}
