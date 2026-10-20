package mcpserver

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestPredictPSSComplianceKeepsAdmissionChangedPod(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "equivalent child", true: "privileged child"}[changed], func(t *testing.T) {
			deploy := loadYAMLFixture(t, "testdata/pss/compliant-deployment.yaml")
			deploy.SetUID("deployment-id")
			rs := deploy.DeepCopy()
			rs.SetKind("ReplicaSet")
			rs.SetName("app-rs")
			rs.SetUID("replicaset-id")
			controller := true
			rs.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: deploy.GetName(), UID: deploy.GetUID(), Controller: &controller}})
			spec, found, err := unstructured.NestedMap(rs.Object, "spec", "template", "spec")
			require.NoError(t, err)
			require.True(t, found)
			pod := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "app-pod", "namespace": "test-pss"}, "spec": spec}}
			pod.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.GetName(), UID: rs.GetUID(), Controller: &controller}})
			if changed {
				containers, _, _ := unstructured.NestedSlice(pod.Object, "spec", "containers")
				containers[0].(map[string]any)["securityContext"].(map[string]any)["privileged"] = true
				require.NoError(t, unstructured.SetNestedSlice(pod.Object, containers, "spec", "containers"))
			}
			server := newPSSPredictorTestServer(t, deploy, rs, pod)
			result := registeredToolResult(t, dispatchRegisteredTool(t, server, "predict_pss_compliance", map[string]any{"namespace": "test-pss", "level": "Baseline"}))
			require.False(t, result.IsError)
			parsed := parsePSSResult(t, result)
			summary := getSummary(t, parsed)
			if changed {
				require.Equal(t, float64(2), summary["total_workloads"])
				require.Equal(t, float64(1), summary["failing"])
				failing := parsed["failing_workloads"].([]any)
				require.Len(t, failing, 1)
				require.Equal(t, "app-pod", failing[0].(map[string]any)["name"])
			} else {
				require.Equal(t, float64(1), summary["total_workloads"])
				require.Equal(t, float64(0), summary["failing"])
			}
		})
	}
}
