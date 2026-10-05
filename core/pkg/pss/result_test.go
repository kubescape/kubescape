package pss

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestAggregate_AllPassing(t *testing.T) {
	// A compliant pod with Restricted settings
	pod := unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      "secure-pod",
				"namespace": "secure-ns",
			},
			"spec": map[string]any{
				"securityContext": map[string]any{
					"runAsNonRoot": true,
					"seccompProfile": map[string]any{
						"type": "RuntimeDefault",
					},
				},
				"containers": []any{
					map[string]any{
						"name":  "c1",
						"image": "nginx",
						"securityContext": map[string]any{
							"allowPrivilegeEscalation": false,
							"capabilities": map[string]any{
								"drop": []any{"ALL"},
							},
						},
					},
				},
			},
		},
	}

	res := Aggregate("secure-ns", []unstructured.Unstructured{pod}, Restricted)
	assert.Equal(t, "secure-ns", res.Namespace)
	assert.Equal(t, Restricted, res.TargetLevel)
	assert.Equal(t, 1, res.TotalWorkloads)
	assert.Equal(t, 1, res.PassingWorkloads)
	assert.Equal(t, 0, res.FailingWorkloads)
	assert.Equal(t, 0, res.UnevaluatedWorkloads)
	assert.Equal(t, Restricted, res.CurrentEffectiveLevel)
	assert.False(t, res.HasFailures())
	assert.Len(t, res.PassingResults(), 1)
	assert.Empty(t, res.FailingResults())
}

func TestAggregate_FailingWorkload(t *testing.T) {
	// A pod running as privileged
	privilegedPod := unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      "priv-pod",
				"namespace": "mixed-ns",
			},
			"spec": map[string]any{
				"containers": []any{
					map[string]any{
						"name":  "c1",
						"image": "nginx",
						"securityContext": map[string]any{
							"privileged": true,
						},
					},
				},
			},
		},
	}

	res := Aggregate("mixed-ns", []unstructured.Unstructured{privilegedPod}, Restricted)
	assert.Equal(t, 1, res.TotalWorkloads)
	assert.Equal(t, 0, res.PassingWorkloads)
	assert.Equal(t, 1, res.FailingWorkloads)
	assert.Equal(t, Privileged, res.CurrentEffectiveLevel)
	assert.True(t, res.HasFailures())
	require.Len(t, res.FailingResults(), 1)
	assert.Equal(t, "priv-pod", res.FailingResults()[0].Name)
	assert.NotEmpty(t, res.FailingResults()[0].Violations)
}

func TestAggregate_UnevaluatedObject(t *testing.T) {
	// An object where PodSpec extraction fails (e.g. malformed spec)
	badObj := unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      "malformed-pod",
				"namespace": "test",
			},
			"spec": "not-a-map",
		},
	}

	res := Aggregate("test", []unstructured.Unstructured{badObj}, Baseline)
	assert.Equal(t, 1, res.TotalWorkloads)
	assert.Equal(t, 1, res.UnevaluatedWorkloads)
	assert.Len(t, res.DecodeWarnings, 1)
}
