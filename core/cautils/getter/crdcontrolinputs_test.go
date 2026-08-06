package getter

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
)

func TestGetControlsInputs_WithControls(t *testing.T) {
	scheme := runtime.NewScheme()
	client := fake.NewSimpleDynamicClient(scheme,
		&unstructured.Unstructured{
			Object: map[string]any{
				"apiVersion": "kubescape.io/v1",
				"kind":       "ControlInput",
				"metadata": map[string]any{
					"name": "default",
				},
				"spec": map[string]any{
					"controls": map[string]any{
						"untrustedRegistries":  []any{"docker.io", "quay.io"},
						"insecureCapabilities": []any{"NET_RAW", "SYS_ADMIN"},
					},
				},
			},
		},
	)

	getter := &CRDControlInputs{client: client}
	inputs, err := getter.GetControlsInputs(context.TODO(), "")
	require.NoError(t, err)
	assert.Len(t, inputs, 2)
	assert.Equal(t, []string{"docker.io", "quay.io"}, inputs["untrustedRegistries"])
	assert.Equal(t, []string{"NET_RAW", "SYS_ADMIN"}, inputs["insecureCapabilities"])
}

func TestGetControlsInputs_MissingDefault(t *testing.T) {
	scheme := runtime.NewScheme()
	client := fake.NewSimpleDynamicClient(scheme)

	getter := &CRDControlInputs{client: client}
	_, err := getter.GetControlsInputs(context.TODO(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get ControlInput CRD")
}

func TestExtractControlsInputs_EmptyObject(t *testing.T) {
	obj := &unstructured.Unstructured{
		Object: map[string]any{
			"spec": map[string]any{},
		},
	}

	result, err := extractControlsInputs(obj)
	assert.NoError(t, err)
	assert.Empty(t, result)
}

func TestExtractControlsInputs_NoSpec(t *testing.T) {
	obj := &unstructured.Unstructured{
		Object: map[string]any{},
	}

	result, err := extractControlsInputs(obj)
	assert.NoError(t, err)
	assert.Empty(t, result)
}

func TestExtractControlsInputs_WithControls(t *testing.T) {
	obj := &unstructured.Unstructured{
		Object: map[string]any{
			"spec": map[string]any{
				"controls": map[string]any{
					"c-0001": []any{"val1", "val2"},
					"c-0004": []any{"val3"},
					"c-0050": []any{"0.5", "5"},
				},
			},
		},
	}

	result, err := extractControlsInputs(obj)
	assert.NoError(t, err)
	assert.Len(t, result, 3)
	assert.Equal(t, []string{"val1", "val2"}, result["c-0001"])
	assert.Equal(t, []string{"val3"}, result["c-0004"])
	assert.Equal(t, []string{"0.5", "5"}, result["c-0050"])
}

func TestExtractControlsInputs_NumericValues(t *testing.T) {
	obj := &unstructured.Unstructured{
		Object: map[string]any{
			"spec": map[string]any{
				"controls": map[string]any{
					"maxCriticalVulnerabilities": []any{int64(5)},
					"cpuLimitMin":                []any{float64(0.5)},
				},
			},
		},
	}

	result, err := extractControlsInputs(obj)
	assert.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, []string{"5"}, result["maxCriticalVulnerabilities"])
	assert.Equal(t, []string{"0.5"}, result["cpuLimitMin"])
}

func TestExtractControlsInputs_EmptyControls(t *testing.T) {
	obj := &unstructured.Unstructured{
		Object: map[string]any{
			"spec": map[string]any{
				"controls": map[string]any{},
			},
		},
	}

	result, err := extractControlsInputs(obj)
	assert.NoError(t, err)
	assert.Empty(t, result)
}

func TestExtractControlsInputs_InvalidTypeSkipped(t *testing.T) {
	// Non-array values (like a bare string) should be skipped gracefully
	obj := &unstructured.Unstructured{
		Object: map[string]any{
			"spec": map[string]any{
				"controls": map[string]any{
					"validKey":         []any{"val1"},
					"invalidStringKey": "not-an-array",
					"invalidIntKey":    int64(42),
				},
			},
		},
	}

	result, err := extractControlsInputs(obj)
	assert.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, []string{"val1"}, result["validKey"])
}
