package getter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

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
