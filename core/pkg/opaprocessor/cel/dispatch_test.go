package cel

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mutableFilesystemPod violates C-0017: a Pod whose container does not set
// readOnlyRootFilesystem: true.
func mutableFilesystemPod() map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "mutable", "namespace": "default"},
		"spec": map[string]any{
			"containers": []any{
				map[string]any{"name": "c", "image": "nginx"},
			},
		},
	}
}

// readOnlyFilesystemPod satisfies C-0017.
func readOnlyFilesystemPod() map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "readonly", "namespace": "default"},
		"spec": map[string]any{
			"containers": []any{
				map[string]any{
					"name":            "c",
					"image":           "nginx",
					"securityContext": map[string]any{"readOnlyRootFilesystem": true},
				},
			},
		},
	}
}

// TestEvaluateControlLoadsAndEvaluatesFromBundle proves the facade wires the
// loader to the evaluator: given only a control ID and an object, it loads the
// control's policy from the embedded bundle and returns the right verdict.
func TestEvaluateControlLoadsAndEvaluatesFromBundle(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	t.Run("violating object fails the policy", func(t *testing.T) {
		eval, err := e.EvaluateControl(context.Background(), "C-0017", mutableFilesystemPod(), nil)
		require.NoError(t, err)
		require.True(t, eval.Applicable)
		require.NotEmpty(t, eval.Results)

		violated := false
		for _, res := range eval.Results {
			require.NoError(t, res.Err)
			if !res.Passed {
				violated = true
				assert.NotEmpty(t, res.Message)
			}
		}
		assert.True(t, violated, "a pod with a mutable root filesystem must violate C-0017")
	})

	t.Run("compliant object passes every validation", func(t *testing.T) {
		eval, err := e.EvaluateControl(context.Background(), "C-0017", readOnlyFilesystemPod(), nil)
		require.NoError(t, err)
		require.True(t, eval.Applicable)
		require.NotEmpty(t, eval.Results)

		for _, res := range eval.Results {
			require.NoError(t, res.Err)
			assert.True(t, res.Passed)
		}
	})

	t.Run("object outside matchConstraints is not applicable", func(t *testing.T) {
		// C-0017 constrains pods and workload kinds, not ConfigMaps. At admission
		// a ConfigMap is never matched, so the scan must not evaluate it.
		configMap := map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata":   map[string]any{"name": "cm", "namespace": "default"},
			"data":       map[string]any{"k": "v"},
		}
		eval, err := e.EvaluateControl(context.Background(), "C-0017", configMap, nil)
		require.NoError(t, err)
		assert.False(t, eval.Applicable, "a ConfigMap is outside C-0017's matchConstraints")
		assert.Empty(t, eval.Results)
	})
}

// TestEvaluateControlUnknownControl proves a control absent from the bundle
// surfaces the loader error rather than a verdict, so the scanner can map it to
// a skipped status instead of a silent pass.
func TestEvaluateControlUnknownControl(t *testing.T) {
	e, err := NewEvaluator()
	require.NoError(t, err)

	_, err = e.EvaluateControl(context.Background(), "C-9999", mutableFilesystemPod(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "C-9999")
}
