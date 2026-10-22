package cel

import (
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithoutNullFieldsDropsNullKeysAndLeavesInputAlone(t *testing.T) {
	in := map[string]any{
		"metadata": map[string]any{"name": "p", "annotations": nil},
		"spec": map[string]any{
			"volumes": nil,
			"containers": []any{
				map[string]any{"name": "c", "env": nil, "ports": []any{map[string]any{"containerPort": 80}}},
				nil,
			},
		},
	}

	out := withoutNullFields(in)

	assert.Equal(t, map[string]any{
		"metadata": map[string]any{"name": "p"},
		"spec": map[string]any{
			"containers": []any{
				map[string]any{"name": "c", "ports": []any{map[string]any{"containerPort": 80}}},
				nil, // a null list element keeps its index
			},
		},
	}, out)
	assert.Contains(t, in["metadata"], "annotations", "input must not be mutated")
	assert.Contains(t, in["spec"], "volumes", "input must not be mutated")
}

func TestWithoutNullFieldsReturnsTheSameMapWithoutNulls(t *testing.T) {
	in := map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "c"}}}}
	out := withoutNullFields(in)
	assert.Equal(t, reflect.ValueOf(in).Pointer(), reflect.ValueOf(out).Pointer(), "no nulls means no copy")
}

// An empty manifest block decodes to null. At admission the typed decode drops
// it, so these bundle controls admit the pod; they must not error offline.
func TestBundleTreatsNullFieldsAsUnset(t *testing.T) {
	pod := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "p", "namespace": "ns"},
		"spec": map[string]any{
			"volumes":        nil,
			"initContainers": nil,
			"containers": []any{map[string]any{
				"name": "c", "image": "nginx:1.25", "env": nil, "ports": nil,
			}},
		},
	}
	e, err := NewEvaluator()
	require.NoError(t, err)
	for _, id := range []string{"C-0012", "C-0020", "C-0042", "C-0044", "C-0045", "C-0046", "C-0048", "C-0057", "C-0074", "C-0193", "C-0203", "C-0204", "C-0207", "C-0295"} {
		vap, err := loadVAP(id)
		require.NoError(t, err, id)
		params, err := resolveParams(vap)
		require.NoError(t, err, id)
		ev, err := e.EvaluateVAP(context.Background(), vap, pod, nil, params)
		require.NoError(t, err, id)
		require.True(t, ev.Applicable, id)
		for i, r := range ev.Results {
			assert.NoErrorf(t, r.Err, "%s validation %d", id, i)
			assert.Truef(t, r.Passed, "%s validation %d: %s", id, i, r.Message)
		}
	}
}

// A real violation behind a null guard still fires once the null is gone:
// C-0231 denies a 443 LoadBalancer without the AWS cert annotation.
func TestNullAnnotationsStillReachTheViolation(t *testing.T) {
	svc := map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   map[string]any{"name": "s", "namespace": "ns", "annotations": nil},
		"spec": map[string]any{
			"type":  "LoadBalancer",
			"ports": []any{map[string]any{"port": 443, "targetPort": 8443}},
		},
	}
	e, err := NewEvaluator()
	require.NoError(t, err)
	vap, err := loadVAP("C-0231")
	require.NoError(t, err)
	ev, err := e.EvaluateVAP(context.Background(), vap, svc, nil, nil)
	require.NoError(t, err)
	require.True(t, ev.Applicable)
	require.Len(t, ev.Results, 1)
	assert.NoError(t, ev.Results[0].Err)
	assert.False(t, ev.Results[0].Passed)
}
