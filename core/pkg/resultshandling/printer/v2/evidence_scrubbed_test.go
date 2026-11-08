package printer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The scan overwrites ConfigMap and Secret data and container env values with
// scrubbedPlaceholder before any output is built. A path that resolves to it
// must read as redacted, never as the field's value.
func scrubbedConfigMap() *mockResource {
	return &mockResource{
		kind: "ConfigMap",
		obj: map[string]any{
			"metadata": map[string]any{"name": "cfg"},
			"data": map[string]any{
				"blob": scrubbedPlaceholder,
				"mode": scrubbedPlaceholder,
			},
		},
	}
}

func TestScrubbedValueShowsAsRedacted(t *testing.T) {
	resource := scrubbedConfigMap()
	want := "data[blob] (current: " + redactedValue + ")"

	t.Run("delete path in the terminal evidence", func(t *testing.T) {
		got := evidencePathsWithCurrentValues(deletePathControl("data[blob]"), resource, false)
		assert.Equal(t, []string{want}, got)
	})

	t.Run("review path in the terminal evidence", func(t *testing.T) {
		got := reviewPathsWithCurrentValuesRedacted(makeControlWithPaths(nil, []string{"data[blob]"}), resource)
		assert.Equal(t, []string{want}, got)
	})

	t.Run("--show-secrets cannot bring back a scrubbed value", func(t *testing.T) {
		got := evidencePathsWithCurrentValues(deletePathControl("data[blob]"), resource, true)
		assert.Equal(t, []string{want}, got)

		got = reviewPathsWithCurrentValuesUnredacted(makeControlWithPaths(nil, []string{"data[blob]"}), resource)
		assert.Equal(t, []string{want}, got)
	})

	t.Run("the JSON evidence array", func(t *testing.T) {
		got := failedPathValues(deletePathControl("data[blob]", "data[mode]"), resource)
		assert.Equal(t, []PathValue{
			{Path: "data[blob]", Value: redactedValue},
			{Path: "data[mode]", Value: redactedValue},
		}, got)
	})

	t.Run("a path that selects the whole map", func(t *testing.T) {
		got := evidencePathsWithCurrentValues(deletePathControl("data"), resource, false)
		assert.Equal(t, []string{`data (current: {"blob":"[redacted]","mode":"[redacted]"})`}, got)
	})
}

func TestScrubbedEnvValueShowsAsRedactedWithShowSecrets(t *testing.T) {
	const envValue = "spec.containers[0].env[0].value"
	resource := &mockResource{
		kind: "Pod",
		obj: map[string]any{
			"spec": map[string]any{
				"containers": []any{
					map[string]any{
						"name": "app",
						"env": []any{
							map[string]any{"name": "API_TOKEN", "value": scrubbedPlaceholder},
						},
					},
				},
			},
		},
	}

	got := evidencePathsWithCurrentValues(deletePathControl(envValue), resource, true)
	assert.Equal(t, []string{envValue + " (current: " + redactedValue + ")"}, got)
}

func TestScrubbedValueMaskLeavesOtherValuesAlone(t *testing.T) {
	resource := &mockResource{
		kind: "ConfigMap",
		obj: map[string]any{
			"data": map[string]any{
				"mode":     "production",
				"longer":   scrubbedPlaceholder + "Y",
				"lower":    "xxxxxx",
				"scrubbed": scrubbedPlaceholder,
			},
		},
	}

	for path, want := range map[string]string{
		"data.mode":     "production",
		"data.longer":   scrubbedPlaceholder + "Y",
		"data.lower":    "xxxxxx",
		"data.scrubbed": redactedValue,
	} {
		t.Run(path, func(t *testing.T) {
			got := evidencePathsWithCurrentValues(deletePathControl(path), resource, false)
			assert.Equal(t, []string{path + " (current: " + want + ")"}, got)
		})
	}
}

func TestMaskScrubbed(t *testing.T) {
	original := map[string]any{
		"a": scrubbedPlaceholder,
		"b": []any{scrubbedPlaceholder, "keep", map[string]any{"c": scrubbedPlaceholder}},
		"d": float64(1),
		"e": nil,
	}

	got := maskScrubbed(original)

	assert.Equal(t, map[string]any{
		"a": redactedValue,
		"b": []any{redactedValue, "keep", map[string]any{"c": redactedValue}},
		"d": float64(1),
		"e": nil,
	}, got)

	// The object belongs to the scan, so masking must not change it.
	require.Equal(t, scrubbedPlaceholder, original["a"])
	assert.Equal(t, scrubbedPlaceholder, original["b"].([]any)[0])
}
