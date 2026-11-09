package printer

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The scan overwrites ConfigMap and Secret data and container env values with
// scrubbedPlaceholder before any output is built. A path that resolves to one
// of those fields must read as redacted, never as the field's value.
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

// The text alone does not make a value scrubbed. A label, an annotation or an
// image can hold it as a genuine value, and evidence must show that value.
// Each case runs with and without --show-secrets: the expected text is the same
// either way, because the credential-shaped fields are redacted by name anyway.
func TestScrubbedPlaceholderIsMaskedOnlyWhereTheScanWritesIt(t *testing.T) {
	const x = scrubbedPlaceholder

	configMap := &mockResource{kind: "ConfigMap", obj: map[string]any{
		"metadata":   map[string]any{"labels": map[string]any{"tier": x}},
		"data":       map[string]any{"blob": x},
		"binaryData": map[string]any{"bin": x},
	}}
	secret := &mockResource{kind: "Secret", obj: map[string]any{
		"metadata":   map[string]any{"annotations": map[string]any{"note": x}},
		"data":       map[string]any{"k": x},
		"stringData": map[string]any{"s": x},
	}}
	deployment := &mockResource{kind: "Deployment", obj: map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{"note": x}},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{
				"name":  "app",
				"image": x,
				"env":   []any{map[string]any{"name": "LOG", "value": x}},
			}},
			"initContainers": []any{map[string]any{
				"name": "init",
				"env":  []any{map[string]any{"name": "SETUP", "value": x}},
			}},
		}}},
	}}

	const pod = "spec.template.spec."
	tests := []struct {
		name     string
		resource *mockResource
		path     string
		want     string
	}{
		{"ConfigMap data is scrubbed", configMap, "data[blob]", redactedValue},
		{"ConfigMap binaryData is scrubbed", configMap, "binaryData[bin]", redactedValue},
		{"a ConfigMap label that reads the same is kept", configMap, "metadata.labels.tier", x},
		{"Secret data is scrubbed", secret, "data[k]", redactedValue},
		{"Secret stringData is scrubbed", secret, "stringData[s]", redactedValue},
		{"a Secret annotation that reads the same is kept", secret, "metadata.annotations.note", x},
		{"a container env value is scrubbed", deployment, pod + "containers[0].env[0].value", redactedValue},
		{"an init container env value is scrubbed", deployment, pod + "initContainers[0].env[0].value", redactedValue},
		{"an image that reads the same is kept", deployment, pod + "containers[0].image", x},
		{"a workload annotation that reads the same is kept", deployment, "metadata.annotations.note", x},
		{
			"a selected container masks the env value and keeps the image",
			deployment, pod + "containers[0]",
			`{"env":[{"name":"LOG","value":"[redacted]"}],"image":"XXXXXX","name":"app"}`,
		},
		{"a selected ConfigMap metadata is kept whole", configMap, "metadata", `{"labels":{"tier":"XXXXXX"}}`},
	}

	for _, tt := range tests {
		for _, showSecrets := range []bool{false, true} {
			t.Run(tt.name, func(t *testing.T) {
				got := evidencePathsWithCurrentValues(deletePathControl(tt.path), tt.resource, showSecrets)
				assert.Equal(t, []string{tt.path + " (current: " + tt.want + ")"}, got)
			})
		}
	}

	t.Run("a field outside a container that reads the same is kept with --show-secrets", func(t *testing.T) {
		// "env[0].value" is redacted by name wherever it appears, so only
		// --show-secrets can show whether the scrub logic itself treats it as
		// scrubbed. It must not: a custom resource's env is not a container's.
		widget := &mockResource{kind: "Widget", obj: map[string]any{
			"spec": map[string]any{"env": []any{map[string]any{"name": "A", "value": x}}},
		}}
		const path = "spec.env[0].value"
		got := evidencePathsWithCurrentValues(deletePathControl(path), widget, true)
		assert.Equal(t, []string{path + " (current: " + x + ")"}, got)
	})
}

func TestMaskScrubbedDoesNotCopyUnchangedSubtrees(t *testing.T) {
	clean := map[string]any{"a": "x", "b": []any{"y", map[string]any{"c": "z"}}}
	data := map[string]any{"k": scrubbedPlaceholder}
	root := map[string]any{"clean": clean, "data": data}

	got, changed := maskScrubbed("ConfigMap", nil, root)

	require.True(t, changed)
	out, ok := got.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, redactedValue, out["data"].(map[string]any)["k"])

	// The subtree with nothing to mask is shared with the original, not copied.
	assert.Equal(t, reflect.ValueOf(clean).Pointer(), reflect.ValueOf(out["clean"]).Pointer())

	// The object belongs to the scan, so masking must not change it.
	assert.Equal(t, scrubbedPlaceholder, data["k"])
	assert.NotEqual(t, reflect.ValueOf(root).Pointer(), reflect.ValueOf(out).Pointer())

	// With nothing to mask, the same object comes back and nothing is reported.
	same, changed := maskScrubbed("ConfigMap", nil, clean)
	assert.False(t, changed)
	assert.Equal(t, reflect.ValueOf(clean).Pointer(), reflect.ValueOf(same).Pointer())
}

func TestIsScrubbedLocation(t *testing.T) {
	seg := func(keys ...string) []pathSegment {
		out := make([]pathSegment, len(keys))
		for i, key := range keys {
			out[i] = pathSegment{Key: key, Index: -1}
		}
		return out
	}
	env := func(list string) []pathSegment {
		return []pathSegment{{Key: "spec", Index: -1}, {Key: list, Index: 0}, {Key: "env", Index: 2}, {Key: "value", Index: -1}}
	}

	assert.True(t, isScrubbedLocation("Secret", seg("data", "k")))
	assert.True(t, isScrubbedLocation("Secret", seg("stringData", "k")))
	assert.False(t, isScrubbedLocation("Secret", seg("data")), "the map itself is not a value")
	assert.False(t, isScrubbedLocation("Secret", seg("metadata", "name")))
	assert.True(t, isScrubbedLocation("ConfigMap", seg("data", "k")))
	assert.True(t, isScrubbedLocation("ConfigMap", seg("binaryData", "k")))
	assert.False(t, isScrubbedLocation("ConfigMap", seg("stringData", "k")), "ConfigMaps have no stringData")
	assert.True(t, isScrubbedLocation("Pod", env("containers")))
	assert.True(t, isScrubbedLocation("Pod", env("initContainers")))
	assert.True(t, isScrubbedLocation("Pod", env("ephemeralContainers")))
	assert.False(t, isScrubbedLocation("Widget", env("sidecars")))
	assert.False(t, isScrubbedLocation("Pod", seg("spec", "image")))
	assert.False(t, isScrubbedLocation("Pod", nil))
}
