package fixhandler

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// liveDeployment mirrors what a cluster scan records: the object as the API
// server returned it, including the fields the server owns.
func liveDeployment() map[string]any {
	return map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":              "nginx",
			"namespace":         "default",
			"uid":               "8f1a2b3c-0000-4444-8888-abcdefabcdef",
			"resourceVersion":   "123456",
			"generation":        int64(3),
			"creationTimestamp": "2026-08-31T10:00:00Z",
			"selfLink":          "/apis/apps/v1/namespaces/default/deployments/nginx",
			"managedFields": []any{
				map[string]any{"manager": "kubectl-client-side-apply", "operation": "Update"},
			},
			"annotations": map[string]any{
				lastAppliedConfigAnnotation: `{"apiVersion":"apps/v1","kind":"Deployment"}`,
				"team":                      "platform",
			},
		},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "nginx",
							"image": "nginx:latest",
							"securityContext": map[string]any{
								"privileged": true,
							},
						},
					},
				},
			},
		},
		"status": map[string]any{
			"replicas":      int64(1),
			"readyReplicas": int64(1),
		},
	}
}

const privilegedFixExpression = `select(di==0).spec.template.spec.containers[0].securityContext.privileged |= false`

func TestRenderFixedManifest_AppliesTheFix(t *testing.T) {
	got, err := RenderFixedManifest(context.Background(), liveDeployment(), privilegedFixExpression)
	require.NoError(t, err)

	assert.Contains(t, got, "privileged: false")
	assert.NotContains(t, got, "privileged: true")

	// The rest of the resource has to survive the round trip, or the emitted
	// manifest would apply a fix and silently drop everything else.
	assert.Contains(t, got, "name: nginx")
	assert.Contains(t, got, "image: nginx:latest")
	assert.Contains(t, got, "kind: Deployment")
}

func TestRenderFixedManifest_StripsServerManagedFields(t *testing.T) {
	got, err := RenderFixedManifest(context.Background(), liveDeployment(), privilegedFixExpression)
	require.NoError(t, err)

	for _, field := range []string{
		"status:",
		"managedFields",
		"resourceVersion",
		"uid:",
		"generation:",
		"creationTimestamp",
		"selfLink",
		lastAppliedConfigAnnotation,
	} {
		assert.NotContainsf(t, got, field, "%s is owned by the API server and must not reach the manifest", field)
	}

	// Annotations the user actually set are not server-managed and must stay.
	assert.Contains(t, got, "team: platform")
}

// TestRenderFixedManifest_DoesNotMutateInput guards the shallow-copy strategy:
// the object belongs to the report and is read again by the caller, so
// rendering must not strip fields out from under it.
func TestRenderFixedManifest_DoesNotMutateInput(t *testing.T) {
	obj := liveDeployment()

	_, err := RenderFixedManifest(context.Background(), obj, privilegedFixExpression)
	require.NoError(t, err)

	assert.Contains(t, obj, "status", "top-level status was removed from the caller's map")

	metadata, ok := obj["metadata"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, metadata, "managedFields", "metadata was mutated in place")
	assert.Contains(t, metadata, "resourceVersion")

	annotations, ok := metadata["annotations"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, annotations, lastAppliedConfigAnnotation, "annotations were mutated in place")

	// The original object must still be privileged: the fix is applied to the
	// serialized copy, never to the report's own resource.
	containers := obj["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)
	sc := containers[0].(map[string]any)["securityContext"].(map[string]any)
	assert.Equal(t, true, sc["privileged"])
}

// TestRenderFixedManifest_OutputIsValidYAML is the property that matters most:
// the emitted text has to parse as a Kubernetes manifest, or `kubectl apply`
// rejects it no matter how correct the patch was.
func TestRenderFixedManifest_OutputIsValidYAML(t *testing.T) {
	got, err := RenderFixedManifest(context.Background(), liveDeployment(), privilegedFixExpression)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(got), &parsed), "rendered manifest must parse")

	assert.Equal(t, "apps/v1", parsed["apiVersion"])
	assert.Equal(t, "Deployment", parsed["kind"])
	assert.NotContains(t, parsed, "status")

	metadata, ok := parsed["metadata"].(map[string]any)
	require.True(t, ok, "metadata must survive as a map")
	assert.Equal(t, "nginx", metadata["name"])
	assert.NotContains(t, metadata, "managedFields")
}

// TestRenderFixedManifest_UsesKubernetesIndent pins the two-space indent.
// yaml.Marshal defaults to four, which parses the same but makes every line of
// a rendered manifest differ from the file a user diffs it against.
func TestRenderFixedManifest_UsesKubernetesIndent(t *testing.T) {
	got, err := RenderFixedManifest(context.Background(), liveDeployment(), privilegedFixExpression)
	require.NoError(t, err)

	assert.Contains(t, got, "\n  name: nginx", "metadata keys should sit at two spaces")
	assert.NotContains(t, got, "\n    name: nginx", "four-space indent means SetIndent was lost")
}

func TestRenderFixedManifest_AddsAbsentField(t *testing.T) {
	// The common case: the control failed because the field is missing, so the
	// fix has to create it rather than overwrite one.
	obj := liveDeployment()
	containers := obj["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)
	delete(containers[0].(map[string]any), "securityContext")

	got, err := RenderFixedManifest(context.Background(), obj,
		`select(di==0).spec.template.spec.containers[0].securityContext.runAsNonRoot |= true`)
	require.NoError(t, err)

	assert.Contains(t, got, "runAsNonRoot: true")
}

func TestRenderFixedManifest_StripsWithoutMetadata(t *testing.T) {
	// A resource with no metadata map must not panic on the metadata branch.
	obj := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"spec":       map[string]any{"hostNetwork": true},
		"status":     map[string]any{"phase": "Running"},
	}

	got, err := RenderFixedManifest(context.Background(), obj, `select(di==0).spec.hostNetwork |= false`)
	require.NoError(t, err)

	assert.Contains(t, got, "hostNetwork: false")
	assert.NotContains(t, got, "status")
}

func TestRenderFixedManifest_Errors(t *testing.T) {
	tests := []struct {
		name       string
		obj        map[string]any
		expression string
		wantErr    string
	}{
		{
			name:       "nil resource",
			obj:        nil,
			expression: privilegedFixExpression,
			wantErr:    "empty resource",
		},
		{
			name:       "empty resource",
			obj:        map[string]any{},
			expression: privilegedFixExpression,
			wantErr:    "empty resource",
		},
		{
			name:       "no expression",
			obj:        liveDeployment(),
			expression: "",
			wantErr:    "without a yaml expression",
		},
		{
			name:       "malformed expression",
			obj:        liveDeployment(),
			expression: "select(di==0).spec |= (((",
			wantErr:    "failed to apply fix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				got, err := RenderFixedManifest(context.Background(), tt.obj, tt.expression)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Empty(t, got, "no manifest may be returned alongside an error")
			})
		})
	}
}

// TestRenderFixedManifest_Deterministic matters because the output is written
// to files and diffed by users; an unstable key order would show spurious
// changes between runs.
func TestRenderFixedManifest_Deterministic(t *testing.T) {
	first, err := RenderFixedManifest(context.Background(), liveDeployment(), privilegedFixExpression)
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		next, err := RenderFixedManifest(context.Background(), liveDeployment(), privilegedFixExpression)
		require.NoError(t, err)
		require.Equal(t, first, next, "rendering must be stable across runs")
	}

	assert.False(t, strings.HasPrefix(first, "---"), "a single resource should not be emitted as a document stream")
}
