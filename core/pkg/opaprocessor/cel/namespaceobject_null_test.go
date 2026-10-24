package cel

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// evaluateNamespaceObjectBothWays evaluates expression on a Pod with the given
// Namespace bound as namespaceObject, once as the scanned manifest and once as
// the native typed conversion the apiserver hands admission. Both results must
// agree, so an expectation cannot drift from the typed decoding.
func evaluateNamespaceObjectBothWays(t *testing.T, manifest, expression string) (fromManifest, fromTyped bool) {
	t.Helper()
	pod := rawManifest(t, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","namespace":"ns"}}`)
	e, err := NewEvaluator()
	require.NoError(t, err)

	evaluate := func(namespace map[string]any) bool {
		results, err := e.EvaluateOnObject(context.Background(), pod, namespace, nil, nil,
			[]Validation{{Expression: expression}})
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.NoError(t, results[0].Err, results[0].Message)
		return results[0].Passed
	}
	return evaluate(rawManifest(t, manifest)), evaluate(typedDecode(t, manifest))
}

// An empty block in the Namespace manifest is null in the file, but the
// apiserver hands a policy the typed Namespace, where an omitempty map is
// unset. namespaceObject must present the same view as that typed Namespace.
func TestNamespaceObjectNullFieldsMatchTypedDecoding(t *testing.T) {
	manifest := `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"ns","annotations":null,"labels":null}}`
	for _, expression := range []string{
		"!has(namespaceObject.metadata.annotations)",
		"!has(namespaceObject.metadata.labels)",
	} {
		fromManifest, fromTyped := evaluateNamespaceObjectBothWays(t, manifest, expression)
		assert.Truef(t, fromTyped, "typed conversion: %s", expression)
		assert.Equalf(t, fromTyped, fromManifest, "namespaceObject must match the typed conversion: %s", expression)
	}
}

// creationTimestamp is tagged omitzero, so a zero metav1.Time is dropped by the
// typed decode: a null in the manifest is absent, not a null, at admission.
func TestNamespaceObjectDropsAnOmitZeroNull(t *testing.T) {
	manifest := `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"ns","creationTimestamp":null}}`
	fromManifest, fromTyped := evaluateNamespaceObjectBothWays(t, manifest, "!has(namespaceObject.metadata.creationTimestamp)")
	assert.True(t, fromTyped, "typed conversion drops the zero creationTimestamp")
	assert.Equal(t, fromTyped, fromManifest)
}

// A null the typed decode keeps must stay visible through namespaceObject: a
// condition's lastTransitionTime is only omitempty, so its zero value stays as
// the null it serializes to.
func TestNamespaceObjectKeepsNullsTheTypedDecodingKeeps(t *testing.T) {
	manifest := `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"ns"},` +
		`"status":{"conditions":[{"type":"Ready","status":"True","lastTransitionTime":null}]}}`
	fromManifest, fromTyped := evaluateNamespaceObjectBothWays(t, manifest,
		"has(namespaceObject.status.conditions[0].lastTransitionTime) && namespaceObject.status.conditions[0].lastTransitionTime == null")
	assert.True(t, fromTyped, "typed conversion keeps an omitempty zero lastTransitionTime as null")
	assert.Equal(t, fromTyped, fromManifest)
}
