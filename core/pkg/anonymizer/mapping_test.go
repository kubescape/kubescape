package anonymizer

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapping_GetOrCreate(t *testing.T) {
	tests := []struct {
		name     string
		prefixA  string
		valueA   string
		prefixB  string
		valueB   string
		validate func(t *testing.T, first, second string)
	}{
		{
			name:    "same input should return same output",
			prefixA: "res",
			valueA:  "my-pod",
			prefixB: "res",
			valueB:  "my-pod",
			validate: func(t *testing.T, first, second string) {
				assert.Equal(t, first, second)
			},
		},
		{
			name:    "different inputs should return different outputs",
			prefixA: "res",
			valueA:  "pod-a",
			prefixB: "res",
			valueB:  "pod-b",
			validate: func(t *testing.T, first, second string) {
				assert.NotEqual(t, first, second)
			},
		},
		{
			name:    "different prefixes should isolate mappings",
			prefixA: "res",
			valueA:  "same-value",
			prefixB: "ns",
			valueB:  "same-value",
			validate: func(t *testing.T, first, second string) {
				assert.NotEqual(t, first, second)
			},
		},
		{
			name:    "empty value should still produce deterministic mapping",
			prefixA: "res",
			valueA:  "",
			prefixB: "res",
			valueB:  "",
			validate: func(t *testing.T, first, second string) {
				assert.Equal(t, first, second)
				assert.Contains(t, first, "res-")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mapping := NewMapping()

			first := mapping.GetOrCreate(test.prefixA, test.valueA)
			second := mapping.GetOrCreate(test.prefixB, test.valueB)

			test.validate(t, first, second)
		})
	}
}

func TestMapping_GetOrCreate_PrefixIsolationAcrossMultiplePrefixes(t *testing.T) {
	mapping := NewMapping()

	resource := mapping.GetOrCreate("res", "same-value")
	namespace := mapping.GetOrCreate("ns", "same-value")
	label := mapping.GetOrCreate("lbl", "same-value")

	assert.NotEqual(t, resource, namespace)
	assert.NotEqual(t, resource, label)
	assert.NotEqual(t, namespace, label)
}

// pseudoIDSuffix returns the hash portion of a "<prefix>-<suffix>" pseudo-ID.
func pseudoIDSuffix(t *testing.T, pseudoID, prefix string) string {
	t.Helper()
	suffix := strings.TrimPrefix(pseudoID, prefix+"-")
	require.NotEqual(t, pseudoID, suffix, "pseudo-ID %q must start with %q-", pseudoID, prefix)
	return suffix
}

// TestMapping_GetOrCreate_HashSuffixDoesNotLeakAcrossPrefixes guards against a
// regression where GetOrCreate hashed only the raw value, not prefix+value.
// The pseudo-ID's display prefix always differs across categories, so the
// full string was always distinct - but the hash *suffix* was identical
// whenever the same raw value was mapped under two different prefixes (e.g.
// a namespace and a resource name that happen to be the same string). That
// let an observer notice "res-a1b2c3d4" and "ns-a1b2c3d4" share a suffix and
// infer the two original values were equal, without ever learning what the
// value was - exactly the cross-category correlation an anonymizer must not
// allow.
func TestMapping_GetOrCreate_HashSuffixDoesNotLeakAcrossPrefixes(t *testing.T) {
	mapping := NewMapping()

	resource := mapping.GetOrCreate("res", "same-value")
	namespace := mapping.GetOrCreate("ns", "same-value")

	resourceSuffix := pseudoIDSuffix(t, resource, "res")
	namespaceSuffix := pseudoIDSuffix(t, namespace, "ns")

	assert.NotEqual(t, resourceSuffix, namespaceSuffix,
		"hash suffix must not be identical across prefixes for the same raw value - it leaks that the two original values are equal")
}
