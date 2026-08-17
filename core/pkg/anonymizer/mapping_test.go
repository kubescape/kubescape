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

// TestMapping_GetOrCreate_DeterministicAcrossInstances pins the property the
// docs promise ("identical values produce identical pseudonyms across
// reports"): two independent Mapping instances - standing in for two
// separate scan runs - must produce the same pseudonym for the same
// (prefix, value) pair. A within-instance-only check (same Mapping, called
// twice) would also pass for a construction that is deterministic only
// because of the map cache, not because the hash itself is stable.
func TestMapping_GetOrCreate_DeterministicAcrossInstances(t *testing.T) {
	assert.Equal(t,
		NewMapping().GetOrCreate("res", "same-value"),
		NewMapping().GetOrCreate("res", "same-value"))
}

// collidingNameA and collidingNameB are two distinct values whose SHA-256
// digests share their first 8 hex characters (822ee169) and differ from the
// 9th onwards. They were found by hashing sequential "payments-api-<n>" names
// and stopping at the first repeated 8-character prefix - reachable after
// ~90k names, which is the birthday bound for a 32-bit suffix and well inside
// the number of distinct values one large cluster contributes.
//
// The pair is a fixed input, so these tests are deterministic: they do not
// search for a collision at run time.
const (
	collidingNameA = "payments-api-55939"
	collidingNameB = "payments-api-89940"
)

// TestMapping_GetOrCreate_TruncatedHashDoesNotCollide covers the case the
// "different inputs should return different outputs" table entry above
// asserts but cannot detect: that entry uses two arbitrary values, which
// pass for any suffix width. This one uses a value pair chosen to collide in
// the first 32 bits of the digest, so it fails whenever the suffix is
// truncated that short, and passes only because the retained digest is wide
// enough to separate them.
func TestMapping_GetOrCreate_TruncatedHashDoesNotCollide(t *testing.T) {
	mapping := NewMapping()

	first := mapping.GetOrCreate("res", collidingNameA)
	second := mapping.GetOrCreate("res", collidingNameB)

	require.Equal(t,
		pseudoIDSuffix(t, first, "res")[:8],
		pseudoIDSuffix(t, second, "res")[:8],
		"test fixture is stale: %q and %q must still collide in the first 32 bits, otherwise this test proves nothing", collidingNameA, collidingNameB)

	assert.NotEqual(t, first, second,
		"two distinct values must not share a pseudonym: the report cannot tell them apart, and session maps keyed by the pseudonym silently lose one of them")
}

// TestMapping_GetOrCreate_SuffixRetainsEnoughDigest pins the suffix width
// itself. Without it, a future change could shorten the digest again and only
// TestMapping_GetOrCreate_TruncatedHashDoesNotCollide would notice - and only
// for the one collision the fixture happens to encode.
func TestMapping_GetOrCreate_SuffixRetainsEnoughDigest(t *testing.T) {
	suffix := pseudoIDSuffix(t, NewMapping().GetOrCreate("res", "any-value"), "res")

	assert.Len(t, suffix, pseudoIDHashLength)
	assert.GreaterOrEqual(t, len(suffix), 32,
		"a suffix shorter than 128 bits brings collisions back within reach of a single large report")
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

// TestMapping_GetOrCreate_SameValueSharesHashSuffixAcrossPrefixes pins a
// property transformSession (session.go) architecturally depends on: the
// *same raw value* must produce the *same hash suffix* regardless of
// prefix, even though the display prefix differs. A resource's own name is
// transformed with prefix "res" (session.go transformResourceMetadata), but
// a reference to that same name elsewhere - an imagePullSecrets entry or a
// ServiceAccount name - is transformed separately with prefix "ref"/"sa"
// (container.go), with no shared lookup table between the two call sites.
// The shared hash suffix is the only thing that lets a reader of a --hide
// report tell that a pod actually pulls a specific Secret or runs as a
// specific ServiceAccount, without the report ever revealing the real name.
//
// Previously untested at the suffix level: existing tests only compare full
// "<prefix>-<suffix>" strings, which differ from the prefix text alone
// regardless of whether the suffix matches. See #2687. Hashing value alone
// is deliberate, not an oversight; see the doc comment on GetOrCreate for
// the accepted trade-off this implies.
func TestMapping_GetOrCreate_SameValueSharesHashSuffixAcrossPrefixes(t *testing.T) {
	mapping := NewMapping()

	resource := mapping.GetOrCreate("res", "same-value")
	reference := mapping.GetOrCreate("ref", "same-value")
	serviceAccount := mapping.GetOrCreate("sa", "same-value")

	resourceSuffix := pseudoIDSuffix(t, resource, "res")
	referenceSuffix := pseudoIDSuffix(t, reference, "ref")
	serviceAccountSuffix := pseudoIDSuffix(t, serviceAccount, "sa")

	assert.Equal(t, resourceSuffix, referenceSuffix,
		"a resource's own pseudonym (\"res\") and a reference to the same raw name elsewhere (\"ref\") must share a hash suffix, or the report loses the ability to show that the reference points at that resource")
	assert.Equal(t, resourceSuffix, serviceAccountSuffix,
		"a resource's own pseudonym (\"res\") and a ServiceAccount name reference (\"sa\") to the same raw name must share a hash suffix, for the same reason")
}
