package v1alpha1

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDigest(t *testing.T) {
	frameworks := StringList{"nsa", "mitre"}
	base := &SelectedContract{
		APIVersion:              APIVersion,
		Kind:                    Kind,
		Metadata:                Metadata{Name: "repo-policy"},
		MinimumKubescapeVersion: "v4.0.0",
		ContractName:            "ci",
		Contract: Contract{
			Policy: &Policy{
				Frameworks: &frameworks,
			},
		},
	}

	first, err := Digest(base)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(first, "sha256:"))
	assert.Len(t, first, len("sha256:")+64)

	second, err := Digest(base)
	require.NoError(t, err)
	assert.Equal(t, first, second, "identical selected contracts must produce the same digest")

	changed := *base
	changed.ContractName = "release"
	different, err := Digest(&changed)
	require.NoError(t, err)
	assert.NotEqual(t, first, different, "changing contractName must change the digest")
}

func TestDigestCanonical_DomainSeparation(t *testing.T) {
	payload := []byte(`{"contractName":"ci"}`)

	contractDigest := digestCanonical(DigestSchema, payload)
	effectiveDigest := digestCanonical(EffectiveRunDigestSchema, payload)

	assert.True(t, strings.HasPrefix(contractDigest, "sha256:"))
	assert.True(t, strings.HasPrefix(effectiveDigest, "sha256:"))
	assert.NotEqual(t, contractDigest, effectiveDigest, "distinct schemas must domain-separate identical canonical bytes")
}

func TestDigestEffectiveRun_MarshalError(t *testing.T) {
	_, err := DigestEffectiveRun(map[string]any{"bad": make(chan int)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marshal effective scan contract run for digest")
}
