package v1alpha1

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// digestCanonical
// ---------------------------------------------------------------------------

func TestDigestCanonical_ReturnsHexSHA256WithPrefix(t *testing.T) {
	digest := digestCanonical("test-schema:v1", []byte(`{"key":"value"}`))
	assert.True(t, strings.HasPrefix(digest, "sha256:"),
		"digest must start with 'sha256:' prefix, got %q", digest)
	// sha256 hex is always 64 chars after the prefix
	assert.Equal(t, 64, len(digest)-len("sha256:"),
		"hex-encoded SHA-256 must be 64 characters")
}

func TestDigestCanonical_Deterministic(t *testing.T) {
	payload := []byte(`{"a":1,"b":2}`)
	d1 := digestCanonical("kubescape-scan-contract:v1", payload)
	d2 := digestCanonical("kubescape-scan-contract:v1", payload)
	assert.Equal(t, d1, d2, "same inputs must always produce the same digest")
}

func TestDigestCanonical_SchemaDomainSeparation(t *testing.T) {
	payload := []byte(`{"x":"y"}`)
	d1 := digestCanonical("schema-a:v1", payload)
	d2 := digestCanonical("schema-b:v1", payload)
	assert.NotEqual(t, d1, d2,
		"different schemas with identical payload must produce different digests")
}

func TestDigestCanonical_PayloadSensitivity(t *testing.T) {
	schema := "kubescape-scan-contract:v1"
	d1 := digestCanonical(schema, []byte(`{"field":"value1"}`))
	d2 := digestCanonical(schema, []byte(`{"field":"value2"}`))
	assert.NotEqual(t, d1, d2,
		"different payloads with the same schema must produce different digests")
}

// ---------------------------------------------------------------------------
// Digest
// ---------------------------------------------------------------------------

func TestDigest_ReturnsNonEmptyDigest(t *testing.T) {
	sc := minimalSelectedContract()
	digest, err := Digest(sc)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(digest, "sha256:"))
}

func TestDigest_Deterministic(t *testing.T) {
	sc := minimalSelectedContract()
	d1, err := Digest(sc)
	require.NoError(t, err)
	d2, err := Digest(sc)
	require.NoError(t, err)
	assert.Equal(t, d1, d2, "Digest must be deterministic for identical input")
}

func TestDigest_ChangingContractName_ChangeDigest(t *testing.T) {
	sc1 := minimalSelectedContract()
	sc2 := minimalSelectedContract()
	sc2.ContractName = "different-contract"

	d1, err := Digest(sc1)
	require.NoError(t, err)
	d2, err := Digest(sc2)
	require.NoError(t, err)
	assert.NotEqual(t, d1, d2,
		"a change in ContractName must produce a different digest")
}

func TestDigest_ChangingMetadataName_ChangeDigest(t *testing.T) {
	sc1 := minimalSelectedContract()
	sc2 := minimalSelectedContract()
	sc2.Metadata.Name = "other-name"

	d1, err := Digest(sc1)
	require.NoError(t, err)
	d2, err := Digest(sc2)
	require.NoError(t, err)
	assert.NotEqual(t, d1, d2,
		"a change in Metadata.Name must produce a different digest")
}

func TestDigest_ChangingMinimumVersion_ChangeDigest(t *testing.T) {
	sc1 := minimalSelectedContract()
	sc2 := minimalSelectedContract()
	sc2.MinimumKubescapeVersion = "v99.0.0"

	d1, err := Digest(sc1)
	require.NoError(t, err)
	d2, err := Digest(sc2)
	require.NoError(t, err)
	assert.NotEqual(t, d1, d2,
		"a change in MinimumKubescapeVersion must produce a different digest")
}

// ---------------------------------------------------------------------------
// DigestEffectiveRun
// ---------------------------------------------------------------------------

func TestDigestEffectiveRun_ReturnsNonEmptyDigest(t *testing.T) {
	input := map[string]string{"framework": "nsa", "cluster": "my-cluster"}
	digest, err := DigestEffectiveRun(input)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(digest, "sha256:"))
}

func TestDigestEffectiveRun_Deterministic(t *testing.T) {
	input := map[string]string{"framework": "nsa"}
	d1, err := DigestEffectiveRun(input)
	require.NoError(t, err)
	d2, err := DigestEffectiveRun(input)
	require.NoError(t, err)
	assert.Equal(t, d1, d2)
}

func TestDigestEffectiveRun_SchemaSeparatedFromDigest(t *testing.T) {
	sc := minimalSelectedContract()
	contractDigest, err := Digest(sc)
	require.NoError(t, err)

	runDigest, err := DigestEffectiveRun(map[string]string{"same": "data"})
	require.NoError(t, err)

	// Even if by coincidence the JSON were identical the schema prefix ensures
	// the two domains never collide.
	assert.NotEqual(t, contractDigest, runDigest,
		"Digest and DigestEffectiveRun use different schema prefixes so they must not collide")
}

func TestDigestEffectiveRun_UnserializableInput_ReturnsError(t *testing.T) {
	// Channels cannot be marshalled to JSON.
	ch := make(chan int)
	_, err := DigestEffectiveRun(ch)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func minimalSelectedContract() *SelectedContract {
	return &SelectedContract{
		APIVersion:              APIVersion,
		Kind:                    Kind,
		Metadata:                Metadata{Name: "default"},
		MinimumKubescapeVersion: "v3.0.0",
		ContractName:            "default",
		Contract:                Contract{},
	}
}
