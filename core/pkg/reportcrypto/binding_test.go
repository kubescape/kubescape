package reportcrypto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const bindingTestMasterKey = "01234567890123456789012345678901"

// TestReportKeyRejectsCiphertextFromAnotherReport is the regression test for
// the interchangeable-ciphertext bug.
//
// Two reports may legitimately share a DEK: ApplyEncrypted takes the key from
// its caller rather than generating one, so any embedder that reuses a key
// produces reports whose ciphertexts were, before bindings existed, freely
// portable between them. Sealing with nil associated data made every such blob
// authenticate anywhere the key reached.
//
// On the unfixed code both keys seal and open with nil AAD, so the lift below
// succeeds and this test fails.
func TestReportKeyRejectsCiphertextFromAnotherReport(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	first, err := NewReportKey(dek)
	require.NoError(t, err)

	second, err := NewReportKey(dek)
	require.NoError(t, err)

	require.NotEqual(t, first.Binding(), second.Binding())

	ciphertext, err := first.EncryptString("git@github.com:acme/private.git")
	require.NoError(t, err)

	roundTripped, err := first.DecryptString(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, "git@github.com:acme/private.git", roundTripped)

	_, err = second.DecryptString(ciphertext)
	require.Error(t, err, "a ciphertext lifted from another report must not authenticate")
	assert.Contains(t, err.Error(), "message authentication failed")
}

// TestWrappedDEKAndFieldEnvelopesAreNotInterchangeable covers the second half of
// the bug: with no associated data, a wrapped DEK and a report field are the
// same construction and are told apart only by their textual prefix, which an
// attacker with write access controls.
func TestWrappedDEKAndFieldEnvelopesAreNotInterchangeable(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	key, err := NewReportKey(dek)
	require.NoError(t, err)

	asField, err := sealString("payload", dek, buildAAD(aadDomainField, key.Binding()))
	require.NoError(t, err)

	_, err = openString(asField, dek, buildAAD(aadDomainDEK, key.Binding()))
	require.Error(t, err, "a field ciphertext must not open as a wrapped DEK")

	asDEK, err := sealString("payload", dek, buildAAD(aadDomainDEK, key.Binding()))
	require.NoError(t, err)

	_, err = openString(asDEK, dek, buildAAD(aadDomainField, key.Binding()))
	require.Error(t, err, "a wrapped DEK ciphertext must not open as a field")
}

// TestBuildAADIsUnambiguous guards the encoding itself. Concatenating the
// components instead of length-prefixing them would let two different
// (domain, binding) pairs render to identical bytes, which silently returns the
// interchangeability this change removes.
func TestBuildAADIsUnambiguous(t *testing.T) {
	binding := []byte("0123456789abcdef")

	assert.NotEqual(t, buildAAD("dek", binding), buildAAD("field", binding))

	// The classic split-point collision: "de"+"k..." vs "d"+"ek...".
	assert.NotEqual(
		t,
		buildAAD("de", append([]byte("k"), binding...)),
		buildAAD("d", append([]byte("ek"), binding...)),
	)

	assert.Nil(t, buildAAD(aadDomainField, nil), "an unbound key must seal with no associated data")
}

// TestUnboundReportsRemainDecryptable pins the backward-compatibility contract.
// Reports written before bindings existed carry a v1 envelope and fields sealed
// with no associated data, and must keep opening unchanged.
func TestUnboundReportsRemainDecryptable(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	wrapped, err := WrapDEK(dek, []byte(bindingTestMasterKey))
	require.NoError(t, err)

	require.True(
		t,
		strings.HasPrefix(wrapped, kekPrefix+kekVersion+","),
		"the deprecated bare-DEK path must keep emitting the v1 envelope",
	)

	key, err := UnwrapReportKey(wrapped, []byte(bindingTestMasterKey))
	require.NoError(t, err)
	assert.Equal(t, dek, key.DEK())
	assert.False(t, key.IsBound())

	legacyCiphertext, err := EncryptString("demo-repository", dek)
	require.NoError(t, err)

	plaintext, err := key.DecryptString(legacyCiphertext)
	require.NoError(t, err)
	assert.Equal(t, "demo-repository", plaintext)
}

// TestBoundEnvelopeRoundTrip checks the new envelope end to end, including that
// the binding survives the wrap/unwrap cycle intact.
func TestBoundEnvelopeRoundTrip(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	key, err := NewReportKey(dek)
	require.NoError(t, err)

	wrapped, err := WrapReportKey(key, []byte(bindingTestMasterKey))
	require.NoError(t, err)

	require.True(
		t,
		strings.HasPrefix(wrapped, kekPrefix+kekVersionBound+","),
		"WrapReportKey must emit the bound envelope",
	)

	unwrapped, err := UnwrapReportKey(wrapped, []byte(bindingTestMasterKey))
	require.NoError(t, err)

	assert.Equal(t, key.DEK(), unwrapped.DEK())
	assert.Equal(t, key.Binding(), unwrapped.Binding())

	ciphertext, err := key.EncryptString("demo commit")
	require.NoError(t, err)

	plaintext, err := unwrapped.DecryptString(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, "demo commit", plaintext)
}

// TestBoundEnvelopeRejectsTamperedBinding confirms the binding is authenticated
// rather than merely recorded: rewriting it in the envelope must break the
// unwrap instead of silently changing which ciphertexts the report accepts.
func TestBoundEnvelopeRejectsTamperedBinding(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	key, err := NewReportKey(dek)
	require.NoError(t, err)

	wrapped, err := WrapReportKey(key, []byte(bindingTestMasterKey))
	require.NoError(t, err)

	// kekPrefix ends in a comma, so the envelope splits into 9 fields and the
	// binding sits at index 6.
	parts := strings.Split(wrapped, ",")
	require.Len(t, parts, 9)

	other, err := NewReportKey(dek)
	require.NoError(t, err)

	forged, err := WrapReportKey(other, []byte(bindingTestMasterKey))
	require.NoError(t, err)

	// Swap in a well-formed binding taken from a different report.
	parts[6] = strings.Split(forged, ",")[6]

	_, err = UnwrapReportKey(strings.Join(parts, ","), []byte(bindingTestMasterKey))
	require.Error(t, err, "a rewritten binding must fail the DEK's authentication tag")
}

// TestParseKEKCiphertextRejectsMalformedBinding keeps the envelope parser strict
// about a field it now trusts to select the AAD.
func TestParseKEKCiphertextRejectsMalformedBinding(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	key, err := NewReportKey(dek)
	require.NoError(t, err)

	wrapped, err := WrapReportKey(key, []byte(bindingTestMasterKey))
	require.NoError(t, err)

	parts := strings.Split(wrapped, ",")
	require.Len(t, parts, 9)

	t.Run("not base64", func(t *testing.T) {
		tampered := append([]string(nil), parts...)
		tampered[6] = "!!!not-base64!!!"

		_, _, _, err := parseKEKCiphertext(strings.Join(tampered, ","))
		require.ErrorIs(t, err, ErrInvalidKEKEnvelope)
	})

	t.Run("wrong length", func(t *testing.T) {
		tampered := append([]string(nil), parts...)
		tampered[6] = "c2hvcnQ=" // "short"

		_, _, _, err := parseKEKCiphertext(strings.Join(tampered, ","))
		require.ErrorIs(t, err, ErrInvalidKEKEnvelope)
	})

	t.Run("unknown version", func(t *testing.T) {
		tampered := append([]string(nil), parts...)
		tampered[1] = "v99"

		_, _, _, err := parseKEKCiphertext(strings.Join(tampered, ","))
		require.ErrorIs(t, err, ErrInvalidKEKEnvelope)
	})
}
