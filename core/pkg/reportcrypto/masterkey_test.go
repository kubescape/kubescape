package reportcrypto

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// legacyWrapDEK reproduces the pre-derivation wrapping scheme: the master key
// was used as the AES key with no stretching and no salt. It exists so the
// backward-compatibility tests exercise a real legacy envelope rather than one
// this package can still produce.
func legacyWrapDEK(t *testing.T, dek []byte, masterKey []byte) string {
	t.Helper()

	wrapped, err := EncryptString(
		base64.StdEncoding.EncodeToString(dek),
		masterKey,
	)
	require.NoError(t, err)

	return wrapped
}

// TestWrapDEKDerivesKeyFromMasterSecret is the regression test for the bug:
// the master secret must never be used as the AES key directly.
//
// Deliberately written against the exported API only, so it compiles against
// the pre-fix implementation too and genuinely fails there: that version passed
// the 32 bytes of KUBESCAPE_MASTER_KEY straight to aes.NewCipher, which made
// DecryptString(wrapped, masterKey) succeed.
func TestWrapDEKDerivesKeyFromMasterSecret(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	masterKey := []byte("01234567890123456789012345678901")

	wrapped, err := WrapDEK(dek, masterKey)
	require.NoError(t, err)

	_, err = DecryptString(wrapped, masterKey)
	assert.Error(
		t,
		err,
		"master secret must not double as the AES key that protects the DEK",
	)

	unwrapped, err := UnwrapDEK(wrapped, masterKey)
	require.NoError(t, err)
	assert.Equal(t, dek, unwrapped)
}

// TestWrapDEKEnvelopeAnnouncesDerivation checks the envelope header separately,
// using package internals, so a future change cannot keep the test above green
// by switching to some other undeclared scheme.
func TestWrapDEKEnvelopeAnnouncesDerivation(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	wrapped, err := WrapDEK(dek, []byte("01234567890123456789012345678901"))
	require.NoError(t, err)

	require.True(
		t,
		strings.HasPrefix(wrapped, kekPrefix),
		"wrapped DEK must carry the Argon2id envelope, got %q",
		wrapped,
	)

	_, inner, err := parseKEKCiphertext(wrapped)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(inner, prefix))
}

// TestWrapDEKUsesUniqueSaltPerEnvelope guards the property that makes the KDF
// worth having: two reports protected by the same passphrase must not share a
// key-encryption key, so a precomputed attack against one buys nothing against
// the other.
func TestWrapDEKUsesUniqueSaltPerEnvelope(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	masterKey := []byte("a-sufficiently-long-passphrase")

	first, err := WrapDEK(dek, masterKey)
	require.NoError(t, err)

	second, err := WrapDEK(dek, masterKey)
	require.NoError(t, err)

	firstParams, _, err := parseKEKCiphertext(first)
	require.NoError(t, err)

	secondParams, _, err := parseKEKCiphertext(second)
	require.NoError(t, err)

	assert.NotEqual(t, firstParams.salt, secondParams.salt)
	assert.Len(t, firstParams.salt, kekSaltSize)
}

// TestWrapDEKAcceptsPassphrasesOfAnyLength covers the usability half of the
// bug: requiring exactly 32 bytes is what pushed users toward typed ASCII.
// `openssl rand -base64 32` and `-hex 32` were both rejected before the fix.
func TestWrapDEKAcceptsPassphrasesOfAnyLength(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	tests := []struct {
		name      string
		masterKey string
	}{
		{"minimum length", "0123456789abcdef"},
		{"legacy exact 32 bytes", "01234567890123456789012345678901"},
		{"openssl rand -base64 32", "3q2+7wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		{"openssl rand -hex 32", strings.Repeat("ab", 32)},
		{"long passphrase", strings.Repeat("correct horse battery staple ", 8)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped, err := WrapDEK(dek, []byte(tt.masterKey))
			require.NoError(t, err)

			unwrapped, err := UnwrapDEK(wrapped, []byte(tt.masterKey))
			require.NoError(t, err)
			assert.Equal(t, dek, unwrapped)
		})
	}
}

func TestWrapDEKRejectsShortMasterSecret(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	_, err = WrapDEK(dek, []byte(strings.Repeat("x", minMasterKeySize-1)))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid master key length")
}

// TestUnwrapDEKReadsLegacyEnvelope keeps reports written before this change
// readable. A regression here silently strands every already-encrypted report.
func TestUnwrapDEKReadsLegacyEnvelope(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	masterKey := []byte("01234567890123456789012345678901")
	legacy := legacyWrapDEK(t, dek, masterKey)

	require.True(t, strings.HasPrefix(legacy, prefix))
	require.False(t, strings.HasPrefix(legacy, kekPrefix))

	unwrapped, err := UnwrapDEK(legacy, masterKey)
	require.NoError(t, err)
	assert.Equal(t, dek, unwrapped)
}

func TestUnwrapDEKLegacyEnvelopeStillRequiresExactKeyLength(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	legacy := legacyWrapDEK(t, dek, []byte("01234567890123456789012345678901"))

	// Long enough for the derivation path, wrong size for a legacy raw key.
	_, err = UnwrapDEK(legacy, []byte("0123456789abcdefghij"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "predates master key derivation")
}

// TestUnwrapDEKRejectsHostileWorkFactors covers the denial-of-service surface
// the envelope introduces: work factors are read from an attacker-controlled
// report, so an unbounded memory cost would let a crafted file exhaust the
// memory of whoever runs `kubescape decrypt`.
func TestUnwrapDEKRejectsHostileWorkFactors(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	masterKey := []byte("a-sufficiently-long-passphrase")

	wrapped, err := WrapDEK(dek, masterKey)
	require.NoError(t, err)

	_, inner, err := parseKEKCiphertext(wrapped)
	require.NoError(t, err)

	payload, err := ciphertextPayload(inner)
	require.NoError(t, err)

	salt := base64.StdEncoding.EncodeToString(make([]byte, kekSaltSize))

	tests := []struct {
		name   string
		header string
	}{
		{"memory cost beyond the cap", "v1,3,4294967295,4"},
		{"time cost beyond the cap", "v1,999,65536,4"},
		{"parallelism beyond the cap", "v1,3,65536,255"},
		{"memory below argon2 minimum", "v1,3,1,4"},
		{"zero time cost", "v1,0,65536,4"},
		{"unsupported version", "v2,3,65536,4"},
		{"non-numeric memory cost", "v1,3,lots,4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostile := kekPrefix + tt.header + "," + salt + "," + payload + suffix

			unwrapped, err := UnwrapDEK(hostile, masterKey)

			require.Error(t, err)
			assert.Nil(t, unwrapped)
		})
	}
}

func TestUnwrapDEKRejectsMalformedEnvelope(t *testing.T) {
	masterKey := []byte("a-sufficiently-long-passphrase")

	tests := []struct {
		name    string
		wrapped string
	}{
		{"too few fields", kekPrefix + "v1,3,65536,4]"},
		{"bad salt encoding", kekPrefix + "v1,3,65536,4,not-base64!!,bm9uY2U=,Y3Q=]"},
		{"missing terminator", kekPrefix + "v1,3,65536,4,c2FsdA==,bm9uY2U=,Y3Q="},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnwrapDEK(tt.wrapped, masterKey)
			assert.Error(t, err)
		})
	}
}

func TestGetMasterKeyFromEnv(t *testing.T) {
	t.Run("passphrase", func(t *testing.T) {
		t.Setenv(masterKeyEnvVar, "a-sufficiently-long-passphrase")

		key, err := GetMasterKeyFromEnv("encryption")
		require.NoError(t, err)
		assert.Equal(t, []byte("a-sufficiently-long-passphrase"), key)
	})

	t.Run("hex key material is decoded", func(t *testing.T) {
		raw := strings.Repeat("ab", 32)
		t.Setenv(masterKeyHexEnvVar, raw)

		key, err := GetMasterKeyFromEnv("encryption")
		require.NoError(t, err)

		want, err := hex.DecodeString(raw)
		require.NoError(t, err)
		assert.Equal(t, want, key)
	})

	t.Run("both variables set is ambiguous", func(t *testing.T) {
		t.Setenv(masterKeyEnvVar, "a-sufficiently-long-passphrase")
		t.Setenv(masterKeyHexEnvVar, strings.Repeat("ab", 32))

		_, err := GetMasterKeyFromEnv("encryption")
		require.ErrorIs(t, err, ErrMasterKeyAmbiguous)
	})

	t.Run("invalid hex is rejected", func(t *testing.T) {
		t.Setenv(masterKeyHexEnvVar, "nothexatall")

		_, err := GetMasterKeyFromEnv("encryption")
		require.Error(t, err)
		assert.Contains(t, err.Error(), masterKeyHexEnvVar)
	})

	t.Run("short secret is rejected", func(t *testing.T) {
		t.Setenv(masterKeyEnvVar, "short")

		_, err := GetMasterKeyFromEnv("encryption")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid master key length")
	})

	t.Run("unset reports both variables", func(t *testing.T) {
		t.Setenv(masterKeyEnvVar, "")
		t.Setenv(masterKeyHexEnvVar, "")

		_, err := GetMasterKeyFromEnv("decryption")
		require.Error(t, err)
		assert.Contains(t, err.Error(), masterKeyEnvVar)
		assert.Contains(t, err.Error(), "decryption")
	})
}

// TestEnvelopeReportsCurrentWorkFactors pins the parameters written into new
// reports. Raising them is a deliberate act: old reports stay readable because
// each envelope carries its own, but the constants should not drift silently.
func TestEnvelopeReportsCurrentWorkFactors(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	wrapped, err := WrapDEK(dek, []byte("a-sufficiently-long-passphrase"))
	require.NoError(t, err)

	params, _, err := parseKEKCiphertext(wrapped)
	require.NoError(t, err)

	assert.Equal(t, argon2Time, params.time)
	assert.Equal(t, argon2MemoryKiB, params.memoryKiB)
	assert.Equal(t, argon2Threads, params.threads)
	require.NoError(t, params.validate())
}
