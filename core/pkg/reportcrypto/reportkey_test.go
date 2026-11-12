package reportcrypto

import (
	"encoding/hex"
	"testing"

	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewReportKey(t *testing.T) {
	t.Run("valid DEK creates bound key", func(t *testing.T) {
		dek, err := GenerateDEK()
		require.NoError(t, err)

		key, err := NewReportKey(dek)
		require.NoError(t, err)
		require.NotNil(t, key)
		assert.Equal(t, dek, key.DEK())
		assert.Len(t, key.Binding(), bindingSize)
		assert.True(t, key.IsBound())
	})

	t.Run("invalid DEK size fails validation", func(t *testing.T) {
		tests := []struct {
			name string
			dek  []byte
		}{
			{"nil DEK", nil},
			{"empty DEK", []byte{}},
			{"short DEK (16 bytes)", make([]byte, 16)},
			{"long DEK (64 bytes)", make([]byte, 64)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				key, err := NewReportKey(tt.dek)
				require.Error(t, err)
				assert.Nil(t, key)
				assert.Contains(t, err.Error(), "invalid DEK length")
			})
		}
	})
}

func TestUnboundReportKey(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	key := UnboundReportKey(dek)
	require.NotNil(t, key)
	assert.Equal(t, dek, key.DEK())
	assert.Nil(t, key.Binding())
	assert.False(t, key.IsBound())

	// Unbound key can seal and open
	plaintext := "test-unbound-plaintext"
	ciphertext, err := key.EncryptString(plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)

	decrypted, err := key.DecryptString(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestReportKey_NilReceiver(t *testing.T) {
	var nilKey *ReportKey

	assert.Nil(t, nilKey.DEK())
	assert.Nil(t, nilKey.Binding())
	assert.False(t, nilKey.IsBound())

	// Zero on nil must be safe (no panic)
	assert.NotPanics(t, func() {
		nilKey.Zero()
	})

	encrypted, err := nilKey.EncryptString("secret")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilReportKey)
	assert.Empty(t, encrypted)

	decrypted, err := nilKey.DecryptString("ciphertext")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilReportKey)
	assert.Empty(t, decrypted)
}

func TestReportKey_Zero(t *testing.T) {
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}

	key, err := NewReportKey(dek)
	require.NoError(t, err)
	originalBinding := append([]byte(nil), key.Binding()...)

	key.Zero()

	// DEK bytes must all be zeroed
	for i, b := range key.DEK() {
		assert.Equal(t, byte(0), b, "byte at %d should be 0", i)
	}

	// Binding remains intact (non-secret label)
	assert.Equal(t, originalBinding, key.Binding())
}

func TestReportKey_BuildAAD(t *testing.T) {
	t.Run("nil binding returns nil", func(t *testing.T) {
		aad := buildAAD("field", nil)
		assert.Nil(t, aad)
	})

	t.Run("valid binding produces length-prefixed bytes", func(t *testing.T) {
		binding := []byte("0123456789abcdef")
		aad := buildAAD("field", binding)
		require.NotNil(t, aad)
		assert.NotEmpty(t, aad)
	})
}

func TestDecryptMetadataFromEnv(t *testing.T) {
	masterKey := []byte("01234567890123456789012345678901")

	t.Run("fails when neither KUBESCAPE_MASTER_KEY nor KUBESCAPE_MASTER_KEY_HEX is set", func(t *testing.T) {
		t.Setenv("KUBESCAPE_MASTER_KEY", "")
		t.Setenv("KUBESCAPE_MASTER_KEY_HEX", "")

		key, err := DecryptMetadataFromEnv(&reporthandlingv2.Metadata{})
		require.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "requires KUBESCAPE_MASTER_KEY or KUBESCAPE_MASTER_KEY_HEX to be configured")
	})

	t.Run("fails when both KUBESCAPE_MASTER_KEY and KUBESCAPE_MASTER_KEY_HEX are set", func(t *testing.T) {
		t.Setenv("KUBESCAPE_MASTER_KEY", string(masterKey))
		t.Setenv("KUBESCAPE_MASTER_KEY_HEX", hex.EncodeToString(masterKey))

		key, err := DecryptMetadataFromEnv(&reporthandlingv2.Metadata{})
		require.Error(t, err)
		assert.Nil(t, key)
		assert.ErrorIs(t, err, ErrMasterKeyAmbiguous)
	})

	t.Run("fails when KUBESCAPE_MASTER_KEY_HEX is invalid hex", func(t *testing.T) {
		t.Setenv("KUBESCAPE_MASTER_KEY", "")
		t.Setenv("KUBESCAPE_MASTER_KEY_HEX", "not-a-valid-hex")

		key, err := DecryptMetadataFromEnv(&reporthandlingv2.Metadata{})
		require.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "not valid hex")
	})

	t.Run("fails when metadata is nil", func(t *testing.T) {
		t.Setenv("KUBESCAPE_MASTER_KEY", string(masterKey))
		t.Setenv("KUBESCAPE_MASTER_KEY_HEX", "")

		key, err := DecryptMetadataFromEnv(nil)
		require.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "metadata is nil")
	})

	t.Run("fails when encryption metadata is missing", func(t *testing.T) {
		t.Setenv("KUBESCAPE_MASTER_KEY", string(masterKey))
		t.Setenv("KUBESCAPE_MASTER_KEY_HEX", "")

		metadata := &reporthandlingv2.Metadata{}
		key, err := DecryptMetadataFromEnv(metadata)
		require.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "encryption metadata not found")
	})

	t.Run("successful decryption from env", func(t *testing.T) {
		t.Setenv("KUBESCAPE_MASTER_KEY", string(masterKey))
		t.Setenv("KUBESCAPE_MASTER_KEY_HEX", "")

		dek, err := GenerateDEK()
		require.NoError(t, err)

		reportKey, err := NewReportKey(dek)
		require.NoError(t, err)

		wrappedDEK, err := WrapReportKey(reportKey, masterKey)
		require.NoError(t, err)

		encryptedRepo, err := reportKey.EncryptString("my-secret-repo")
		require.NoError(t, err)

		metadata := &reporthandlingv2.Metadata{
			EncryptionMetadata: &reporthandlingv2.EncryptionMetadata{
				EncryptedDEK: wrappedDEK,
			},
			ContextMetadata: reporthandlingv2.ContextMetadata{
				RepoContextMetadata: &reporthandlingv2.RepoContextMetadata{
					Repo: encryptedRepo,
				},
			},
		}

		key, err := DecryptMetadataFromEnv(metadata)
		require.NoError(t, err)
		require.NotNil(t, key)
		defer key.Zero()

		assert.Equal(t, "my-secret-repo", metadata.ContextMetadata.RepoContextMetadata.Repo)
		assert.Equal(t, dek, key.DEK())
		assert.Equal(t, reportKey.Binding(), key.Binding())
	})

	t.Run("failed repo context decryption zeroes key and returns error", func(t *testing.T) {
		t.Setenv("KUBESCAPE_MASTER_KEY", string(masterKey))
		t.Setenv("KUBESCAPE_MASTER_KEY_HEX", "")

		dek, err := GenerateDEK()
		require.NoError(t, err)

		reportKey, err := NewReportKey(dek)
		require.NoError(t, err)

		wrappedDEK, err := WrapReportKey(reportKey, masterKey)
		require.NoError(t, err)

		// Ciphertext with bad format or invalid payload
		metadata := &reporthandlingv2.Metadata{
			EncryptionMetadata: &reporthandlingv2.EncryptionMetadata{
				EncryptedDEK: wrappedDEK,
			},
			ContextMetadata: reporthandlingv2.ContextMetadata{
				RepoContextMetadata: &reporthandlingv2.RepoContextMetadata{
					Repo: "ENC[invalid]",
				},
			},
		}

		key, err := DecryptMetadataFromEnv(metadata)
		require.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "failed to decrypt repo")
	})
}
