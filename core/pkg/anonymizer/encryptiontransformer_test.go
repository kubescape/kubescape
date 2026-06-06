package anonymizer

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/pkg/reportcrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptionTransformer_Transform(t *testing.T) {
	dek, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)

	transformer := NewEncryptionTransformer(dek)

	plaintext := "/workspace/demo-repository"

	ciphertext, err := transformer.Transform(
		"git",
		plaintext,
	)
	require.NoError(t, err)

	assert.NotEqual(t, plaintext, ciphertext)
	assert.Contains(t, ciphertext, "ENC[AES256_GCM,")

	decrypted, err := reportcrypto.DecryptString(
		ciphertext,
		dek,
	)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptionTransformer_UniqueCiphertexts(t *testing.T) {
	dek, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)

	transformer := NewEncryptionTransformer(dek)

	ciphertext1, err := transformer.Transform(
		"git",
		"demo-repository",
	)
	require.NoError(t, err)

	ciphertext2, err := transformer.Transform(
		"git",
		"demo-repository",
	)
	require.NoError(t, err)

	assert.NotEqual(t, ciphertext1, ciphertext2)
}

func TestEncryptionTransformer_InvalidDEK(t *testing.T) {
	transformer := NewEncryptionTransformer(
		[]byte("short-key"),
	)

	_, err := transformer.Transform(
		"git",
		"demo-repository",
	)

	assert.Error(t, err)
}
