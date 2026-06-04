package reportcrypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := "/home/devjijo/work/kubescape"

	dek, err := GenerateDEK()
	require.NoError(t, err)

	ciphertext, err := EncryptString(plaintext, dek)
	require.NoError(t, err)

	assert.NotEqual(t, plaintext, ciphertext)

	restored, err := DecryptString(ciphertext, dek)
	require.NoError(t, err)

	assert.Equal(t, plaintext, restored)
}

func TestEncryptString_UniqueCiphertexts(t *testing.T) {
	plaintext := "kubescape"

	dek, err := GenerateDEK()
	require.NoError(t, err)

	ciphertext1, err := EncryptString(plaintext, dek)
	require.NoError(t, err)

	ciphertext2, err := EncryptString(plaintext, dek)
	require.NoError(t, err)

	assert.NotEqual(t, ciphertext1, ciphertext2)
}

func TestDecryptString_WrongDEK(t *testing.T) {
	dek1, err := GenerateDEK()
	require.NoError(t, err)

	dek2, err := GenerateDEK()
	require.NoError(t, err)

	ciphertext, err := EncryptString("super-secret-value", dek1)
	require.NoError(t, err)

	_, err = DecryptString(ciphertext, dek2)

	assert.Error(t, err)
}

func TestGenerateDEK_Length(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	assert.Len(t, dek, 32)
}

func TestDecryptString_InvalidCiphertext(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	_, err = DecryptString("not-a-valid-ciphertext", dek)

	assert.Error(t, err)
}

func TestEncryptString_EmptyPlaintext(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	ciphertext, err := EncryptString("", dek)
	require.NoError(t, err)

	restored, err := DecryptString(ciphertext, dek)
	require.NoError(t, err)

	assert.Equal(t, "", restored)
}

func TestEncryptString_InvalidDEKLength(t *testing.T) {
	invalidDEK := []byte("short-key")

	_, err := EncryptString("secret", invalidDEK)

	assert.Error(t, err)
}

func TestDecryptString_InvalidDEKLength(t *testing.T) {
	invalidDEK := []byte("short-key")

	_, err := DecryptString(
		"ENC[AES256_GCM,bm9uY2U=,Y2lwaGVydGV4dA==]",
		invalidDEK,
	)

	assert.Error(t, err)
}

func TestEncryptString_Format(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	ciphertext, err := EncryptString("secret", dek)
	require.NoError(t, err)

	assert.Contains(t, ciphertext, "ENC[AES256_GCM,")
	assert.Contains(t, ciphertext, "]")
}

func TestGenerateDEK_UniqueKeys(t *testing.T) {
	dek1, err := GenerateDEK()
	require.NoError(t, err)

	dek2, err := GenerateDEK()
	require.NoError(t, err)

	assert.NotEqual(t, dek1, dek2)
}

func TestDecryptString_InvalidNonceSize(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	_, err = DecryptString(
		"ENC[AES256_GCM,YWJj,Y2lwaGVydGV4dA==]",
		dek,
	)

	assert.Error(t, err)
}
