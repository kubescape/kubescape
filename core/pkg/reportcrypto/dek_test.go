package reportcrypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapAndUnwrapDEK(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	masterKey, err := GenerateDEK()
	require.NoError(t, err)

	wrappedDEK, err := WrapDEK(
		dek,
		masterKey,
	)
	require.NoError(t, err)

	unwrappedDEK, err := UnwrapDEK(
		wrappedDEK,
		masterKey,
	)
	require.NoError(t, err)

	assert.Equal(
		t,
		dek,
		unwrappedDEK,
	)
}

func TestUnwrapDEKWrongMasterKey(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	masterKey, err := GenerateDEK()
	require.NoError(t, err)

	wrongMasterKey, err := GenerateDEK()
	require.NoError(t, err)

	wrappedDEK, err := WrapDEK(
		dek,
		masterKey,
	)
	require.NoError(t, err)

	unwrappedDEK, err := UnwrapDEK(
		wrappedDEK,
		wrongMasterKey,
	)

	assert.Error(t, err)
	assert.Nil(t, unwrappedDEK)
}

func TestWrapDEKInvalidDEK(t *testing.T) {
	masterKey, err := GenerateDEK()
	require.NoError(t, err)

	wrappedDEK, err := WrapDEK(
		[]byte("invalid-dek"),
		masterKey,
	)

	assert.Error(t, err)
	assert.Empty(t, wrappedDEK)
}

func TestWrapDEKInvalidMasterKey(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	wrappedDEK, err := WrapDEK(
		dek,
		[]byte("invalid-master-key"),
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "master key")
	assert.Empty(t, wrappedDEK)
}

func TestUnwrapDEKMalformedCiphertext(t *testing.T) {
	masterKey, err := GenerateDEK()
	require.NoError(t, err)

	dek, err := UnwrapDEK(
		"malformed-ciphertext",
		masterKey,
	)

	assert.Error(t, err)
	assert.Nil(t, dek)
}

func TestUnwrapDEKInvalidMasterKey(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	masterKey, err := GenerateDEK()
	require.NoError(t, err)

	wrappedDEK, err := WrapDEK(
		dek,
		masterKey,
	)
	require.NoError(t, err)

	unwrappedDEK, err := UnwrapDEK(
		wrappedDEK,
		[]byte("invalid-master-key"),
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "master key")
	assert.Nil(t, unwrappedDEK)
}
