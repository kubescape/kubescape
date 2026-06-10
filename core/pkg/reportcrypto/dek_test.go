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