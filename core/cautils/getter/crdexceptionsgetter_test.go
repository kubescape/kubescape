package getter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCRDExceptionsGetter_ImplementsInterface(t *testing.T) {
	// Verify that CRDExceptionsGetter satisfies IExceptionsGetter at compile time.
	// The package-level var check (var _ IExceptionsGetter = &CRDExceptionsGetter{})
	// enforces this, but this test serves as documentation and runtime verification.
	getter := NewCRDExceptionsGetter()
	require.NotNil(t, getter)

	// Verify through type assertion
	var ig IExceptionsGetter = getter
	assert.NotNil(t, ig)
}

func TestCRDExceptionsGetter_GetExceptions_ReturnsEmpty(t *testing.T) {
	getter := NewCRDExceptionsGetter()
	require.NotNil(t, getter)

	exceptions, err := getter.GetExceptions("test-cluster")
	require.NoError(t, err)
	assert.NotNil(t, exceptions)
	assert.Empty(t, exceptions, "expected empty exceptions until CRD implementation is completed")
}

func TestCRDExceptionsGetter_NilReceiver(t *testing.T) {
	var getter *CRDExceptionsGetter

	exceptions, err := getter.GetExceptions("test-cluster")
	require.Error(t, err)
	assert.Nil(t, exceptions)
	assert.Contains(t, err.Error(), "nil")
}

func TestCRDExceptionsGetter_MultipleCalls(t *testing.T) {
	getter := NewCRDExceptionsGetter()

	// Multiple calls should be idempotent
	for i := range 3 {
		exceptions, err := getter.GetExceptions("test-cluster")
		require.NoError(t, err, "call %d should not error", i)
		assert.Empty(t, exceptions, "call %d should return empty", i)
	}
}
