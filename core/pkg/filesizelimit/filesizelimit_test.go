package filesizelimit

import (
	"fmt"
	"math"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetMaxFileSize_Defaults(t *testing.T) {
	t.Run("env unset returns 32 MiB", func(t *testing.T) {
		require.NoError(t, os.Unsetenv(MaxFileSizeEnvVar))
		assert.Equal(t, int64(32<<20), GetMaxFileSize())
		assert.Equal(t, int64(32*1024*1024), DefaultMaxFileSize)
	})

	t.Run("empty env returns default", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "")
		assert.Equal(t, DefaultMaxFileSize, GetMaxFileSize())
	})

	t.Run("whitespace only returns default", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "   \t\n  ")
		assert.Equal(t, DefaultMaxFileSize, GetMaxFileSize())
	})
}

func TestGetMaxFileSize_ValidOverrides(t *testing.T) {
	t.Run("valid positive override", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "67108864")
		assert.Equal(t, int64(67108864), GetMaxFileSize())
	})

	t.Run("small positive override", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "1024")
		assert.Equal(t, int64(1024), GetMaxFileSize())
	})

	t.Run("whitespace trimmed valid override", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "  52428800  ")
		assert.Equal(t, int64(52428800), GetMaxFileSize())
	})
}

func TestGetMaxFileSize_InvalidValuesFallbackToDefault(t *testing.T) {
	testCases := []struct {
		name  string
		value string
	}{
		{"alphanumeric", "invalid"},
		{"unit suffix", "32MB"},
		{"hexadecimal", "0x20"},
		{"float", "32.5"},
		{"zero", "0"},
		{"negative one", "-1"},
		{"negative number", "-5000"},
		{"overflow max int64", fmt.Sprintf("%d", uint64(math.MaxInt64)+1)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(MaxFileSizeEnvVar, tc.value)
			assert.Equal(t, DefaultMaxFileSize, GetMaxFileSize(), "value %q must fall back to default", tc.value)
		})
	}
}

func TestGetMaxFileSize_MaxInt64RejectedForOverflowProtection(t *testing.T) {
	// math.MaxInt64 must fall back to default so downstream limit+1 calculations
	// do not overflow to math.MinInt64.
	t.Setenv(MaxFileSizeEnvVar, fmt.Sprintf("%d", math.MaxInt64))
	assert.Equal(t, DefaultMaxFileSize, GetMaxFileSize(), "math.MaxInt64 must fall back to default")
}
