package getter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseHost(t *testing.T) {
	t.Parallel()

	t.Run("should recognize http scheme", func(t *testing.T) {
		t.Parallel()

		const input = "http://localhost:7555"
		scheme, host := parseHost(input)
		require.Equal(t, "http", scheme)
		require.Equal(t, "localhost:7555", host)
	})

	t.Run("should recognize https scheme", func(t *testing.T) {
		t.Parallel()

		const input = "https://localhost:7555"
		scheme, host := parseHost(input)
		require.Equal(t, "https", scheme)
		require.Equal(t, "localhost:7555", host)
	})

	t.Run("should adopt https scheme by default", func(t *testing.T) {
		t.Parallel()

		const input = "portal-dev.armo.cloud"
		scheme, host := parseHost(input)
		require.Equal(t, "https", scheme)
		require.Equal(t, "portal-dev.armo.cloud", host)
	})
}

func TestIsNativeFramework(t *testing.T) {
	t.Parallel()

	require.Truef(t, isNativeFramework("nSa"), "expected nsa to be native (case insensitive)")
	require.Falsef(t, isNativeFramework("foo"), "expected framework to be custom")
}
