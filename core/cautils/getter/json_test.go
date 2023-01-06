package getter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJSONDecoder(t *testing.T) {
	t.Run("should decode json string", func(t *testing.T) {
		const input = `"xyz"`
		d := JSONDecoder(input)
		var receiver string
		require.NoError(t, d.Decode(&receiver))
		require.Equal(t, "xyz", receiver)
	})

	t.Run("should decode json number", func(t *testing.T) {
		const input = `123.01`
		d := JSONDecoder(input)
		var receiver float64
		require.NoError(t, d.Decode(&receiver))
		require.Equal(t, 123.01, receiver)
	})

	t.Run("requires json quotes", func(t *testing.T) {
		const input = `xyz`
		d := JSONDecoder(input)
		var receiver string
		require.Error(t, d.Decode(&receiver))
	})
}
