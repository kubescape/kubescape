package getter

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeAsUTF16 copies the fixture at src into a temporary UTF-16LE file with a
// byte order mark, the encoding of Windows PowerShell 5.1 redirection.
func writeAsUTF16(t *testing.T, src string) string {
	t.Helper()
	body, err := os.ReadFile(src)
	require.NoError(t, err)

	var encoded []byte
	for _, unit := range utf16.Encode([]rune("\ufeff" + string(body))) {
		encoded = binary.LittleEndian.AppendUint16(encoded, unit)
	}
	path := filepath.Join(t.TempDir(), "utf16.json")
	require.NoError(t, os.WriteFile(path, encoded, 0o600)) //nolint:gosec // G703: test-only; the path is generated under t.TempDir(), never external input
	return path
}

func TestLoadPolicy_UTF16(t *testing.T) {
	t.Run("exceptions", func(t *testing.T) {
		src := filepath.Join("testdata", "exceptions.json")

		want, err := NewLoadPolicy([]string{src}).GetExceptions(context.Background(), "")
		require.NoError(t, err)

		got, err := NewLoadPolicy([]string{writeAsUTF16(t, src)}).GetExceptions(context.Background(), "")
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("controls inputs", func(t *testing.T) {
		src := filepath.Join("testdata", "controls-inputs.json")

		want, err := NewLoadPolicy([]string{src}).GetControlsInputs(context.Background(), "")
		require.NoError(t, err)

		got, err := ReadControlsInputsFile(writeAsUTF16(t, src))
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})
}
