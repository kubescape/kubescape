package getter

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeWithAndWithoutBOM copies the fixture at src into two temporary files,
// one as is and one prefixed with a UTF-8 byte order mark, and returns their
// paths and the BOM-prefixed contents.
func writeWithAndWithoutBOM(t *testing.T, src string) (plain, withBOM string, bomContents []byte) {
	t.Helper()
	body, err := os.ReadFile(src)
	require.NoError(t, err)

	dir := t.TempDir()
	plain = filepath.Join(dir, "plain.json")
	withBOM = filepath.Join(dir, "bom.json")
	bomContents = append([]byte("\xef\xbb\xbf"), body...)
	require.NoError(t, os.WriteFile(plain, body, 0o600))          //nolint:gosec // G703: test-only; the path is generated under t.TempDir(), never external input
	require.NoError(t, os.WriteFile(withBOM, bomContents, 0o600)) //nolint:gosec // G703: test-only; the path is generated under t.TempDir(), never external input
	return plain, withBOM, bomContents
}

// Windows editors and PowerShell's Out-File -Encoding utf8 write a UTF-8 byte
// order mark. A local policy input saved that way must load like the same
// file without the mark.
func TestLoadPolicy_UTF8BOM(t *testing.T) {
	t.Run("exceptions", func(t *testing.T) {
		plain, withBOM, bomContents := writeWithAndWithoutBOM(t, filepath.Join("testdata", "exceptions.json"))

		want, err := NewLoadPolicy([]string{plain}).GetExceptions(context.Background(), "")
		require.NoError(t, err)
		require.Len(t, want, 231)
		assert.Equal(t, "exclude-minikube-kube-system-resources-1", want[0].Name)

		lp := NewLoadPolicy([]string{withBOM})
		got, err := lp.GetExceptions(context.Background(), "")
		require.NoError(t, err)
		assert.Equal(t, want, got)

		// The consumed-input digest still identifies the file's exact bytes.
		_, digest, ok := lp.ConsumedFileDigest()
		require.True(t, ok)
		assert.Equal(t, contentDigest(bomContents), digest)
	})

	t.Run("controls inputs", func(t *testing.T) {
		plain, withBOM, _ := writeWithAndWithoutBOM(t, filepath.Join("testdata", "controls-inputs.json"))

		want, err := NewLoadPolicy([]string{plain}).GetControlsInputs(context.Background(), "")
		require.NoError(t, err)
		require.Contains(t, want["listOfDangerousArtifacts"], "bin/bash")

		got, err := NewLoadPolicy([]string{withBOM}).GetControlsInputs(context.Background(), "")
		require.NoError(t, err)
		assert.Equal(t, want, got)

		got, err = ReadControlsInputsFile(withBOM)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("framework (--use-from)", func(t *testing.T) {
		plain, withBOM, _ := writeWithAndWithoutBOM(t, testFrameworkFile("MITRE"))

		want, err := NewLoadPolicy([]string{plain}).GetFramework("MITRE")
		require.NoError(t, err)
		require.NotEmpty(t, want.Controls)

		got, err := NewLoadPolicy([]string{withBOM}).GetFramework("MITRE")
		require.NoError(t, err, "a BOM must not be reported as a framework mismatch")
		assert.Equal(t, want, got)
	})

	t.Run("only one leading mark is removed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "controls-inputs.json")
		require.NoError(t, os.WriteFile(path, []byte("\xef\xbb\xbf\xef\xbb\xbf{}"), 0o600))

		_, err := ReadControlsInputsFile(path)
		require.Error(t, err)
	})
}
