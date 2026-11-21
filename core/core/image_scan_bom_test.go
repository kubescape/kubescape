package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An image exceptions file saved with a UTF-8 byte order mark, as Windows
// editors and PowerShell's Out-File -Encoding utf8 write it, must load like
// the same file without the mark.
func TestGetImageExceptionsFromFile_UTF8BOM(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("testdata", "exceptions.json"))
	require.NoError(t, err)

	want, err := GetImageExceptionsFromFile(filepath.Join("testdata", "exceptions.json"))
	require.NoError(t, err)
	require.NotEmpty(t, want)
	assert.Equal(t, "medium-severity-vulnerabilites-exceptions", want[0].Metadata.Name)
	assert.Equal(t, []string{"medium"}, want[0].Severities)

	path := filepath.Join(t.TempDir(), "exceptions.json")
	require.NoError(t, os.WriteFile(path, append([]byte("\xef\xbb\xbf"), body...), 0o600))

	got, err := GetImageExceptionsFromFile(path)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}
