package getter

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withBOM copies the testdata fixture name into a temporary directory, under
// the same base name, with a UTF-8 byte order mark in front of its contents,
// as Windows editors and Windows PowerShell's Out-File -Encoding utf8 save it.
func withBOM(t *testing.T, name string) (plain, bom string) {
	t.Helper()
	plain = filepath.Join(testutils.CurrentDir(), "testdata", name)
	contents, err := os.ReadFile(plain)
	require.NoError(t, err)

	bom = filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(bom, append(append([]byte{}, utf8BOM...), contents...), 0o600)) //nolint:gosec // G703: bom is in the test's own temp dir, under a testdata fixture name
	return plain, bom
}

// A byte order mark is not part of the JSON text. A local policy file that
// starts with one has to load like the same file without it, rather than fail
// to decode at its first byte.
func TestLoadPolicySkipsUTF8ByteOrderMark(t *testing.T) {
	t.Parallel()

	t.Run("GetFramework", func(t *testing.T) {
		t.Parallel()
		plain, bom := withBOM(t, "MITRE.json")
		want, err := NewLoadPolicy([]string{plain}).GetFramework("MITRE")
		require.NoError(t, err)
		got, err := NewLoadPolicy([]string{bom}).GetFramework("MITRE")
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("GetFrameworks and ListFrameworks", func(t *testing.T) {
		t.Parallel()
		plain, bom := withBOM(t, "NSA.json")
		want, err := NewLoadPolicy([]string{plain}).GetFrameworks()
		require.NoError(t, err)
		got, err := NewLoadPolicy([]string{bom}).GetFrameworks()
		require.NoError(t, err)
		assert.Equal(t, want, got)

		names, err := NewLoadPolicy([]string{bom}).ListFrameworks()
		require.NoError(t, err)
		assert.Equal(t, []string{"NSA"}, names)
	})

	t.Run("GetControl and ListControls from a control file", func(t *testing.T) {
		t.Parallel()
		plain, bom := withBOM(t, "C-0001.json")
		want, err := NewLoadPolicy([]string{plain}).GetControl("C-0001")
		require.NoError(t, err)
		got, err := NewLoadPolicy([]string{bom}).GetControl("C-0001")
		require.NoError(t, err)
		assert.Equal(t, want, got)

		wantList, err := NewLoadPolicy([]string{plain}).ListControls()
		require.NoError(t, err)
		gotList, err := NewLoadPolicy([]string{bom}).ListControls()
		require.NoError(t, err)
		assert.Equal(t, wantList, gotList)
	})

	t.Run("GetControl from a framework file", func(t *testing.T) {
		t.Parallel()
		plain, bom := withBOM(t, "MITRE.json")
		want, err := NewLoadPolicy([]string{plain}).GetControl("C-0053")
		require.NoError(t, err)
		got, err := NewLoadPolicy([]string{bom}).GetControl("C-0053")
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("GetExceptions", func(t *testing.T) {
		t.Parallel()
		plain, bom := withBOM(t, "exceptions.json")
		want, err := NewLoadPolicy([]string{plain}).GetExceptions(context.Background(), "")
		require.NoError(t, err)
		require.NotEmpty(t, want)
		got, err := NewLoadPolicy([]string{bom}).GetExceptions(context.Background(), "")
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("GetControlsInputs and ReadControlsInputsFile", func(t *testing.T) {
		t.Parallel()
		plain, bom := withBOM(t, "controls-inputs.json")
		want, err := NewLoadPolicy([]string{plain}).GetControlsInputs(context.Background(), "")
		require.NoError(t, err)
		require.NotEmpty(t, want)
		got, err := NewLoadPolicy([]string{bom}).GetControlsInputs(context.Background(), "")
		require.NoError(t, err)
		assert.Equal(t, want, got)

		read, err := ReadControlsInputsFile(bom)
		require.NoError(t, err)
		assert.Equal(t, want, read)
	})

	t.Run("GetAttackTracks", func(t *testing.T) {
		t.Parallel()
		plain, bom := withBOM(t, "attack-tracks.json")
		want, err := NewLoadPolicy([]string{plain}).GetAttackTracks()
		require.NoError(t, err)
		require.NotEmpty(t, want)
		got, err := NewLoadPolicy([]string{bom}).GetAttackTracks()
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})
}

// Skipping the byte order mark changes only what is decoded. The digest of the
// consumed file is still that of the bytes on disk, so it keeps matching the
// identity CacheSource derives from the file itself.
func TestLoadPolicyByteOrderMarkKeepsFileDigest(t *testing.T) {
	t.Parallel()
	_, bom := withBOM(t, "exceptions.json")

	p := NewLoadPolicy([]string{bom})
	_, err := p.GetExceptions(context.Background(), "")
	require.NoError(t, err)

	contents, err := os.ReadFile(bom)
	require.NoError(t, err)
	path, digest, ok := p.ConsumedFileDigest()
	require.True(t, ok)
	assert.Equal(t, bom, path)
	assert.Equal(t, fmt.Sprintf("sha256:%x", sha256.Sum256(contents)), digest)

	source, loaded := p.LoadedCacheSource()
	require.True(t, loaded)
	assert.Equal(t, p.CacheSource(), source)
}
