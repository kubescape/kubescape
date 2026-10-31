package getter

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheSourceOf(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(name, content string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}
	file := func(path string) string { return CacheSourceOf(NewLoadPolicy([]string{path})) }

	a := writeFile("a.json", `[{"name":"a"}]`)
	sourceA := file(a)

	t.Run("same contents at different paths", func(t *testing.T) {
		// e.g. identical REST request bodies saved to different temporary files
		assert.Equal(t, sourceA, file(writeFile("copy-of-a.json", `[{"name":"a"}]`)))
		assert.Equal(t, sourceA, file(filepath.Join(dir, ".", "a.json")))
	})
	t.Run("different contents at different paths", func(t *testing.T) {
		assert.NotEqual(t, sourceA, file(writeFile("b.json", `[{"name":"b"}]`)))
	})
	t.Run("changed contents at the same path", func(t *testing.T) {
		path := writeFile("changing.json", `[{"name":"before"}]`)
		before := file(path)
		writeFile("changing.json", `[{"name":"after"}]`)
		assert.NotEqual(t, before, file(path))
	})
	t.Run("matches the consumed file digest", func(t *testing.T) {
		lp := NewLoadPolicy([]string{a})
		_, err := lp.GetExceptions(context.Background(), "")
		require.NoError(t, err)
		_, digest, ok := lp.ConsumedFileDigest()
		require.True(t, ok)
		assert.Equal(t, "file:"+digest, lp.CacheSource())
	})
	t.Run("unreadable files", func(t *testing.T) {
		missing := file(filepath.Join(dir, "missing.json"))
		assert.NotEqual(t, sourceA, missing)
		assert.NotEqual(t, missing, file(filepath.Join(dir, "other-missing.json")))
		assert.NotEqual(t, missing, CacheSourceOf(NewLoadPolicy(nil)))
	})
	t.Run("releases", func(t *testing.T) {
		latest := CacheSourceOf(NewDownloadReleasedPolicy())
		pinned := CacheSourceOf(NewDownloadReleasedPolicyWithVersion("v2.0.300"))

		assert.Equal(t, latest, CacheSourceOf(NewDownloadReleasedPolicyWithVersion("")))
		assert.Equal(t, pinned, CacheSourceOf(NewDownloadReleasedPolicyWithVersion("v2.0.300")))
		assert.NotEqual(t, pinned, CacheSourceOf(NewDownloadReleasedPolicyWithVersion("v2.0.301")))
		assert.NotEqual(t, latest, pinned)
	})
	t.Run("different getter types", func(t *testing.T) {
		assert.NotEqual(t, sourceA, CacheSourceOf(&exceptionsGetterStub{}))
		assert.NotEqual(t, CacheSourceOf(&exceptionsGetterStub{}), CacheSourceOf(&CRDExceptionsGetter{}))
	})
	t.Run("merged getters", func(t *testing.T) {
		merged := func(primary, secondary IExceptionsGetter) string {
			return CacheSourceOf(NewMergedExceptionsGetter(primary, secondary))
		}
		withCRDs := merged(NewLoadPolicy([]string{a}), &exceptionsGetterStub{})
		withoutCRDs := merged(NewLoadPolicy([]string{a}), nil)

		assert.Equal(t, withCRDs, merged(NewLoadPolicy([]string{a}), &exceptionsGetterStub{}))
		assert.NotEqual(t, withCRDs, withoutCRDs)
		assert.NotEqual(t, withCRDs, merged(NewLoadPolicy([]string{writeFile("c.json", `[]`)}), &exceptionsGetterStub{}))
		assert.NotEqual(t, withCRDs, merged(&exceptionsGetterStub{}, &exceptionsGetterStub{}))
		// The file itself, read without the merge, is a different source.
		assert.NotEqual(t, sourceA, withoutCRDs)
		assert.NotEqual(t, file(writeFile("a.json+clusterExceptions=false", `[{"name":"a"}]`)), withoutCRDs)
	})
	t.Run("nil getters", func(t *testing.T) {
		assert.Equal(t, "<nil>", CacheSourceOf(nil))
		var nilMerged *MergedExceptionsGetter
		assert.Equal(t, "<nil>", nilMerged.CacheSource())
		assert.Equal(t, "<nil>", CacheSourceOf(nilMerged))
		var nilRelease *DownloadReleasedPolicy
		assert.Equal(t, "<nil>", CacheSourceOf(nilRelease))
		assert.NotEqual(t, "<nil>", CacheSourceOf(NewMergedExceptionsGetter(nil, nil)))
	})
}
