package getter

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/kubescape/backend/pkg/client/v1"
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

func TestKSCloudAPIAdapterCacheSource(t *testing.T) {
	adapter := func(t *testing.T, apiURL, accountID, accessKey string) *KSCloudAPIAdapter {
		t.Helper()
		api, err := v1.NewKSCloudAPI(apiURL, "", accountID, accessKey)
		require.NoError(t, err)
		return &KSCloudAPIAdapter{KSCloudAPI: api}
	}
	accountA := CacheSourceOf(adapter(t, "https://api.example.com", "account-a", "secret-key-a"))

	assert.Equal(t, accountA, CacheSourceOf(adapter(t, "https://api.example.com", "account-a", "another-secret-key")))
	assert.NotEqual(t, accountA, CacheSourceOf(adapter(t, "https://api.example.com", "account-b", "secret-key-a")))
	assert.NotEqual(t, accountA, CacheSourceOf(adapter(t, "https://other.example.com", "account-a", "secret-key-a")))
	assert.NotContains(t, accountA, "secret-key-a")

	var nilAdapter *KSCloudAPIAdapter
	assert.Equal(t, "<nil>", CacheSourceOf(nilAdapter))
	assert.Equal(t, "<nil>", CacheSourceOf(&KSCloudAPIAdapter{}))
}

func TestLoadedCacheSourceOf(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exceptions.json")
	write := func(content string) {
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	sourceOf := func(content string) string {
		other := filepath.Join(dir, "other.json")
		require.NoError(t, os.WriteFile(other, []byte(content), 0o600))
		return CacheSourceOf(NewLoadPolicy([]string{other}))
	}
	const contentA, contentB = `[{"name":"a"}]`, `[{"name":"b"}]`

	t.Run("nothing loaded yet", func(t *testing.T) {
		write(contentA)
		_, ok := LoadedCacheSourceOf(NewLoadPolicy([]string{path}))
		assert.False(t, ok)
	})

	t.Run("the bytes that were loaded", func(t *testing.T) {
		// The file holds A when the source is computed, B when it is loaded and
		// A again afterwards: what was loaded is B.
		write(contentA)
		lp := NewLoadPolicy([]string{path})
		require.Equal(t, sourceOf(contentA), lp.CacheSource())
		write(contentB)
		exceptions, err := lp.GetExceptions(context.Background(), "")
		require.NoError(t, err)
		write(contentA)

		require.Len(t, exceptions, 1)
		assert.Equal(t, "b", exceptions[0].Name)
		loaded, ok := LoadedCacheSourceOf(lp)
		require.True(t, ok)
		assert.Equal(t, sourceOf(contentB), loaded)
		assert.NotEqual(t, lp.CacheSource(), loaded)
		_, digest, ok := lp.ConsumedFileDigest()
		require.True(t, ok)
		assert.Equal(t, "file:"+digest, loaded)
	})

	t.Run("merged getter", func(t *testing.T) {
		write(contentB)
		primary := NewLoadPolicy([]string{path})
		merged := NewMergedExceptionsGetter(primary, &exceptionsGetterStub{})
		_, ok := LoadedCacheSourceOf(merged)
		assert.False(t, ok, "nothing loaded yet")

		_, err := merged.GetExceptions(context.Background(), "")
		require.NoError(t, err)
		loaded, ok := LoadedCacheSourceOf(merged)
		require.True(t, ok)
		assert.Equal(t, merged.CacheSource(), loaded)
	})

	t.Run("getters without a load identity", func(t *testing.T) {
		release := NewDownloadReleasedPolicyWithVersion("v2.0.300")
		loaded, ok := LoadedCacheSourceOf(release)
		require.True(t, ok)
		assert.Equal(t, CacheSourceOf(release), loaded)
	})
}

func TestSourceFile(t *testing.T) {
	lp := NewLoadPolicy([]string{"/tmp/exceptions.json"})
	file, ok := lp.SourceFile()
	assert.True(t, ok)
	assert.Equal(t, "/tmp/exceptions.json", file)

	file, ok = NewMergedExceptionsGetter(lp, &exceptionsGetterStub{}).SourceFile()
	assert.True(t, ok)
	assert.Equal(t, "/tmp/exceptions.json", file)

	_, ok = NewLoadPolicy(nil).SourceFile()
	assert.False(t, ok)
	_, ok = NewMergedExceptionsGetter(&exceptionsGetterStub{}, nil).SourceFile()
	assert.False(t, ok)
	var nilMerged *MergedExceptionsGetter
	_, ok = nilMerged.SourceFile()
	assert.False(t, ok)
}
