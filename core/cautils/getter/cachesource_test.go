package getter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCacheSourceOf(t *testing.T) {
	fileA := CacheSourceOf(NewLoadPolicy([]string{"/tmp/a.json"}))

	t.Run("same file", func(t *testing.T) {
		assert.Equal(t, fileA, CacheSourceOf(NewLoadPolicy([]string{"/tmp/a.json"})))
		assert.Equal(t, fileA, CacheSourceOf(NewLoadPolicy([]string{"/tmp/./a.json"})))
	})
	t.Run("different files", func(t *testing.T) {
		assert.NotEqual(t, fileA, CacheSourceOf(NewLoadPolicy([]string{"/tmp/b.json"})))
	})
	t.Run("no file", func(t *testing.T) {
		assert.NotEqual(t, fileA, CacheSourceOf(NewLoadPolicy(nil)))
	})
	t.Run("different getter types", func(t *testing.T) {
		assert.NotEqual(t, fileA, CacheSourceOf(&exceptionsGetterStub{}))
		assert.NotEqual(t, CacheSourceOf(&exceptionsGetterStub{}), CacheSourceOf(&CRDExceptionsGetter{}))
	})
	t.Run("merged getters", func(t *testing.T) {
		withCRDs := CacheSourceOf(NewMergedExceptionsGetter(NewLoadPolicy([]string{"/tmp/a.json"}), &exceptionsGetterStub{}))
		withoutCRDs := CacheSourceOf(NewMergedExceptionsGetter(NewLoadPolicy([]string{"/tmp/a.json"}), nil))

		assert.Equal(t, withCRDs, CacheSourceOf(NewMergedExceptionsGetter(NewLoadPolicy([]string{"/tmp/a.json"}), &exceptionsGetterStub{})))
		assert.NotEqual(t, withCRDs, withoutCRDs)
		assert.NotEqual(t, withCRDs, CacheSourceOf(NewMergedExceptionsGetter(NewLoadPolicy([]string{"/tmp/b.json"}), &exceptionsGetterStub{})))
		assert.NotEqual(t, withCRDs, CacheSourceOf(NewMergedExceptionsGetter(&exceptionsGetterStub{}, &exceptionsGetterStub{})))
		assert.NotEqual(t, fileA, withoutCRDs)
	})
}
