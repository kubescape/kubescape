package k8scveindex

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_LocalPathValid(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "feed.json")
	err := os.WriteFile(feedPath, []byte(testFeed), 0o600)
	require.NoError(t, err)

	ix, src, err := Load(context.Background(), Options{LocalPath: feedPath})
	require.NoError(t, err)
	assert.Equal(t, SourceLocal, src)
	assert.NotNil(t, ix)
	assert.Equal(t, Applicable, ix.Lookup("CVE-2024-3177", "kube-apiserver", "v1.29.1", "linux"))
}

func TestLoad_LocalPathDirectoryRejected(t *testing.T) {
	dir := t.TempDir()

	ix, src, err := Load(context.Background(), Options{LocalPath: dir})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFeedNotRegular), "expected ErrFeedNotRegular, got %v", err)
	assert.Nil(t, ix)
	assert.Empty(t, src)
}

func TestLoad_LocalPathNonRegularRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping device node test on windows")
	}

	ix, src, err := Load(context.Background(), Options{LocalPath: "/dev/null"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFeedNotRegular), "expected ErrFeedNotRegular for /dev/null, got %v", err)
	assert.Nil(t, ix)
	assert.Empty(t, src)
}

func TestLoad_LocalPathOversizedRejected(t *testing.T) {
	dir := t.TempDir()
	oversizedPath := filepath.Join(dir, "large_feed.json")

	f, err := os.Create(oversizedPath)
	require.NoError(t, err)
	// Create sparse oversized file
	_, err = f.WriteAt([]byte("}"), maxFeedSize+10)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	ix, src, err := Load(context.Background(), Options{LocalPath: oversizedPath})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFeedTooLarge), "expected ErrFeedTooLarge, got %v", err)
	assert.Nil(t, ix)
	assert.Empty(t, src)
}

func TestFetch_OversizedRejected(t *testing.T) {
	chunk := make([]byte, 64*1024)
	for i := range chunk {
		chunk[i] = ' '
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Stream more than maxFeedSize bytes
		total := 0
		target := int(maxFeedSize + 1024)
		for total < target {
			n, writeErr := w.Write(chunk)
			if writeErr != nil {
				return
			}
			total += n
		}
	}))
	defer srv.Close()

	ix, err := fetch(context.Background(), Options{
		URL:    srv.URL,
		Client: srv.Client(),
	})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFeedTooLarge), "expected ErrFeedTooLarge, got %v", err)
	assert.Nil(t, ix)
}

func TestLoad_NonExistentPath(t *testing.T) {
	ix, src, err := Load(context.Background(), Options{LocalPath: filepath.Join(t.TempDir(), "does-not-exist.json")})
	assert.Error(t, err)
	assert.Nil(t, ix)
	assert.Empty(t, src)
}

func TestLoad_PreservesSymlinkSemantics(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping symlink test on windows")
	}

	dir := t.TempDir()
	realDir := filepath.Join(dir, "target", "nested")
	require.NoError(t, os.MkdirAll(realDir, 0o700))

	feedPath := filepath.Join(realDir, "feed.json")
	require.NoError(t, os.WriteFile(feedPath, []byte(testFeed), 0o600))

	linkDir := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(realDir, linkDir))

	// link/../nested/feed.json resolves via the symlink destination (target/nested/feed.json)
	traversalPath := linkDir + "/../nested/feed.json"
	ix, src, err := Load(context.Background(), Options{LocalPath: traversalPath})
	require.NoError(t, err)
	assert.Equal(t, SourceLocal, src)
	assert.NotNil(t, ix)
}
