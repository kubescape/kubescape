package getter

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	beClient "github.com/kubescape/backend/pkg/client/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetDefaultPath(t *testing.T) {
	t.Parallel()

	const name = "mine"

	pth := GetDefaultPath(name)
	require.Equal(t, name, filepath.Base(pth))
	require.Equal(t, ".kubescape", filepath.Base(filepath.Dir(pth)))
}

func TestPolicyCacheFilename(t *testing.T) {
	t.Parallel()

	t.Run("should lowercase an uppercase identifier", func(t *testing.T) {
		got, err := PolicyCacheFilename("NSA")
		require.NoError(t, err)
		require.Equal(t, "nsa.json", got)
	})

	t.Run("should leave an already-lowercase identifier unchanged", func(t *testing.T) {
		got, err := PolicyCacheFilename("nsa")
		require.NoError(t, err)
		require.Equal(t, "nsa.json", got)
	})

	t.Run("should trim whitespace and lowercase a mixed-case identifier", func(t *testing.T) {
		got, err := PolicyCacheFilename("  Nsa  ")
		require.NoError(t, err)
		require.Equal(t, "nsa.json", got)
	})

	t.Run("should lowercase MITRE to mitre.json", func(t *testing.T) {
		got, err := PolicyCacheFilename("MITRE")
		require.NoError(t, err)
		require.Equal(t, "mitre.json", got)
	})

	t.Run("should lowercase a mixed-case control ID to a single filename", func(t *testing.T) {
		upper, err := PolicyCacheFilename("C-0001")
		require.NoError(t, err)
		require.Equal(t, "c-0001.json", upper)

		lower, err := PolicyCacheFilename("c-0001")
		require.NoError(t, err)
		require.Equal(t, "c-0001.json", lower)

		require.Equal(t, upper, lower)
	})

	t.Run("should error on an empty identifier", func(t *testing.T) {
		got, err := PolicyCacheFilename("")
		require.Error(t, err)
		require.Empty(t, got)
	})

	t.Run("should error on a whitespace-only identifier", func(t *testing.T) {
		got, err := PolicyCacheFilename("   ")
		require.Error(t, err)
		require.Empty(t, got)
	})

	t.Run("should error on a dot identifier", func(t *testing.T) {
		got, err := PolicyCacheFilename(".")
		require.Error(t, err)
		require.Empty(t, got)
	})

	t.Run("should error on a double-dot identifier", func(t *testing.T) {
		got, err := PolicyCacheFilename("..")
		require.Error(t, err)
		require.Empty(t, got)
	})

	t.Run("should error on an identifier containing a forward slash", func(t *testing.T) {
		got, err := PolicyCacheFilename("../etc/passwd")
		require.Error(t, err)
		require.Empty(t, got)
	})

	t.Run("should error on an identifier containing a backslash", func(t *testing.T) {
		got, err := PolicyCacheFilename(`nsa\evil`)
		require.Error(t, err)
		require.Empty(t, got)
	})

	t.Run("should error on an identifier containing a pipe", func(t *testing.T) {
		got, err := PolicyCacheFilename("C-0001|control name|frameworks")
		require.Error(t, err)
		require.Empty(t, got)
	})
}

func TestPolicyCachePath(t *testing.T) {
	t.Parallel()

	t.Run("should return canonical path for an uppercase identifier", func(t *testing.T) {
		pth, err := PolicyCachePath("NSA")
		require.NoError(t, err)
		require.Equal(t, "nsa.json", filepath.Base(pth))
		require.Equal(t, ".kubescape", filepath.Base(filepath.Dir(pth)))
	})

	t.Run("should map mixed-case and lowercase identifiers to the same path", func(t *testing.T) {
		upper, err := PolicyCachePath("NSA")
		require.NoError(t, err)
		lower, err := PolicyCachePath("nsa")
		require.NoError(t, err)
		spaced, err := PolicyCachePath("  Nsa  ")
		require.NoError(t, err)
		require.Equal(t, upper, lower)
		require.Equal(t, upper, spaced)
	})

	t.Run("should lowercase MITRE to mitre.json under the local store", func(t *testing.T) {
		pth, err := PolicyCachePath("MITRE")
		require.NoError(t, err)
		require.Equal(t, "mitre.json", filepath.Base(pth))
		require.Equal(t, ".kubescape", filepath.Base(filepath.Dir(pth)))
	})

	t.Run("should map mixed-case and lowercase control IDs to the same path", func(t *testing.T) {
		upper, err := PolicyCachePath("C-0001")
		require.NoError(t, err)
		require.Equal(t, "c-0001.json", filepath.Base(upper))

		lower, err := PolicyCachePath("c-0001")
		require.NoError(t, err)

		require.Equal(t, upper, lower)
	})

	t.Run("should error on an empty identifier", func(t *testing.T) {
		pth, err := PolicyCachePath("")
		require.Error(t, err)
		require.Empty(t, pth)
	})

	t.Run("should error on a whitespace-only identifier", func(t *testing.T) {
		pth, err := PolicyCachePath("   ")
		require.Error(t, err)
		require.Empty(t, pth)
	})

	t.Run("should error on a dot identifier", func(t *testing.T) {
		pth, err := PolicyCachePath(".")
		require.Error(t, err)
		require.Empty(t, pth)
	})

	t.Run("should error on a double-dot identifier", func(t *testing.T) {
		pth, err := PolicyCachePath("..")
		require.Error(t, err)
		require.Empty(t, pth)
	})

	t.Run("should error on an identifier containing a forward slash", func(t *testing.T) {
		pth, err := PolicyCachePath("../etc/passwd")
		require.Error(t, err)
		require.Empty(t, pth)
	})

	t.Run("should error on an identifier containing a backslash", func(t *testing.T) {
		pth, err := PolicyCachePath(`nsa\evil`)
		require.Error(t, err)
		require.Empty(t, pth)
	})
}

func TestSaveInFile(t *testing.T) {
	dir := t.TempDir()

	policy := map[string]any{
		"key":    "value",
		"number": 1.00,
	}

	t.Run("should save data as JSON (target folder exists)", func(t *testing.T) {
		target := filepath.Join(dir, "target.json")
		require.NoError(t, SaveInFile(policy, target))

		buf, err := os.ReadFile(target)
		require.NoError(t, err)
		var retrieved any
		require.NoError(t, json.Unmarshal(buf, &retrieved))

		require.EqualValues(t, policy, retrieved)

		info, err := os.Stat(target)
		require.NoError(t, err)
		require.Equal(t, savedJSONFileMode, info.Mode().Perm())
	})

	t.Run("should save data as JSON (new target folder)", func(t *testing.T) {
		target := filepath.Join(dir, "subdir", "target.json")
		require.NoError(t, SaveInFile(policy, target))

		buf, err := os.ReadFile(target)
		require.NoError(t, err)
		var retrieved any
		require.NoError(t, json.Unmarshal(buf, &retrieved))

		require.EqualValues(t, policy, retrieved)
	})

	t.Run("should error", func(t *testing.T) {
		badPolicy := map[string]any{
			"key":    "value",
			"number": 1.00,
			"err":    func() {},
		}
		target := filepath.Join(dir, "error.json")
		require.Error(t, SaveInFile(badPolicy, target))
		_, err := os.Stat(target)
		require.ErrorIs(t, err, os.ErrNotExist)
	})
}

func TestSaveInFilePreservesExistingFileWhenCommitFails(t *testing.T) {
	target := filepath.Join(t.TempDir(), "framework.json")
	original := []byte(`{"name":"known-good"}`)
	require.NoError(t, os.WriteFile(target, original, 0o600))

	originalRename := renameSavedFile
	renameSavedFile = func(_, _ string) error {
		return errors.New("simulated rename failure")
	}
	t.Cleanup(func() { renameSavedFile = originalRename })

	err := SaveInFile(map[string]string{"name": "replacement"}, target)
	require.ErrorContains(t, err, "simulated rename failure")

	contents, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, original, contents, "a failed commit must leave the last valid cache entry intact")

	temps, err := filepath.Glob(filepath.Join(filepath.Dir(target), ".kubescape-json-*.tmp"))
	require.NoError(t, err)
	require.Empty(t, temps, "failed writes must not leak temporary files")
}

func TestSaveInFilePreservesExistingPermissions(t *testing.T) {
	target := filepath.Join(t.TempDir(), "controls.json")
	require.NoError(t, os.WriteFile(target, []byte(`{"old":true}`), 0o600))

	require.NoError(t, SaveInFile(map[string]bool{"new": true}, target))

	info, err := os.Stat(target)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestSaveInFileRejectsNonRegularTargets(t *testing.T) {
	t.Run("empty target", func(t *testing.T) {
		require.ErrorContains(t, SaveInFile(map[string]string{"key": "value"}, ""), "target file is empty")
	})

	t.Run("directory", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "target.json")
		require.NoError(t, os.Mkdir(target, 0o755))
		require.ErrorContains(t, SaveInFile(map[string]string{"key": "value"}, target), "not a regular file")
	})

	t.Run("symbolic link", func(t *testing.T) {
		dir := t.TempDir()
		destination := filepath.Join(dir, "destination.json")
		link := filepath.Join(dir, "target.json")
		require.NoError(t, os.WriteFile(destination, []byte(`{"safe":true}`), 0o600))
		if err := os.Symlink(destination, link); err != nil {
			t.Skipf("symbolic links are unavailable: %v", err)
		}

		require.ErrorContains(t, SaveInFile(map[string]bool{"safe": false}, link), "symbolic link")
		contents, err := os.ReadFile(destination)
		require.NoError(t, err)
		require.JSONEq(t, `{"safe":true}`, string(contents))
	})
}

func TestSaveInFileConcurrentWritersAlwaysPublishCompleteJSON(t *testing.T) {
	target := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, SaveInFile(map[string]any{"writer": -1, "payload": strings.Repeat("initial", 1000)}, target))

	const writers = 12
	start := make(chan struct{})
	errorsByWriter := make(chan error, writers)
	var writersWG sync.WaitGroup
	for writer := 0; writer < writers; writer++ {
		writersWG.Add(1)
		go func(writer int) {
			defer writersWG.Done()
			<-start
			errorsByWriter <- SaveInFile(map[string]any{
				"writer":  writer,
				"payload": strings.Repeat(strconv.Itoa(writer), 20000),
			}, target)
		}(writer)
	}

	close(start)
	readDone := make(chan struct{})
	go func() {
		writersWG.Wait()
		close(readDone)
	}()

	for {
		contents, err := os.ReadFile(target)
		require.NoError(t, err)
		var published map[string]any
		require.NoError(t, json.Unmarshal(contents, &published), "readers must never observe a partially written cache entry")

		select {
		case <-readDone:
			for writer := 0; writer < writers; writer++ {
				require.NoError(t, <-errorsByWriter)
			}
			return
		default:
		}
	}
}

func TestHttpMethods(t *testing.T) {
	client := http.DefaultClient
	hdrs := map[string]string{"key": "value"}

	srv := beClient.MockAPIServer(t)
	t.Cleanup(srv.Close)

	t.Run("HttpGetter should GET", func(t *testing.T) {
		resp, err := HttpGetter(client, srv.URL(pathTestGet), hdrs)
		require.NoError(t, err)
		require.EqualValues(t, "body-get", resp)
	})

	t.Run("HttpDelete should DELETE", func(t *testing.T) {
		resp, err := HttpDelete(client, srv.URL(pathTestDelete), hdrs)
		require.NoError(t, err)
		require.EqualValues(t, "body-delete", resp)
	})
}

// Returns an empty string and nil error when given a nil response or nil response body.
func TestHttpRespToString_NilResponse(t *testing.T) {
	resp := &http.Response{}
	result, err := httpRespToString(resp)
	assert.Equal(t, "", result)
	assert.Nil(t, err)
}

func TestHttpRespToString_ValidResponse(t *testing.T) {
	resp := &http.Response{
		Body:       io.NopCloser(strings.NewReader("test response")),
		Status:     "200 OK",
		StatusCode: 200,
	}
	result, err := httpRespToString(resp)
	assert.Equal(t, "test response", result)
	assert.Nil(t, err)
}

// Returns an error with status and reason when unable to read response body.
func TestHttpRespToString_ReadError(t *testing.T) {
	resp := &http.Response{
		Body: io.NopCloser(strings.NewReader("test response")),
	}
	resp.Body.Close()
	result, err := httpRespToString(resp)
	assert.EqualError(t, err, "http-error: '', reason: 'test response'")
	assert.Equal(t, "test response", result)
}

// Returns an error with status and reason when unable to read response body.
func TestHttpRespToString_ErrorCodeLessThan200(t *testing.T) {
	resp := &http.Response{
		Body:       io.NopCloser(strings.NewReader("test response")),
		StatusCode: 100,
	}
	resp.Body.Close()
	result, err := httpRespToString(resp)
	assert.EqualError(t, err, "http-error: '', reason: 'test response'")
	assert.Equal(t, "test response", result)
}

func TestSetHeaders(t *testing.T) {
	t.Run("sets every header on the request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)

		setHeaders(req, map[string]string{"Authorization": "token abc", "X-Custom": "value"})

		assert.Equal(t, "token abc", req.Header.Get("Authorization"))
		assert.Equal(t, "value", req.Header.Get("X-Custom"))
	})

	// Regression: setHeaders used to gate the range loop behind
	// `if len(headers) >= 0`, a condition that is always true (len() is
	// never negative) - a nil map must still be handled without panicking,
	// which ranging over nil already does safely in Go.
	t.Run("nil headers map does not panic and sets nothing", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)

		assert.NotPanics(t, func() { setHeaders(req, nil) })
		assert.Empty(t, req.Header)
	})
}
