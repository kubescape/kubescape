package getter

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	t.Parallel()

	dir, err := os.MkdirTemp(".", "test")
	require.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(dir)
	}()

	policy := map[string]interface{}{
		"key":    "value",
		"number": 1.00,
	}

	t.Run("should save data as JSON (target folder exists)", func(t *testing.T) {
		target := filepath.Join(dir, "target.json")
		require.NoError(t, SaveInFile(policy, target))

		buf, err := os.ReadFile(target)
		require.NoError(t, err)
		var retrieved interface{}
		require.NoError(t, json.Unmarshal(buf, &retrieved))

		require.EqualValues(t, policy, retrieved)
	})

	t.Run("should save data as JSON (new target folder)", func(t *testing.T) {
		target := filepath.Join(dir, "subdir", "target.json")
		require.NoError(t, SaveInFile(policy, target))

		buf, err := os.ReadFile(target)
		require.NoError(t, err)
		var retrieved interface{}
		require.NoError(t, json.Unmarshal(buf, &retrieved))

		require.EqualValues(t, policy, retrieved)
	})

	t.Run("should error", func(t *testing.T) {
		badPolicy := map[string]interface{}{
			"key":    "value",
			"number": 1.00,
			"err":    func() {},
		}
		target := filepath.Join(dir, "error.json")
		require.Error(t, SaveInFile(badPolicy, target))
	})
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
