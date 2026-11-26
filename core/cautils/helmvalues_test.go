package cautils

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHelmValueOptions_MergeValues_BoundsAndNonRegularInputs(t *testing.T) {
	t.Run("oversized -f values file rejected", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "128")
		valFile := filepath.Join(t.TempDir(), "values.yaml")
		require.NoError(t, os.WriteFile(valFile, []byte("note: "+strings.Repeat("a", 256)+"\n"), 0o600))

		_, err := (HelmValueOptions{ValueFiles: []string{valFile}}).MergeValues()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHelmTemplateTooLarge)
	})

	t.Run("oversized --set-file rejected", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "128")
		dataFile := filepath.Join(t.TempDir(), "config.txt")
		require.NoError(t, os.WriteFile(dataFile, []byte(strings.Repeat("b", 256)), 0o600))

		_, err := (HelmValueOptions{FileValues: []string{"cfg=" + dataFile}}).MergeValues()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHelmTemplateTooLarge)
	})

	t.Run("oversized stdin values rejected", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "128")
		stdin := strings.NewReader("note: " + strings.Repeat("c", 256) + "\n")

		_, err := mergeBoundedHelmValues(HelmValueOptions{ValueFiles: []string{"-"}}, stdin)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHelmTemplateTooLarge)
	})

	t.Run("oversized HTTP values URL rejected", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "128")
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("note: " + strings.Repeat("d", 512) + "\n"))
		}))
		defer ts.Close()

		_, err := (HelmValueOptions{ValueFiles: []string{ts.URL}}).MergeValues()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHelmTemplateTooLarge)
	})

	t.Run("HTTP client timeout prevents hung values server", func(t *testing.T) {
		done := make(chan struct{})
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-done:
			}
		}))
		defer func() {
			close(done)
			ts.Close()
		}()

		client := &http.Client{Timeout: 50 * time.Millisecond}
		_, err := mergeBoundedHelmValuesWithClient(HelmValueOptions{ValueFiles: []string{ts.URL}}, nil, client)
		require.Error(t, err)
	})

	t.Run("non-regular values path rejected", func(t *testing.T) {
		if _, err := os.Stat("/dev/null"); err != nil {
			t.Skip("/dev/null unavailable")
		}
		_, err := (HelmValueOptions{ValueFiles: []string{"/dev/null"}}).MergeValues()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHelmTemplateNotRegular)
	})

	t.Run("valid -f, --set-file, --set, and HTTP URL merge in precedence order", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "4096")
		dir := t.TempDir()
		f1 := filepath.Join(dir, "base.yaml")
		f2 := filepath.Join(dir, "extra.txt")
		require.NoError(t, os.WriteFile(f1, []byte("replicas: 2\napp:\n  env: staging\n"), 0o600))
		require.NoError(t, os.WriteFile(f2, []byte("secret-value"), 0o600))

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("app:\n  env: prod\n"))
		}))
		defer ts.Close()

		merged, err := (HelmValueOptions{
			ValueFiles:   []string{f1, ts.URL},
			Values:       []string{"replicas=3"},
			StringValues: []string{"app.tag=v1"},
			FileValues:   []string{"app.config=" + f2},
		}).MergeValues()
		require.NoError(t, err)
		assert.EqualValues(t, 3, merged["replicas"])
		app := merged["app"].(map[string]any)
		assert.Equal(t, "prod", app["env"])
		assert.Equal(t, "v1", app["tag"])
		assert.Equal(t, "secret-value", app["config"])
	})
}
