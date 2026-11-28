package cautils

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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

func injectURLCredentials(rawURL, user, password string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if password == "" {
		u.User = url.User(user)
	} else {
		u.User = url.UserPassword(user, password)
	}
	return u.String()
}

func TestHelmValueOptions_MergeValues_RedactsURLCredentialsAndBlocksUnsafeRedirects(t *testing.T) {
	const (
		secretUser    = "ci-fixture-user"
		secretPass    = "ci-fixture-pass-123"
		fixtureBareID = "bare-identity-value-456"
	)

	assertRedacted := func(t *testing.T, err error) {
		t.Helper()
		require.Error(t, err)
		assert.NotContains(t, err.Error(), secretUser)
		assert.NotContains(t, err.Error(), secretPass)
		assert.NotContains(t, err.Error(), fixtureBareID)
	}

	t.Run("redacts credentials from HTTP error status", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "forbidden", http.StatusForbidden)
		}))
		defer ts.Close()

		credURL := injectURLCredentials(ts.URL+"/values.yaml", secretUser, secretPass)
		_, err := (HelmValueOptions{ValueFiles: []string{credURL}}).MergeValues()
		assertRedacted(t, err)
		assert.Contains(t, err.Error(), "/values.yaml")
	})

	t.Run("redacts credentials from oversized HTTP response error", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "32")
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("note: " + strings.Repeat("x", 128) + "\n"))
		}))
		defer ts.Close()

		credURL := injectURLCredentials(ts.URL+"/large.yaml", secretUser, secretPass)
		_, err := (HelmValueOptions{ValueFiles: []string{credURL}}).MergeValues()
		assertRedacted(t, err)
		assert.ErrorIs(t, err, ErrHelmTemplateTooLarge)
	})

	t.Run("redacts credentials from invalid YAML parse error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(":\n\t[invalid"))
		}))
		defer ts.Close()

		credURL := injectURLCredentials(ts.URL+"/bad.yaml", secretUser, secretPass)
		_, err := (HelmValueOptions{ValueFiles: []string{credURL}}).MergeValues()
		assertRedacted(t, err)
		assert.Contains(t, err.Error(), "failed to parse")
	})

	t.Run("redacts credentials and bare username tokens from transport errors in -f and --set-file", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			url  string
		}{
			{name: "user and password", url: "http://" + secretUser + ":" + secretPass + "@127.0.0.1:0/values.yaml"},
			{name: "bare token as username", url: "http://" + fixtureBareID + "@127.0.0.1:0/values.yaml"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := (HelmValueOptions{ValueFiles: []string{tc.url}}).MergeValues()
				assertRedacted(t, err)

				_, err = (HelmValueOptions{FileValues: []string{"cfg=" + tc.url}}).MergeValues()
				assertRedacted(t, err)
			})
		}
	})

	t.Run("redacts credentials from unsupported scheme errors", func(t *testing.T) {
		_, err := (HelmValueOptions{ValueFiles: []string{"ftp://" + secretUser + ":" + secretPass + "@charts.example.com/values.yaml"}}).MergeValues()
		assertRedacted(t, err)
		assert.Contains(t, err.Error(), "unsupported Helm values source scheme")
	})

	t.Run("blocks https to http scheme downgrade redirect", func(t *testing.T) {
		var targetHits atomic.Int32
		httpTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			targetHits.Add(1)
			_, _ = w.Write([]byte("downgraded: true\n"))
		}))
		defer httpTarget.Close()

		httpsSource := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, httpTarget.URL+"/values.yaml", http.StatusFound)
		}))
		defer httpsSource.Close()

		_, err := mergeBoundedHelmValuesWithClient(HelmValueOptions{ValueFiles: []string{httpsSource.URL + "/values.yaml"}}, nil, httpsSource.Client())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scheme downgrade from https")
		assert.Zero(t, targetHits.Load())
	})

	t.Run("blocks cross-origin redirect when URL carries credentials", func(t *testing.T) {
		var targetHits atomic.Int32
		target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			targetHits.Add(1)
			_, _ = w.Write([]byte("leaked: true\n"))
		}))
		defer target.Close()

		source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/values.yaml", http.StatusTemporaryRedirect)
		}))
		defer source.Close()

		credURL := injectURLCredentials(source.URL+"/values.yaml", secretUser, secretPass)
		_, err := mergeBoundedHelmValuesWithClient(HelmValueOptions{ValueFiles: []string{credURL}}, nil, source.Client())
		assertRedacted(t, err)
		assert.Contains(t, err.Error(), "credentials cannot leave origin")
		assert.Zero(t, targetHits.Load())
	})

	t.Run("allows same-origin https redirect and unauthenticated cross-origin http redirect", func(t *testing.T) {
		t.Setenv(MaxFileSizeEnvVar, "4096")
		source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/same" {
				http.Redirect(w, r, "/final", http.StatusFound)
				return
			}
			_, _ = w.Write([]byte("app:\n  tier: core\n"))
		}))
		defer source.Close()

		credSameOrigin := injectURLCredentials(source.URL+"/same", secretUser, secretPass)
		merged, err := mergeBoundedHelmValuesWithClient(HelmValueOptions{ValueFiles: []string{credSameOrigin}}, nil, source.Client())
		require.NoError(t, err)
		assert.Equal(t, "core", merged["app"].(map[string]any)["tier"])

		publicTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("app:\n  tier: edge\n"))
		}))
		defer publicTarget.Close()

		publicSource := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, publicTarget.URL+"/values.yaml", http.StatusFound)
		}))
		defer publicSource.Close()

		merged, err = (HelmValueOptions{ValueFiles: []string{publicSource.URL}}).MergeValues()
		require.NoError(t, err)
		assert.Equal(t, "edge", merged["app"].(map[string]any)["tier"])
	})

	t.Run("redacts malformed URLs and blocks non-HTTP redirect schemes", func(t *testing.T) {
		assert.Equal(t, "https://bad host/values.yaml", sanitizeHelmValueSource("https://"+secretUser+":"+secretPass+"@bad host/values.yaml"))
		assert.Equal(t, `C:\charts\values.yaml`, sanitizeHelmValueSource(`C:\charts\values.yaml`))

		for _, tc := range []struct {
			name string
			url  string
		}{
			{name: "invalid escape", url: "https://" + secretUser + ":" + secretPass + "@host.example/%zz/values.yaml"},
			{name: "space in host", url: "https://" + secretUser + ":" + secretPass + "@ho st.example/values.yaml"},
			{name: "scheme-relative", url: "//" + secretUser + ":" + secretPass + "@host.example/values.yaml"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := (HelmValueOptions{ValueFiles: []string{tc.url}}).MergeValues()
				assertRedacted(t, err)

				_, err = (HelmValueOptions{FileValues: []string{"k=" + tc.url}}).MergeValues()
				assertRedacted(t, err)
			})
		}

		source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
		}))
		defer source.Close()

		_, err := (HelmValueOptions{ValueFiles: []string{source.URL}}).MergeValues()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported scheme")
	})

	t.Run("redacts scheme-relative URL userinfo in url.Error.URL and sanitizeHelmValueSource", func(t *testing.T) {
		assert.Equal(t, "//other.example/values.yaml", sanitizeHelmValueSource("//"+secretUser+":"+secretPass+"@other.example/values.yaml"))
		assert.Equal(t, "/tmp/user@org/values.yaml", sanitizeHelmValueSource("/tmp/user@org/values.yaml"))

		source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "//"+secretUser+":"+secretPass+"@other.example/values.yaml")
			w.WriteHeader(http.StatusFound)
		}))
		defer source.Close()

		credURL := injectURLCredentials(source.URL+"/start", secretUser, secretPass)
		_, err := mergeBoundedHelmValuesWithClient(HelmValueOptions{ValueFiles: []string{credURL}}, nil, source.Client())
		assertRedacted(t, err)
		assert.Contains(t, err.Error(), "//other.example/values.yaml")

		var urlErr *url.Error
		require.ErrorAs(t, err, &urlErr)
		assert.Equal(t, "//other.example/values.yaml", urlErr.URL)
		assertRedacted(t, urlErr)
	})

	t.Run("redacts credentials embedded in redirect parse errors with invalid escapes", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			user string
			pass string
		}{
			{name: "standard userinfo", user: secretUser, pass: secretPass},
			{name: "userinfo with apostrophes", user: "ci-user'1", pass: "ci-val'123"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Location", "https://"+tc.user+":"+tc.pass+"@example.com/%zz")
					w.WriteHeader(http.StatusFound)
				}))
				defer source.Close()

				_, err := (HelmValueOptions{ValueFiles: []string{source.URL}}).MergeValues()
				require.Error(t, err)
				assert.NotContains(t, err.Error(), tc.user)
				assert.NotContains(t, err.Error(), tc.pass)
				assert.Contains(t, err.Error(), "https://example.com/%zz")

				var urlErr *url.Error
				require.ErrorAs(t, err, &urlErr)
				assert.NotContains(t, urlErr.Error(), tc.user)
				assert.NotContains(t, urlErr.Error(), tc.pass)
				require.NotNil(t, urlErr.Err)
				assert.NotContains(t, urlErr.Err.Error(), tc.user)
				assert.NotContains(t, urlErr.Err.Error(), tc.pass)
				if unwrapped := errors.Unwrap(err); unwrapped != nil {
					assert.NotContains(t, unwrapped.Error(), tc.user)
					assert.NotContains(t, unwrapped.Error(), tc.pass)
				}
			})
		}
	})

	t.Run("preserves outer error wrappers and errors.Is markers during sanitization", func(t *testing.T) {
		marker := errors.New("custom transport marker")
		client := &http.Client{
			Transport: helmValuesRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return nil, errors.Join(marker, &url.Error{
					Op:  "Get",
					URL: "https://" + secretUser + ":" + secretPass + "@inner.example.com/values.yaml",
					Err: errors.New("inner transport failure"),
				})
			}),
		}

		credURL := "https://" + secretUser + ":" + secretPass + "@charts.example.com/values.yaml"
		_, err := mergeBoundedHelmValuesWithClient(HelmValueOptions{ValueFiles: []string{credURL}}, nil, client)
		assertRedacted(t, err)
		assert.ErrorIs(t, err, marker)

		var outerURLErr *url.Error
		require.ErrorAs(t, err, &outerURLErr)
		assert.Equal(t, "https://charts.example.com/values.yaml", outerURLErr.URL)
		assertRedacted(t, outerURLErr)
		assertRedacted(t, outerURLErr.Err)

		joined := errors.Join(marker, &url.Error{Op: "Get", URL: credURL, Err: errors.New("boom")})
		sanitized := sanitizeHelmURLError(joined)
		assertRedacted(t, sanitized)
		assert.ErrorIs(t, sanitized, marker)

		var joinedURLErr *url.Error
		require.ErrorAs(t, sanitized, &joinedURLErr)
		assert.Equal(t, "https://charts.example.com/values.yaml", joinedURLErr.URL)
		assertRedacted(t, joinedURLErr)
	})
}

type helmValuesRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f helmValuesRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
