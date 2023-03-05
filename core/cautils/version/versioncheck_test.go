package version

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/semver"
)

const testVersionPath = "/ksgf1v1"

var envMx sync.Mutex // mutex to serialize tests dependent on environment variables

func TestChecker(t *testing.T) {
	t.Parallel()

	v := NewChecker()
	ctx := context.Background()

	t.Run("should request kubescape version by default", func(t *testing.T) {
		require.NoError(t,
			v.CheckLatestVersion(ctx),
		)

		mx.RLock()
		defer mx.RUnlock()
		require.NotEmpty(t, LatestReleaseVersion)

		t.Logf("latest: %s", LatestReleaseVersion)
	})
}

func TestIChecker(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("constructor strategy should yield version checker", func(t *testing.T) {
		envMx.Lock()
		t.Cleanup(envMx.Unlock)
		orig := os.Getenv(SKIP_VERSION_CHECK_ENV)
		origDeprec := os.Getenv(SKIP_VERSION_CHECK_DEPRECATED_ENV)
		os.Setenv(SKIP_VERSION_CHECK_ENV, "false")
		os.Setenv(SKIP_VERSION_CHECK_DEPRECATED_ENV, "false")
		t.Cleanup(func() {
			os.Setenv(SKIP_VERSION_CHECK_ENV, orig)
			os.Setenv(SKIP_VERSION_CHECK_DEPRECATED_ENV, origDeprec)
		})
		v := NewIChecker(ctx)

		_, isChecker := v.(*Checker)
		require.True(t, isChecker)
	})

	t.Run("constructor strategy should yield skip checker", func(t *testing.T) {
		envMx.Lock()
		t.Cleanup(envMx.Unlock)
		orig := os.Getenv(SKIP_VERSION_CHECK_ENV)
		origDeprec := os.Getenv(SKIP_VERSION_CHECK_DEPRECATED_ENV)
		os.Setenv(SKIP_VERSION_CHECK_ENV, "true")
		os.Setenv(SKIP_VERSION_CHECK_DEPRECATED_ENV, "false")
		t.Cleanup(func() {
			os.Setenv(SKIP_VERSION_CHECK_ENV, orig)
			os.Setenv(SKIP_VERSION_CHECK_DEPRECATED_ENV, origDeprec)
		})
		v := NewIChecker(ctx)

		_, isSkipChecker := v.(*SkipChecker)
		require.True(t, isSkipChecker)
	})

	t.Run("constructor strategy should yield skip checker (backward-compatible)", func(t *testing.T) {
		envMx.Lock()
		t.Cleanup(envMx.Unlock)
		orig := os.Getenv(SKIP_VERSION_CHECK_ENV)
		origDeprec := os.Getenv(SKIP_VERSION_CHECK_DEPRECATED_ENV)
		os.Setenv(SKIP_VERSION_CHECK_ENV, "false")
		os.Setenv(SKIP_VERSION_CHECK_DEPRECATED_ENV, "true")
		t.Cleanup(func() {
			os.Setenv(SKIP_VERSION_CHECK_ENV, orig)
			os.Setenv(SKIP_VERSION_CHECK_DEPRECATED_ENV, origDeprec)
		})
		v := NewIChecker(ctx)

		_, isSkipChecker := v.(*SkipChecker)
		require.True(t, isSkipChecker)
	})
}

func TestGetLatestVersion(t *testing.T) {
	t.Parallel()

	t.Run("with real cloud function API", func(t *testing.T) {
		t.Parallel()
		// NOTE(fredbi): if some rate limiting issues appear when intensively running this test against the
		// real cloud function, skip this test and trust the mock.

		v := NewChecker()
		ctx := context.Background()

		t.Run("request with framework", func(t *testing.T) {
			resp, err := v.getLatestVersion(ctx, newCheckRequest([]CheckRequestOption{
				WithFramework("mitre"),
				WithTarget("yaml"),
			}))
			require.NoError(t, err)
			require.NotEmpty(t, resp.Framework)
			require.NotEmpty(t, resp.FrameworkUpdate)
		})

		t.Run("request with framework and version", func(t *testing.T) {
			resp, err := v.getLatestVersion(ctx, newCheckRequest([]CheckRequestOption{
				WithFramework("armobest"),
				WithFrameworkVersion("v1.0.0"),
				WithTarget("cluster"),
			}))
			require.NoError(t, err)
			require.NotEmpty(t, resp.Framework)
			require.NotEmpty(t, resp.FrameworkUpdate)
		})
	})

	t.Run("with mock cloud function API", func(t *testing.T) {
		t.Parallel()

		v := NewChecker()
		mockAPI := mockVersionCheckAPIServer(t)
		t.Cleanup(mockAPI.Close)
		v.versionURL = mockAPI.URL(testVersionPath)
		ctx := context.Background()

		t.Run("request with framework", func(t *testing.T) {
			resp, err := v.getLatestVersion(ctx, newCheckRequest([]CheckRequestOption{
				WithFramework("mitre"),
				WithTarget("yaml"),
			}))
			require.NoError(t, err)
			require.Equal(t, "mitre", resp.Framework)
			require.Equal(t, "v1.0.87", resp.FrameworkUpdate)
		})

		t.Run("request with framework and version", func(t *testing.T) {
			resp, err := v.getLatestVersion(ctx, newCheckRequest([]CheckRequestOption{
				WithFramework("armobest"),
				WithFrameworkVersion("v1.0.0"),
				WithTarget("cluster"),
			}))
			require.NoError(t, err)
			require.Equal(t, "armobest", resp.Framework)
			require.Equal(t, "v1.0.0", resp.FrameworkUpdate)
		})

		t.Run("check latest version", func(t *testing.T) {
			require.NoError(t, v.CheckLatestVersion(ctx,
				WithFramework("armobest"),
				WithFrameworkVersion("v1.0.0"),
				WithTarget("cluster"),
			))
		})
	})

	t.Run("with mock cloud function API: error", func(t *testing.T) {
		t.Parallel()

		v := NewChecker()
		testErr := errors.New("mock sayz error")
		mockAPI := mockVersionCheckAPIServer(t, withAPIError(testErr))
		t.Cleanup(mockAPI.Close)
		v.versionURL = mockAPI.URL(testVersionPath)
		ctx := context.Background()

		t.Run("request with framework", func(t *testing.T) {
			_, err := v.getLatestVersion(ctx, newCheckRequest([]CheckRequestOption{
				WithFramework("mitre"),
				WithTarget("yaml"),
			}))
			require.Error(t, err)
			t.Logf("expected error: %v", err)
			require.Contains(t, err.Error(), testErr.Error())
		})

		t.Run("check latest version", func(t *testing.T) {
			require.Error(t, v.CheckLatestVersion(ctx,
				WithFramework("armobest"),
				WithFrameworkVersion("v1.0.0"),
				WithTarget("cluster"),
			))
		})
	})

	t.Run("with mock cloud function API: garbled JSON", func(t *testing.T) {
		t.Parallel()

		v := NewChecker()
		mockAPI := mockVersionCheckAPIServer(t, withAPIGarbled(true))
		t.Cleanup(mockAPI.Close)
		v.versionURL = mockAPI.URL(testVersionPath)
		ctx := context.Background()

		t.Run("request with framework", func(t *testing.T) {
			_, err := v.getLatestVersion(ctx, newCheckRequest([]CheckRequestOption{
				WithFramework("mitre"),
				WithTarget("yaml"),
			}))
			require.Error(t, err)
			t.Logf("expected error: %v", err)
			require.Contains(t, err.Error(), "garbled")
		})

		t.Run("check latest version", func(t *testing.T) {
			require.Error(t, v.CheckLatestVersion(ctx,
				WithFramework("armobest"),
				WithFrameworkVersion("v1.0.0"),
				WithTarget("cluster"),
			))
		})
	})
}

func TestIsCurrentAtLatest(t *testing.T) {
	t.Parallel()

	mx.RLock()
	currentBuild := BuildNumber
	currentLatest := LatestReleaseVersion
	mx.RUnlock()

	t.Cleanup(func() {
		mx.Lock()
		BuildNumber = currentBuild
		LatestReleaseVersion = currentLatest
		mx.Unlock()
	})

	t.Run("should be up to date", func(t *testing.T) {
		mx.Lock()
		BuildNumber = "v1.2.3"
		LatestReleaseVersion = "v1.2.3"
		mx.Unlock()

		require.True(t, IsCurrentAtLatest())
	})

	t.Run("should not be up to date", func(t *testing.T) {
		mx.Lock()
		BuildNumber = "v1.2.3"
		LatestReleaseVersion = "v1.2.4"
		mx.Unlock()

		require.False(t, IsCurrentAtLatest())
	})
}

func TestSemverLib(t *testing.T) {
	t.Parallel()

	assert.Equal(t, -1, semver.Compare("v2.0.150", "v2.0.151"))
	assert.Equal(t, 0, semver.Compare("v2.0.150", "v2.0.150"))
	assert.Equal(t, 1, semver.Compare("v2.0.150", "v2.0.149"))
	assert.Equal(t, -1, semver.Compare("v2.0.150", "v3.0.150"))
	assert.Equal(t, -1, semver.Compare("unknown", "v3.0.150"))
	assert.Equal(t, -1, semver.Compare("", "v3.0.150"))
	assert.Equal(t, 0, semver.Compare("unknown", "unknown"))
	assert.Equal(t, 0, semver.Compare("unknown", ""))
}

func TestDefaultRequest(t *testing.T) {
	t.Parallel()

	t.Run("should default to env client", func(t *testing.T) {
		const buildClient = "myownbinary"

		resetEnv := setEnv(CLIENT_ENV, buildClient)
		t.Cleanup(resetEnv)

		req := defaultCheckRequest()
		require.Equal(t, buildClient, req.ClientBuild)
	})

	t.Run("should default to baked build client", func(t *testing.T) {
		const buildClient = "mybakedbinary"

		resetEnv := setEnv(CLIENT_ENV, "")
		t.Cleanup(resetEnv)

		reset := setBuildClient(buildClient)
		t.Cleanup(reset)

		req := defaultCheckRequest()
		require.Equal(t, buildClient, req.ClientBuild)
	})

	t.Run("should default to backed build number", func(t *testing.T) {
		const buildNumber = "v9.9.9"

		reset := setBuildNumber(buildNumber)
		t.Cleanup(reset)

		req := defaultCheckRequest()
		require.Equal(t, buildNumber, req.ClientVersion)
	})
}

func setEnv(pairs ...string) func() {
	envMx.Lock()

	j := 0
	orig := make([]string, len(pairs)/2)

	for i := 0; i < len(pairs); {
		key := pairs[i]
		i++
		value := pairs[i]
		i++

		orig[j] = os.Getenv(key)
		os.Setenv(key, value)
		j++
	}

	return func() {
		j := 0
		for i := 0; i < len(pairs); {
			key := pairs[i]
			i += 2
			os.Setenv(key, orig[j])
			j++
		}

		envMx.Unlock()
	}
}

func setBuildClient(buildClient string) func() {
	mx.Lock()
	origBuild := Client
	Client = buildClient
	mx.Unlock()

	return func() {
		mx.Lock()
		Client = origBuild
		mx.Unlock()
	}
}

func setBuildNumber(buildNumber string) func() {
	mx.Lock()
	origBuild := BuildNumber
	BuildNumber = buildNumber
	mx.Unlock()

	return func() {
		mx.Lock()
		BuildNumber = origBuild
		mx.Unlock()
	}
}

type (
	testServer struct {
		*httptest.Server
		*mockAPIOptions
	}

	mockAPIOption  func(*mockAPIOptions)
	mockAPIOptions struct {
		withError   error // responds error systematically
		withGarbled bool  // responds garbled JSON (if a JSON response is expected)
	}
)

func withAPIError(err error) mockAPIOption {
	return func(o *mockAPIOptions) {
		o.withError = err
	}
}

func withAPIGarbled(enabled bool) mockAPIOption {
	return func(o *mockAPIOptions) {
		o.withGarbled = enabled
	}
}

func (s *testServer) Root() string {
	return s.Server.URL
}

func (s *testServer) URL(pth string) string {
	pth = strings.TrimLeft(pth, "/")

	return fmt.Sprintf("%s/%s", s.Server.URL, pth)
}

// WantsError responds with the configured error.
func (o *mockAPIOptions) WantsError(w http.ResponseWriter) bool {
	if o.withError == nil {
		return false
	}

	http.Error(w, o.withError.Error(), http.StatusInternalServerError)

	return true
}

// WantsGarbled responds with invalid JSON
func (o *mockAPIOptions) WantsGarbled(w http.ResponseWriter) bool {
	if !o.withGarbled {
		return false
	}

	invalidJSON(w)

	return true
}

func mockVersionCheckAPIServer(t testing.TB, opts ...mockAPIOption) *testServer {
	h := http.NewServeMux()

	// test options: regular mock (default), error or garbled JSON output
	server := &testServer{
		Server:         httptest.NewServer(h),
		mockAPIOptions: apiOptions(opts),
	}

	h.HandleFunc(testVersionPath, func(w http.ResponseWriter, r *http.Request) {
		if !isPost(t, r) {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		if !isJSON(t, r) {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		buf, err := io.ReadAll(r.Body)
		defer func() {
			_ = r.Body.Close()
		}()

		if !assert.NoError(t, err) {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		request := new(versionCheckRequest)
		if !assert.NoError(t, json.Unmarshal(buf, request)) {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		if server.WantsError(w) {
			return
		}

		if server.WantsGarbled(w) {
			return
		}

		fwVersion := request.FrameworkVersion
		if fwVersion == "" {
			fwVersion = "v1.0.87"
		}

		response := versionCheckResponse{
			Client:          request.Client,
			ClientUpdate:    "v2.2.3",
			Framework:       request.Framework,
			FrameworkUpdate: fwVersion,
			Message:         "a message",
		}

		enc := json.NewEncoder(w)
		if !assert.NoError(t, enc.Encode(response)) {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}
	})

	return server
}

func apiOptions(opts []mockAPIOption) *mockAPIOptions {
	o := &mockAPIOptions{}
	for _, apply := range opts {
		apply(o)
	}

	return o
}

func isPost(t testing.TB, r *http.Request) bool {
	return assert.Truef(t, strings.EqualFold(http.MethodPost, r.Method), "expected a GET method called, but got %q", r.Method)
}

func isJSON(t testing.TB, r *http.Request) bool {
	contentType := r.Header.Get("Content-Type")

	return assert.Equalf(t, "application/json", contentType, "expected application/json content type")
}

func invalidJSON(w http.ResponseWriter) {
	fmt.Fprintf(w, `{"garbled":`)
}
