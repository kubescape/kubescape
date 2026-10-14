package imagescan

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func callRegistryRedirectAPI(ctx context.Context, provider, baseURL string, client *http.Client, credentials RegistryCredentials) ([]byte, error) {
	if provider == "harbor" {
		api := &harborAPIWrapper{baseURL: baseURL, token: credentials.Token, username: credentials.Username, password: credentials.Password, httpClient: client}
		return api.DoRequest(ctx, http.MethodGet, "/scan")
	}
	api := &gitlabAPIWrapper{baseURL: baseURL, token: credentials.Token, httpClient: client}
	return api.DoGraphQL(ctx, "query { currentUser { username } }", map[string]interface{}{"project": "team/app"})
}

func TestRegistryRedirect_AllRedirectCodesRespectCredentialBoundary(t *testing.T) {
	for _, provider := range []string{"harbor", "gitlab"} {
		for _, code := range []int{301, 302, 303, 307, 308} {
			t.Run(provider+"/"+http.StatusText(code), func(t *testing.T) {
				var targetHits atomic.Int32
				target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					targetHits.Add(1)
					w.WriteHeader(http.StatusOK)
				}))
				defer target.Close()
				source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, target.URL+"/foreign", code)
				}))
				defer source.Close()
				body, err := callRegistryRedirectAPI(context.Background(), provider, source.URL, source.Client(), RegistryCredentials{Token: "redirect-test-only"})
				require.ErrorContains(t, err, "credentials cannot leave origin")
				require.Nil(t, body)
				require.Zero(t, targetHits.Load())
			})
		}
	}
}

func TestRegistryRedirect_HarborBasicAuthIsProtected(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		require.True(t, ok)
		require.Equal(t, "test-robot", username)
		require.Equal(t, "test-password", password)
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()
	_, err := callRegistryRedirectAPI(context.Background(), "harbor", source.URL, source.Client(), RegistryCredentials{Username: "test-robot", Password: "test-password"})
	require.ErrorContains(t, err, "credentials cannot leave origin")
	require.Zero(t, hits.Load())
}

func TestRegistryRedirect_SameOriginPreservesRequest(t *testing.T) {
	for _, provider := range []string{"harbor", "gitlab"} {
		t.Run(provider, func(t *testing.T) {
			var hits atomic.Int32
			source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/final" {
					http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
					return
				}
				hits.Add(1)
				require.Equal(t, "Bearer "+"redirect-test-only", r.Header.Get("Authorization"))
				require.Equal(t, "application/json", r.Header.Get("Accept"))
				if provider == "gitlab" {
					require.Equal(t, http.MethodPost, r.Method)
					body, err := io.ReadAll(r.Body)
					require.NoError(t, err)
					require.Contains(t, string(body), "currentUser")
					require.Contains(t, string(body), "team/app")
					require.Equal(t, "application/json", r.Header.Get("Content-Type"))
				} else {
					require.Equal(t, http.MethodGet, r.Method)
				}
				_, _ = w.Write([]byte(`{"result":"safe"}`))
			}))
			defer source.Close()
			body, err := callRegistryRedirectAPI(context.Background(), provider, source.URL, source.Client(), RegistryCredentials{Token: "redirect-test-only"})
			require.NoError(t, err)
			require.JSONEq(t, `{"result":"safe"}`, string(body))
			require.Equal(t, int32(1), hits.Load())
		})
	}
}

func TestRegistryRedirect_CustomCallbackCannotRewriteTarget(t *testing.T) {
	for _, provider := range []string{"harbor", "gitlab"} {
		t.Run(provider, func(t *testing.T) {
			var hits, callbacks atomic.Int32
			target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				_, _ = w.Write([]byte(`{}`))
			}))
			defer target.Close()
			source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/same-origin", http.StatusTemporaryRedirect)
			}))
			defer source.Close()
			client := source.Client()
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				callbacks.Add(1)
				destination, err := url.Parse(target.URL)
				if err != nil {
					return err
				}
				req.URL = destination
				// Clearing the history's header must not erase the original boundary.
				via[0].Header.Del("Authorization")
				return nil
			}
			_, err := callRegistryRedirectAPI(context.Background(), provider, source.URL, client, RegistryCredentials{Token: "redirect-test-only"})
			require.ErrorContains(t, err, "credentials cannot leave origin")
			require.Equal(t, int32(1), callbacks.Load())
			require.Zero(t, hits.Load())
		})
	}
}

func TestRegistryRedirect_HTTPSDowngradeNeverSendsCredentials(t *testing.T) {
	for _, provider := range []string{"harbor", "gitlab"} {
		t.Run(provider, func(t *testing.T) {
			var hits atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				_, _ = w.Write([]byte(`{}`))
			}))
			defer target.Close()
			source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
			}))
			defer source.Close()
			_, err := callRegistryRedirectAPI(context.Background(), provider, source.URL, source.Client(), RegistryCredentials{Token: "redirect-test-only"})
			require.ErrorContains(t, err, "credentials cannot leave origin")
			require.Zero(t, hits.Load())
		})
	}
}

func TestRegistryRedirect_HarborAnonymousCrossOriginStillWorks(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Empty(t, r.Header.Get("Authorization"))
		hits.Add(1)
		_, _ = w.Write([]byte(`{"anonymous":true}`))
	}))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()
	body, err := callRegistryRedirectAPI(context.Background(), "harbor", source.URL, source.Client(), RegistryCredentials{})
	require.NoError(t, err)
	require.JSONEq(t, `{"anonymous":true}`, string(body))
	require.Equal(t, int32(1), hits.Load())
}

func TestRegistryRedirect_ExplicitHTTPOriginStillWorks(t *testing.T) {
	for _, provider := range []string{"harbor", "gitlab"} {
		t.Run(provider, func(t *testing.T) {
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/final" {
					http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
					return
				}
				require.NotEmpty(t, r.Header.Get("Authorization"))
				_, _ = w.Write([]byte(`{}`))
			}))
			defer source.Close()
			_, err := callRegistryRedirectAPI(context.Background(), provider, source.URL, source.Client(), RegistryCredentials{Token: "redirect-test-only"})
			require.NoError(t, err)
		})
	}
}

func TestRegistryRedirect_OriginNormalization(t *testing.T) {
	for _, tc := range []struct {
		source, target string
		allowed        bool
	}{
		{"https://registry.example/a", "https://registry.example/b", true},
		{"https://registry.example/a", "https://REGISTRY.example:443/b", true},
		{"http://registry.example/a", "http://registry.example:80/b", true},
		{"https://registry.example:8443/a", "https://registry.example:8443/b", true},
		{"https://registry.example/a", "https://child.registry.example/b", false},
		{"https://registry.example/a", "https://registry.example:8443/b", false},
		{"https://registry.example/a", "http://registry.example/b", false},
		{"http://registry.example/a", "https://registry.example/b", false},
		{"https://registry.example/a", "https://other.example/b", false},
		{"https://[::1]:8443/a", "https://[::1]:8443/b", true},
		{"https://[::1]:8443/a", "https://[::1]:9443/b", false},
	} {
		t.Run(tc.source+"->"+tc.target, func(t *testing.T) {
			first, err := http.NewRequestWithContext(context.Background(), http.MethodGet, tc.source, nil)
			require.NoError(t, err)
			first.Header.Set("Authorization", "Bearer "+"origin-test-only")
			next, err := http.NewRequestWithContext(context.Background(), http.MethodGet, tc.target, nil)
			require.NoError(t, err)
			err = registryAPIHTTPClient(nil).CheckRedirect(next, []*http.Request{first})
			if tc.allowed {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestRegistryRedirect_CallbackErrorsAreUnchanged(t *testing.T) {
	for _, callbackError := range []error{errors.New("caller policy"), http.ErrUseLastResponse} {
		first, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://registry.example/start", nil)
		require.NoError(t, err)
		first.Header.Set("Authorization", "Bearer "+"error-test-only")
		next, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://registry.example/next", nil)
		require.NoError(t, err)
		client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
			req.URL, err = url.Parse("https://other.example")
			require.NoError(t, err)
			return callbackError
		}}
		require.Same(t, callbackError, registryAPIHTTPClient(client).CheckRedirect(next, []*http.Request{first}))
	}
}

func TestRegistryRedirect_CustomLimitAndClientSettingsArePreserved(t *testing.T) {
	first, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://registry.example/start", nil)
	require.NoError(t, err)
	first.Header.Set("Authorization", "Bearer "+"limit-test-only")
	next, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://registry.example/next", nil)
	require.NoError(t, err)
	via := make([]*http.Request, 11)
	for i := range via {
		via[i] = first
	}
	called := 0
	base := &http.Client{Timeout: 3 * time.Second, Transport: http.DefaultTransport, CheckRedirect: func(*http.Request, []*http.Request) error {
		called++
		return nil
	}}
	wrapped := registryAPIHTTPClient(base)
	require.NotSame(t, base, wrapped)
	require.Equal(t, base.Timeout, wrapped.Timeout)
	require.Same(t, base.Transport, wrapped.Transport)
	require.NoError(t, wrapped.CheckRedirect(next, via))
	require.Equal(t, 1, called)
	require.ErrorContains(t, registryAPIHTTPClient(nil).CheckRedirect(next, via), "10 redirects")
	require.NoError(t, base.CheckRedirect(next, via))
	require.Equal(t, 2, called)
}

func TestRegistryRedirect_URLUserInformationIsProtected(t *testing.T) {
	first, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://robot:test-password@registry.example/start", nil)
	require.NoError(t, err)
	next, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://other.example/next", nil)
	require.NoError(t, err)
	err = registryAPIHTTPClient(nil).CheckRedirect(next, []*http.Request{first})
	require.ErrorContains(t, err, "credentials cannot leave origin")
	require.NotContains(t, err.Error(), "test-password")
}

func TestRegistryRedirect_DoesNotCallPolicyForUnsafeInitialTarget(t *testing.T) {
	first, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://registry.example/start", nil)
	require.NoError(t, err)
	first.Header.Set("Authorization", "Bearer "+"precheck-test-only")
	next, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://other.example/next", nil)
	require.NoError(t, err)
	called := false
	base := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		called = true
		return nil
	}}
	require.Error(t, registryAPIHTTPClient(base).CheckRedirect(next, []*http.Request{first}))
	require.False(t, called)
}

func TestRegistryRedirect_CallbackRemovingURLReturnsError(t *testing.T) {
	first, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://registry.example/start", nil)
	require.NoError(t, err)
	next, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://registry.example/next", nil)
	require.NoError(t, err)
	base := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		req.URL = nil
		return nil
	}}
	require.ErrorContains(t, registryAPIHTTPClient(base).CheckRedirect(next, []*http.Request{first}), "URL is missing")
}

func TestRegistryRedirect_ContextCancellationIsPreserved(t *testing.T) {
	for _, provider := range []string{"harbor", "gitlab"} {
		t.Run(provider, func(t *testing.T) {
			var hits atomic.Int32
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				_, _ = w.Write([]byte(`{}`))
			}))
			defer source.Close()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err := callRegistryRedirectAPI(ctx, provider, source.URL, source.Client(), RegistryCredentials{Token: "cancel-test-only"})
			require.ErrorIs(t, err, context.Canceled)
			require.Zero(t, hits.Load())
		})
	}
}

func TestRegistryRedirect_ResponseLimitsStillApplyAfterRedirect(t *testing.T) {
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/final" {
			http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("x", 9)))
	}))
	defer source.Close()
	harbor := &harborAPIWrapper{baseURL: source.URL, token: "limit-test-only", httpClient: source.Client(), maxResponseSize: 8}
	gitlab := &gitlabAPIWrapper{baseURL: source.URL, token: "limit-test-only", httpClient: source.Client(), maxResponseSize: 8}
	_, err := harbor.DoRequest(context.Background(), http.MethodGet, "/start")
	require.ErrorContains(t, err, "8-byte limit")
	_, err = gitlab.DoGraphQL(context.Background(), "query {}", nil)
	require.ErrorContains(t, err, "8-byte limit")
}

func TestRegistryRedirect_LoginDoesNotAuthenticateAtForeignOrigin(t *testing.T) {
	for _, provider := range []string{"harbor", "gitlab"} {
		t.Run(provider, func(t *testing.T) {
			var targetHits atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetHits.Add(1)
				_, _ = w.Write([]byte(`{"data":{"currentUser":{"username":"robot"}}}`))
			}))
			defer target.Close()
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.NotEmpty(t, r.Header.Get("Authorization"))
				http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
			}))
			defer source.Close()
			credentials := RegistryCredentials{Token: "login-test-only"}
			if provider == "harbor" {
				adaptor := NewHarborAdaptor()
				err := adaptor.Login(context.Background(), source.URL, credentials)
				require.ErrorContains(t, err, "credentials cannot leave origin")
				require.Nil(t, adaptor.client)
			} else {
				adaptor := NewGitlabAdaptor()
				err := adaptor.Login(context.Background(), source.URL, credentials)
				require.ErrorContains(t, err, "credentials cannot leave origin")
				require.Nil(t, adaptor.client)
			}
			require.Zero(t, targetHits.Load())
		})
	}
}

func TestRegistryRedirect_CallbackCannotChangeHistoryOrigin(t *testing.T) {
	first, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://registry.example/start", nil)
	require.NoError(t, err)
	first.Header.Set("Authorization", "Bearer "+"history-test-only")
	next, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://registry.example/next", nil)
	require.NoError(t, err)
	base := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		req.URL.Host = "foreign.example"
		via[0].URL.Host = "foreign.example"
		return nil
	}}
	err = registryAPIHTTPClient(base).CheckRedirect(next, []*http.Request{first})
	require.ErrorContains(t, err, "credentials cannot leave origin registry.example")
}

func TestRegistryRedirect_MultipleHopsKeepOriginalCredentialBoundary(t *testing.T) {
	first, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://registry.example/start", nil)
	require.NoError(t, err)
	first.Header.Set("Authorization", "Bearer "+"chain-test-only")
	middle, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://registry.example/middle", nil)
	require.NoError(t, err)
	next, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://child.registry.example/final", nil)
	require.NoError(t, err)
	require.Error(t, registryAPIHTTPClient(nil).CheckRedirect(next, []*http.Request{first, middle}))
}

func TestRegistryRedirect_StatusErrorsStillReachCaller(t *testing.T) {
	for _, provider := range []string{"harbor", "gitlab"} {
		t.Run(provider, func(t *testing.T) {
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/final" {
					http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
					return
				}
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"access denied"}`))
			}))
			defer source.Close()
			_, err := callRegistryRedirectAPI(context.Background(), provider, source.URL, source.Client(), RegistryCredentials{Token: "status-test-only"})
			require.ErrorContains(t, err, "403")
		})
	}
}

func TestRegistryRedirect_CredentialsStayAtOrigin(t *testing.T) {
	for _, provider := range []string{"harbor", "gitlab"} {
		t.Run(provider, func(t *testing.T) {
			var hits atomic.Int32
			target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				require.NotEmpty(t, r.Header.Get("Authorization"))
				_, _ = w.Write([]byte(`{}`))
			}))
			defer target.Close()
			source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
			}))
			defer source.Close()
			var err error
			if provider == "harbor" {
				api := &harborAPIWrapper{baseURL: source.URL, token: "registry-test-only", httpClient: source.Client()}
				_, err = api.DoRequest(context.Background(), http.MethodGet, "/scan")
			} else {
				api := &gitlabAPIWrapper{baseURL: source.URL, token: "registry-test-only", httpClient: source.Client()}
				_, err = api.DoGraphQL(context.Background(), "query { currentUser { username } }", nil)
			}
			require.Zero(t, hits.Load())
			require.Error(t, err)
		})
	}
}
