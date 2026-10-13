package imagescan

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQuayRedirect_AuthenticatedCrossOriginNeverReachesTarget(t *testing.T) {
	for _, auth := range []string{"Bearer fixture-token", "Basic Zml4dHVyZTpwYXNzd29yZA=="} {
		for _, insecure := range []bool{false, true} {
			t.Run(auth+map[bool]string{false: "/strict", true: "/http-opt-in"}[insecure], func(t *testing.T) {
				var received atomic.Int32
				target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					require.Equal(t, auth, r.Header.Get("Authorization"), "the old redirect policy forwards the fixture credential")
					received.Add(1)
					w.WriteHeader(http.StatusOK)
				}))
				defer target.Close()
				source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, target.URL+"/stolen", http.StatusFound)
				}))
				defer source.Close()
				client := createQuayHTTPClient(source.Client(), insecure)
				req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, source.URL, nil)
				require.NoError(t, err)
				req.Header.Set("Authorization", auth)
				resp, err := client.Do(req)
				if resp != nil {
					_ = resp.Body.Close()
				}
				require.ErrorContains(t, err, "authenticated request changed origin")
				require.Zero(t, received.Load(), "another TLS port is a separate origin, even on the same host")
			})
		}
	}
}

func TestQuayRedirect_SameOriginRetainsAuthentication(t *testing.T) {
	for _, auth := range []string{"Bearer fixture-token", "Basic Zml4dHVyZTpwYXNzd29yZA=="} {
		t.Run(auth, func(t *testing.T) {
			var received atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/start" {
					http.Redirect(w, r, "/finish", http.StatusTemporaryRedirect)
					return
				}
				require.Equal(t, auth, r.Header.Get("Authorization"))
				received.Add(1)
				_, _ = w.Write([]byte(`{"ok":true}`))
			}))
			defer server.Close()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/start", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", auth)
			resp, err := createQuayHTTPClient(server.Client(), false).Do(req)
			require.NoError(t, err)
			_ = resp.Body.Close()
			require.Equal(t, int32(1), received.Load())
		})
	}
}

func TestQuayRedirect_AnonymousCrossOriginRemainsAllowed(t *testing.T) {
	var received atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Empty(t, r.Header.Get("Authorization"))
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()
	resp, err := createQuayHTTPClient(source.Client(), false).Get(source.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, int32(1), received.Load())
}

func TestQuayRedirect_PolicyChecksNormalizedOriginAndCannotBeOverridden(t *testing.T) {
	for _, tc := range []struct {
		name, source, target string
		auth                 bool
		wantDenied           bool
	}{
		{"subdomain is not trusted", "https://quay.example/v2/app", "https://child.quay.example/steal", true, true},
		{"another host", "https://quay.example/v2/app", "https://other.example/steal", true, true},
		{"another port", "https://quay.example/v2/app", "https://quay.example:8443/steal", true, true},
		{"default port normalization", "https://quay.example/v2/app", "https://quay.example:443/safe", true, false},
		{"hostname case normalization", "https://QUAY.example/v2/app", "https://quay.example/safe", true, false},
		{"another same-origin path", "https://quay.example:8443/v2/app", "https://quay.example:8443/other", true, false},
		{"userinfo is credential-bearing", "https://fixture:password@quay.example/v2/app", "https://child.quay.example/steal", false, true},
		{"HTTP opt-in does not authorize downgrade", "https://quay.example/v2/app", "http://quay.example/steal", true, true},
		{"anonymous host redirect", "https://quay.example/v2/app", "https://other.example/safe", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			base := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
				called = true
				return nil
			}}
			client := createQuayHTTPClient(base, true)
			first, err := http.NewRequestWithContext(context.Background(), http.MethodGet, tc.source, nil)
			require.NoError(t, err)
			if tc.auth {
				first.Header.Set("Authorization", "Bearer fixture-token")
			}
			next, err := http.NewRequestWithContext(context.Background(), http.MethodGet, tc.target, nil)
			require.NoError(t, err)
			err = client.CheckRedirect(next, []*http.Request{first})
			if tc.wantDenied {
				require.Error(t, err)
				require.False(t, called, "custom redirect policy must not bypass the credential boundary")
			} else {
				require.NoError(t, err)
				require.True(t, called)
			}
		})
	}
}

func TestQuayRedirect_OriginCheckCoversTheEntireChain(t *testing.T) {
	client := createQuayHTTPClient(nil, false)
	first, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://quay.example/start", nil)
	require.NoError(t, err)
	first.Header.Set("Authorization", "Bearer fixture-token")
	middle, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://quay.example/middle", nil)
	require.NoError(t, err)
	last, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://child.quay.example/last", nil)
	require.NoError(t, err)
	require.ErrorContains(t, client.CheckRedirect(last, []*http.Request{first, middle}), "changed origin")
}

func TestQuayRedirect_ExistingCustomPolicyIsPreserved(t *testing.T) {
	sentinel := errors.New("custom redirect rejected")
	base := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return sentinel }}
	client := createQuayHTTPClient(base, false)
	first, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://quay.example/start", nil)
	require.NoError(t, err)
	first.Header.Set("Authorization", "Bearer fixture-token")
	next, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://quay.example/next", nil)
	require.NoError(t, err)
	require.ErrorIs(t, client.CheckRedirect(next, []*http.Request{first}), sentinel)
	require.ErrorIs(t, base.CheckRedirect(next, []*http.Request{first}), sentinel)
}

func TestQuayRedirect_AuthRealmCannotRedirectCredentialsAway(t *testing.T) {
	var received atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		_, _ = w.Write([]byte(`{"token":"stolen"}`))
	}))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/token", http.StatusFound)
	}))
	defer source.Close()
	for _, credentials := range []RegistryCredentials{
		{Username: "fixture", Password: "password"},
		{Token: "fixture-token"},
	} {
		wrapper := &quayAPIWrapper{
			baseURL:    source.URL,
			username:   credentials.Username,
			password:   credentials.Password,
			token:      credentials.Token,
			httpClient: source.Client(),
		}
		token, err := wrapper.fetchChallengeToken(context.Background(), source.URL+"/auth", "registry", "repository:team/app:pull")
		require.ErrorContains(t, err, "changed origin")
		require.Empty(t, token)
	}
	require.Zero(t, received.Load())
}

func TestQuayRedirect_CachedTokenIsProtectedDuringRegistryRequests(t *testing.T) {
	var received atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer cached-fixture", r.Header.Get("Authorization"))
		http.Redirect(w, r, target.URL+"/manifest", http.StatusFound)
	}))
	defer source.Close()
	wrapper := &quayAPIWrapper{
		baseURL:      source.URL,
		httpClient:   createQuayHTTPClient(source.Client(), false),
		cachedTokens: map[string]string{"repository:team/app:pull": "cached-fixture"},
		maxRetries:   3,
	}
	data, err := wrapper.DoRequest(context.Background(), http.MethodGet, "/v2/team/app/manifests/latest")
	require.ErrorContains(t, err, "changed origin")
	require.Nil(t, data)
	require.Zero(t, received.Load())
}

func TestQuayRedirect_FreshChallengeTokenCannotEscapeOnRetry(t *testing.T) {
	var stolen, attempts atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stolen.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer target.Close()
	var origin string
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth" {
			_, _ = w.Write([]byte(`{"token":"fresh-fixture"}`))
			return
		}
		attempts.Add(1)
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/auth",service="quay",scope="repository:team/app:pull"`, origin))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		require.Equal(t, "Bearer fresh-fixture", r.Header.Get("Authorization"))
		http.Redirect(w, r, target.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	origin = source.URL
	wrapper := &quayAPIWrapper{
		baseURL:    source.URL,
		httpClient: createQuayHTTPClient(source.Client(), false),
		maxRetries: 3,
	}
	data, err := wrapper.DoRequest(context.Background(), http.MethodGet, "/v2/team/app/manifests/latest")
	require.ErrorContains(t, err, "changed origin")
	require.Nil(t, data)
	require.Zero(t, stolen.Load())
	require.Equal(t, int32(2), attempts.Load(), "unsafe redirects should fail immediately, not enter the retry loop")
}

func TestQuayRedirect_AllRedirectStatusCodesProtectCredentials(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var stolen atomic.Int32
			target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				stolen.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer target.Close()
			source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL, code)
			}))
			defer source.Close()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, source.URL, nil)
			require.NoError(t, err)
			req.SetBasicAuth("fixture", "password")
			resp, err := createQuayHTTPClient(source.Client(), false).Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			require.Error(t, err)
			require.Zero(t, stolen.Load())
		})
	}
}

func TestQuayRedirect_HTTPOptInKeepsOriginBoundary(t *testing.T) {
	var stolen atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stolen.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, source.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer fixture-token")
	resp, err := createQuayHTTPClient(source.Client(), true).Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.ErrorContains(t, err, "changed origin")
	require.Zero(t, stolen.Load())
}

func TestQuayRedirect_CredentialsAddedLaterInChainAreProtected(t *testing.T) {
	first, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://quay.example/start", nil)
	require.NoError(t, err)
	middle, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://quay.example/authenticated", nil)
	require.NoError(t, err)
	middle.Header.Set("Authorization", "Bearer added-fixture")
	last, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://child.quay.example/last", nil)
	require.NoError(t, err)
	client := createQuayHTTPClient(nil, false)
	require.ErrorContains(t, client.CheckRedirect(last, []*http.Request{first, middle}), "changed origin")
}

func TestQuayRedirect_DefaultLoopLimitAndDowngradeGuardRemain(t *testing.T) {
	first, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://quay.example/start", nil)
	require.NoError(t, err)
	client := createQuayHTTPClient(nil, false)
	next, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://quay.example/next", nil)
	require.NoError(t, err)
	chain := make([]*http.Request, 10)
	for i := range chain {
		chain[i] = first
	}
	require.ErrorContains(t, client.CheckRedirect(next, chain), "stopped after 10 redirects")
	plain, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://quay.example/plain", nil)
	require.NoError(t, err)
	require.ErrorContains(t, client.CheckRedirect(plain, []*http.Request{first}), "scheme downgrade")
}

func TestQuayRedirect_URLCredentialsCannotEscape(t *testing.T) {
	var received atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		require.True(t, ok)
		require.Equal(t, "fixture", username)
		require.Equal(t, "password", password)
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()
	u, err := url.Parse(source.URL)
	require.NoError(t, err)
	u.User = url.UserPassword("fixture", "password")
	resp, err := createQuayHTTPClient(source.Client(), false).Get(u.String())
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.ErrorContains(t, err, "changed origin")
	require.Zero(t, received.Load())
}

func TestQuayRedirect_CloningDoesNotChangeCallerClient(t *testing.T) {
	called := 0
	base := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		called++
		return nil
	}}
	wrapped := createQuayHTTPClient(base, false)
	require.NotSame(t, base, wrapped)
	first, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://quay.example/start", nil)
	require.NoError(t, err)
	first.Header.Set("Authorization", "Bearer fixture-token")
	next, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://other.example/next", nil)
	require.NoError(t, err)
	require.Error(t, wrapped.CheckRedirect(next, []*http.Request{first}))
	require.Zero(t, called)
	require.NoError(t, base.CheckRedirect(next, []*http.Request{first}))
	require.Equal(t, 1, called)
}

func TestQuayRedirect_OriginErrorDoesNotExposeCredentials(t *testing.T) {
	first, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://fixture:fixture-password@quay.example/start", nil)
	require.NoError(t, err)
	first.Header.Set("Authorization", "Bearer fixture-secret-token")
	next, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://other.example/next", nil)
	require.NoError(t, err)
	err = createQuayHTTPClient(nil, false).CheckRedirect(next, []*http.Request{first})
	require.ErrorContains(t, err, "changed origin")
	require.NotContains(t, err.Error(), "fixture-password")
	require.NotContains(t, err.Error(), "fixture-secret-token")
	require.Contains(t, err.Error(), "quay.example")
	require.Contains(t, err.Error(), "other.example")
}
