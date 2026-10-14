package imagescan

import (
	"context"
	"errors"
	"fmt"
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

func TestQuayHistory_CallbackCannotRewriteCredentialOrigin(t *testing.T) {
	var hits atomic.Int32
	foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer foreign.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/safe", http.StatusFound)
	}))
	defer origin.Close()
	client := foreign.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		destination, err := url.Parse(foreign.URL)
		require.NoError(t, err)
		*via[0].URL = *destination
		req.URL = destination
		return nil
	}
	w := &quayAPIWrapper{baseURL: origin.URL, token: t.Name(), httpClient: createQuayHTTPClient(client, false)}
	_, err := w.DoRequest(context.Background(), http.MethodGet, "/start")
	require.Error(t, err)
	require.Zero(t, hits.Load(), "foreign origin must never receive credentials")
}

func quayHistoryRequest(t *testing.T, address string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, address, nil)
	require.NoError(t, err)
	return req
}

func TestQuayHistory_ClearingCredentialsCannotAuthorizeForeignDestination(t *testing.T) {
	previous := quayHistoryRequest(t, "https://quay.example/start")
	previous.Header.Set("Authorization", t.Name())
	req := quayHistoryRequest(t, "https://quay.example/safe")
	base := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		via[0].Header.Del("Authorization")
		req.URL.Host = "foreign.example"
		return nil
	}}
	err := createQuayHTTPClient(base, false).CheckRedirect(req, []*http.Request{previous})
	require.ErrorContains(t, err, "changed origin")
	require.Empty(t, previous.Header.Get("Authorization"))
}

func TestQuayHistory_ReplacingHistoryRequestCannotAuthorizeForeignDestination(t *testing.T) {
	previous := quayHistoryRequest(t, "https://quay.example/start")
	previous.Header.Set("Authorization", t.Name())
	history := []*http.Request{previous}
	req := quayHistoryRequest(t, "https://quay.example/safe")
	base := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		via[0] = quayHistoryRequest(t, "https://foreign.example/")
		req.URL.Host = "foreign.example"
		return nil
	}}
	err := createQuayHTTPClient(base, false).CheckRedirect(req, history)
	require.Error(t, err)
	require.NotSame(t, previous, history[0])
}

func TestQuayHistory_MutatingURLInPlaceCannotAuthorizeAnotherPort(t *testing.T) {
	previous := quayHistoryRequest(t, "https://quay.example:443/start")
	previous.Header.Set("Authorization", t.Name())
	req := quayHistoryRequest(t, "https://quay.example/safe")
	base := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		via[0].URL.Host = "quay.example:8443"
		req.URL.Host = "quay.example:8443"
		return nil
	}}
	err := createQuayHTTPClient(base, false).CheckRedirect(req, []*http.Request{previous})
	require.ErrorContains(t, err, "changed origin")
}

func TestQuayHistory_ReplacingURLCannotAuthorizeSubdomain(t *testing.T) {
	previous := quayHistoryRequest(t, "https://quay.example/start")
	previous.Header.Set("Authorization", t.Name())
	req := quayHistoryRequest(t, "https://quay.example/safe")
	base := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		foreign, err := url.Parse("https://child.quay.example/")
		require.NoError(t, err)
		via[0].URL = foreign
		req.URL = foreign
		return nil
	}}
	err := createQuayHTTPClient(base, false).CheckRedirect(req, []*http.Request{previous})
	require.Error(t, err)
}

func TestQuayHistory_RemovingUserInfoCannotAuthorizeForeignOrigin(t *testing.T) {
	previous := quayHistoryRequest(t, "https://quay.example/start")
	previous.URL.User = url.UserPassword("robot", t.Name())
	req := quayHistoryRequest(t, "https://quay.example/safe")
	base := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		via[0].URL.User = nil
		req.URL.Host = "foreign.example"
		return nil
	}}
	err := createQuayHTTPClient(base, false).CheckRedirect(req, []*http.Request{previous})
	require.ErrorContains(t, err, "changed origin")
	require.NotContains(t, err.Error(), t.Name())
}

func TestQuayHistory_ClearingBasicAuthStillProtectsOrigin(t *testing.T) {
	previous := quayHistoryRequest(t, "https://quay.example/start")
	previous.SetBasicAuth("robot", t.Name())
	req := quayHistoryRequest(t, "https://quay.example/safe")
	base := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		via[0].Header = make(http.Header)
		req.URL.Host = "foreign.example"
		return nil
	}}
	err := createQuayHTTPClient(base, false).CheckRedirect(req, []*http.Request{previous})
	require.Error(t, err)
	require.NotContains(t, err.Error(), t.Name())
}

func TestQuayHistory_InsecureOptInDoesNotPermitCredentialOriginChange(t *testing.T) {
	previous := quayHistoryRequest(t, "http://quay.example/start")
	previous.Header.Set("Authorization", t.Name())
	req := quayHistoryRequest(t, "http://quay.example/safe")
	base := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		via[0].URL.Host = "foreign.example"
		req.URL.Host = "foreign.example"
		return nil
	}}
	err := createQuayHTTPClient(base, true).CheckRedirect(req, []*http.Request{previous})
	require.ErrorContains(t, err, "changed origin")
}

func TestQuayHistory_MultipleCredentialOriginsCannotBeRewritten(t *testing.T) {
	for _, credentialIndex := range []int{0, 1, 2} {
		t.Run(fmt.Sprint(credentialIndex), func(t *testing.T) {
			history := []*http.Request{
				quayHistoryRequest(t, "https://quay.example/one"),
				quayHistoryRequest(t, "https://quay.example/two"),
				quayHistoryRequest(t, "https://quay.example/three"),
			}
			history[credentialIndex].Header.Set("Authorization", t.Name())
			req := quayHistoryRequest(t, "https://quay.example/safe")
			base := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
				for _, old := range via {
					old.URL.Host = "foreign.example"
					old.Header.Del("Authorization")
				}
				req.URL.Host = "foreign.example"
				return nil
			}}
			require.Error(t, createQuayHTTPClient(base, false).CheckRedirect(req, history))
		})
	}
}

func TestQuayHistory_SafeCallbackStillChangesDestinationPath(t *testing.T) {
	previous := quayHistoryRequest(t, "https://quay.example/start")
	previous.Header.Set("Authorization", t.Name())
	req := quayHistoryRequest(t, "https://quay.example/safe")
	base := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		via[0].URL.Path = "/observed"
		req.URL.Path = "/rewritten"
		req.Header.Set("X-Application", "present")
		return nil
	}}
	require.NoError(t, createQuayHTTPClient(base, false).CheckRedirect(req, []*http.Request{previous}))
	require.Equal(t, "/rewritten", req.URL.Path)
	require.Equal(t, "present", req.Header.Get("X-Application"))
	require.Equal(t, "/observed", previous.URL.Path)
}

func TestQuayHistory_CallbackErrorsTakePrecedenceOverPostValidation(t *testing.T) {
	for _, failure := range []error{http.ErrUseLastResponse, context.Canceled, errors.New("application limit")} {
		t.Run(failure.Error(), func(t *testing.T) {
			previous := quayHistoryRequest(t, "https://quay.example/start")
			previous.Header.Set("Authorization", t.Name())
			req := quayHistoryRequest(t, "https://quay.example/safe")
			base := &http.Client{CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				req.URL = nil
				return failure
			}}
			err := createQuayHTTPClient(base, false).CheckRedirect(req, []*http.Request{previous})
			require.Same(t, failure, err)
		})
	}
}

func TestQuayHistory_CallbackCannotRemoveDestinationURL(t *testing.T) {
	previous := quayHistoryRequest(t, "https://quay.example/start")
	req := quayHistoryRequest(t, "https://quay.example/safe")
	base := &http.Client{CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		req.URL = nil
		return nil
	}}
	var err error
	require.NotPanics(t, func() {
		err = createQuayHTTPClient(base, false).CheckRedirect(req, []*http.Request{previous})
	})
	require.ErrorContains(t, err, "destination URL is missing")
}

func TestQuayHistory_UnsafeInitialRedirectDoesNotCallCallback(t *testing.T) {
	previous := quayHistoryRequest(t, "https://quay.example/start")
	previous.Header.Set("Authorization", t.Name())
	req := quayHistoryRequest(t, "https://foreign.example/")
	called := false
	base := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		called = true
		return nil
	}}
	require.Error(t, createQuayHTTPClient(base, false).CheckRedirect(req, []*http.Request{previous}))
	require.False(t, called)
}

func TestQuayHistory_DefaultRedirectLimitIsUnchanged(t *testing.T) {
	history := make([]*http.Request, 10)
	for i := range history {
		history[i] = quayHistoryRequest(t, "https://quay.example/start")
	}
	req := quayHistoryRequest(t, "https://quay.example/safe")
	client := createQuayHTTPClient(nil, false)
	require.NoError(t, client.CheckRedirect(req, history[:9]))
	require.ErrorContains(t, client.CheckRedirect(req, history), "stopped after 10 redirects")
}

func TestQuayHistory_CustomLimitStillReplacesDefaultLimit(t *testing.T) {
	history := make([]*http.Request, 11)
	for i := range history {
		history[i] = quayHistoryRequest(t, "https://quay.example/start")
	}
	base := &http.Client{CheckRedirect: func(_ *http.Request, via []*http.Request) error {
		if len(via) >= 11 {
			return io.EOF
		}
		return nil
	}}
	client := createQuayHTTPClient(base, false)
	req := quayHistoryRequest(t, "https://quay.example/safe")
	require.NoError(t, client.CheckRedirect(req, history[:10]))
	require.ErrorIs(t, client.CheckRedirect(req, history), io.EOF)
}

func TestQuayHistory_ClientConfigurationAndOriginalCallbackAreNotModified(t *testing.T) {
	transport := &http.Transport{MaxConnsPerHost: 1}
	base := &http.Client{Transport: transport, Timeout: 17 * time.Second}
	called := 0
	base.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		called++
		return nil
	}
	client := createQuayHTTPClient(base, false)
	require.NotSame(t, base, client)
	require.Same(t, transport, client.Transport)
	require.Equal(t, base.Timeout, client.Timeout)
	req := quayHistoryRequest(t, "https://foreign.example/")
	previous := quayHistoryRequest(t, "https://quay.example/start")
	previous.Header.Set("Authorization", t.Name())
	require.NoError(t, base.CheckRedirect(req, []*http.Request{previous}))
	require.Error(t, client.CheckRedirect(req, []*http.Request{previous}))
	require.Equal(t, 1, called)
}

func TestQuayHistory_AnonymousHTTPSOriginChangeStillWorks(t *testing.T) {
	previous := quayHistoryRequest(t, "https://quay.example/start")
	req := quayHistoryRequest(t, "https://quay.example/safe")
	base := &http.Client{CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		req.URL.Host = "cdn.example"
		return nil
	}}
	require.NoError(t, createQuayHTTPClient(base, false).CheckRedirect(req, []*http.Request{previous}))
	require.Equal(t, "cdn.example", req.URL.Host)
}

func TestQuayHistory_EquivalentOriginFormsRemainAllowed(t *testing.T) {
	for _, destination := range []string{"https://QUAY.example/safe", "https://quay.example:443/safe"} {
		t.Run(destination, func(t *testing.T) {
			previous := quayHistoryRequest(t, "https://quay.example/start")
			previous.Header.Set("Authorization", t.Name())
			req := quayHistoryRequest(t, "https://quay.example/safe")
			base := &http.Client{CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				req.URL = quayHistoryRequest(t, destination).URL
				return nil
			}}
			require.NoError(t, createQuayHTTPClient(base, false).CheckRedirect(req, []*http.Request{previous}))
		})
	}
}

func TestQuayHistory_CallbackMutationCannotBypassAnyRedirectCode(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var hits atomic.Int32
			foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer foreign.Close()
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/safe", code)
			}))
			defer origin.Close()
			base := foreign.Client()
			base.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				destination := quayHistoryRequest(t, foreign.URL).URL
				*via[0].URL = *destination
				via[0].Header.Del("Authorization")
				req.URL = destination
				return nil
			}
			w := &quayAPIWrapper{baseURL: origin.URL, username: "robot", password: t.Name(), httpClient: createQuayHTTPClient(base, false)}
			_, err := w.DoRequest(context.Background(), http.MethodGet, "/start")
			require.Error(t, err)
			require.Zero(t, hits.Load())
		})
	}
}

func TestQuayHistory_ChallengeTokenRequestUsesProtectedHistory(t *testing.T) {
	var foreignHits atomic.Int32
	foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		foreignHits.Add(1)
		_, _ = io.WriteString(w, `{"token":"unused"}`)
	}))
	defer foreign.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/safe-token", http.StatusFound)
	}))
	defer origin.Close()
	base := foreign.Client()
	base.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		destination := quayHistoryRequest(t, foreign.URL).URL
		via[0].URL = destination
		req.URL = destination
		return nil
	}
	w := &quayAPIWrapper{baseURL: origin.URL, username: "robot", password: t.Name(), httpClient: base}
	_, err := w.fetchChallengeToken(context.Background(), origin.URL+"/token", "quay", "repository:team/app:pull")
	require.Error(t, err)
	require.Zero(t, foreignHits.Load())
}

func TestQuayHistory_SameOriginTLSRequestStillReturnsBodyAndHeaders(t *testing.T) {
	var hits atomic.Int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		require.Equal(t, "Bearer "+t.Name(), r.Header.Get("Authorization"))
		w.Header().Set("X-Registry", "local")
		_, _ = io.WriteString(w, `{"status":"scanned"}`)
	}))
	defer origin.Close()
	w := &quayAPIWrapper{baseURL: origin.URL, token: t.Name(), httpClient: createQuayHTTPClient(origin.Client(), false)}
	body, headers, err := w.DoRequestWithHeaders(context.Background(), http.MethodGet, "/start", nil)
	require.NoError(t, err)
	require.JSONEq(t, `{"status":"scanned"}`, string(body))
	require.Equal(t, "local", headers.Get("X-Registry"))
	require.Equal(t, int32(2), hits.Load())
}

func TestQuayHistory_ContextCancellationStillStopsRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var hits atomic.Int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()
	w := &quayAPIWrapper{baseURL: origin.URL, token: t.Name(), httpClient: createQuayHTTPClient(origin.Client(), false)}
	_, err := w.DoRequest(ctx, http.MethodGet, "/start")
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, hits.Load())
}

func TestQuayHistory_HistoryEditsDoNotBypassDowngradeGuard(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		previous := quayHistoryRequest(t, "https://quay.example/start")
		if authenticated {
			previous.Header.Set("Authorization", t.Name())
		}
		req := quayHistoryRequest(t, "https://quay.example/safe")
		base := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
			via[0].URL.Scheme = "http"
			req.URL.Scheme = "http"
			return nil
		}}
		err := createQuayHTTPClient(base, false).CheckRedirect(req, []*http.Request{previous})
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), "downgrade"))
	}
}

func TestQuayHistory_RealHTTPDowngradeCannotRewriteHTTPSHistory(t *testing.T) {
	var hits atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer foreign.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/safe", http.StatusFound)
	}))
	defer origin.Close()
	base := origin.Client()
	base.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		destination := quayHistoryRequest(t, foreign.URL).URL
		*via[0].URL = *destination
		via[0].Header.Del("Authorization")
		req.URL = destination
		return nil
	}
	w := &quayAPIWrapper{baseURL: origin.URL, token: t.Name(), httpClient: createQuayHTTPClient(base, false)}
	_, err := w.DoRequest(context.Background(), http.MethodGet, "/start")
	require.ErrorContains(t, err, "downgrade")
	require.Zero(t, hits.Load())
}

func TestQuayHistory_CachedV2TokenCannotEscapeThroughCallback(t *testing.T) {
	var hits atomic.Int32
	foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer foreign.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/safe", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	base := foreign.Client()
	base.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		destination := quayHistoryRequest(t, foreign.URL).URL
		via[0].URL = destination
		via[0].Header.Del("Authorization")
		req.URL = destination
		return nil
	}
	w := &quayAPIWrapper{baseURL: origin.URL, httpClient: createQuayHTTPClient(base, false)}
	w.setCachedToken("repository:team/app:pull", t.Name())
	_, err := w.DoRequest(context.Background(), http.MethodGet, "/v2/team/app/manifests/sha256:123")
	require.Error(t, err)
	require.Zero(t, hits.Load())
}

func TestQuayHistory_CallbackCannotReplaceURLWithNilInsideHistory(t *testing.T) {
	previous := quayHistoryRequest(t, "https://quay.example/start")
	previous.Header.Set("Authorization", t.Name())
	req := quayHistoryRequest(t, "https://quay.example/safe")
	base := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		via[0].URL = nil
		req.URL.Host = "foreign.example"
		return nil
	}}
	var err error
	require.NotPanics(t, func() {
		err = createQuayHTTPClient(base, false).CheckRedirect(req, []*http.Request{previous})
	})
	require.ErrorContains(t, err, "changed origin")
}

func TestQuayHistory_IPv6PortMutationDoesNotRedefineOrigin(t *testing.T) {
	previous := quayHistoryRequest(t, "https://[::1]:443/start")
	previous.Header.Set("Authorization", t.Name())
	req := quayHistoryRequest(t, "https://[::1]/safe")
	base := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		via[0].URL.Host = "[::1]:8443"
		req.URL.Host = "[::1]:8443"
		return nil
	}}
	err := createQuayHTTPClient(base, false).CheckRedirect(req, []*http.Request{previous})
	require.ErrorContains(t, err, "changed origin")
	require.NotContains(t, err.Error(), t.Name())
}

func TestQuayHistory_SafeFirstHopCannotEraseTrustForLaterRedirect(t *testing.T) {
	previous := quayHistoryRequest(t, "https://quay.example/start")
	previous.Header.Set("Authorization", t.Name())
	req := quayHistoryRequest(t, "https://quay.example/safe")
	base := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		via[0].Header.Del("Authorization")
		req.Header.Del("Authorization")
		return nil
	}}
	err := createQuayHTTPClient(base, false).CheckRedirect(req, []*http.Request{previous})
	require.ErrorContains(t, err, "modified trusted request history")
}
