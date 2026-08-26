package notification

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failingDoer struct{}

func (failingDoer) Do(*http.Request) (*http.Response, error) {
	return nil, &url.Error{Op: "Post", URL: "https://example.com/secret/path?token=secret", Err: errors.New("connection refused")}
}

type staticDoer struct {
	response *http.Response
}

func (d staticDoer) Do(*http.Request) (*http.Response, error) { return d.response, nil }

type trackingReadCloser struct {
	reader bytes.Reader
	read   int
	closed bool
}

func newTrackingReadCloser(body []byte) *trackingReadCloser {
	return &trackingReadCloser{reader: *bytes.NewReader(body)}
}

func (r *trackingReadCloser) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.read += n
	return n, err
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

func TestSendPostsJSON(t *testing.T) {
	var method, contentType string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, contentType = r.Method, r.Header.Get("Content-Type")
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	payload := []byte(`{"summary":"ok"}`)
	require.NoError(t, Send(context.Background(), NewClient(time.Second), srv.URL+"/secret?token=123", payload))
	assert.Equal(t, http.MethodPost, method)
	assert.Equal(t, "application/json", contentType)
	assert.Equal(t, payload, body)
}

func TestSendRejectsUnsafeEndpointsWithoutSecrets(t *testing.T) {
	for _, endpoint := range []string{
		"ftp://example.com/hook", "https:///hook", "https://user:secret@example.com/hook", "https://example.com/hook#fragment",
	} {
		t.Run(endpoint, func(t *testing.T) {
			err := Send(context.Background(), NewClient(time.Second), endpoint, []byte(`{}`))
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "secret")
			assert.NotContains(t, err.Error(), "/hook")
		})
	}
}

func TestSendFailsForRedirectAndNon2xx(t *testing.T) {
	redirectTargetCalled := make(chan struct{}, 1)
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectTargetCalled <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer redirectTarget.Close()

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL+"/secret", http.StatusFound)
	}))
	defer redirect.Close()
	err := Send(context.Background(), NewClient(time.Second), redirect.URL+"/token", []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "302")
	assert.NotContains(t, err.Error(), "/token")
	select {
	case <-redirectTargetCalled:
		t.Fatal("notification client followed redirect")
	default:
	}

	failure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("secret response"))
	}))
	defer failure.Close()
	err = Send(context.Background(), NewClient(time.Second), failure.URL+"/token", []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
	assert.NotContains(t, err.Error(), "secret response")
}

func TestSendAcceptsEvery2xxAndClosesBoundedResponse(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusNoContent, 299} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			body := newTrackingReadCloser(bytes.Repeat([]byte("x"), maxResponseBody+1))
			err := Send(context.Background(), staticDoer{response: &http.Response{
				StatusCode: status,
				Body:       body,
			}}, "https://example.com/webhook?token=secret", []byte(`{}`))
			require.NoError(t, err)
			assert.True(t, body.closed)
			assert.Equal(t, maxResponseBody, body.read)
		})
	}
}

func TestSafeTarget(t *testing.T) {
	assert.Equal(t, "https://example.com:8443", SafeTarget("https://example.com:8443/path?token=secret"))
	assert.Equal(t, "invalid endpoint", SafeTarget("%%%"))
	assert.False(t, strings.Contains(SafeTarget("https://example.com/a?b=c"), "?"))
}

func TestSendRedactsTransportURL(t *testing.T) {
	err := Send(context.Background(), failingDoer{}, "https://example.com/secret/path?token=secret", []byte(`{}`))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "secret")
	assert.NotContains(t, err.Error(), "/path")
	assert.Contains(t, err.Error(), "https://example.com")
}

func TestSendHonorsContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Send(ctx, NewClient(time.Second), srv.URL+"/secret", []byte(`{}`))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "/secret")
}

func TestSendHonorsClientTimeout(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseServer := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-releaseServer
	}))
	defer func() {
		close(releaseServer)
		srv.Close()
	}()

	started := time.Now()
	err := Send(context.Background(), NewClient(20*time.Millisecond), srv.URL+"/secret", []byte(`{}`))
	require.Error(t, err)
	<-requestStarted
	assert.Less(t, time.Since(started), time.Second)
	assert.NotContains(t, err.Error(), "/secret")
}
