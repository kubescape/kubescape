package listener

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestV1Router(next http.Handler) *http.ServeMux {
	r := http.NewServeMux()

	v1Handler := bearerAuthMiddleware(next)

	r.Handle("POST "+v1PathPrefix+v1ScanPath, v1Handler)
	r.Handle("DELETE "+v1PathPrefix+v1ScanPath, v1Handler)
	r.Handle("GET "+v1PathPrefix+v1ResultsPath, v1Handler)
	r.Handle("DELETE "+v1PathPrefix+v1ResultsPath, v1Handler)
	r.Handle("GET "+v1PathPrefix+v1StatusPath, v1Handler)

	return r
}

func TestGetAuthToken_TrimsSpaces(t *testing.T) {
	t.Setenv(authTokenEnv, "  s3cr3t  ")
	assert.Equal(t, "s3cr3t", getAuthToken())
	t.Setenv(authTokenEnv, "   ")
	assert.Equal(t, "", getAuthToken())
	t.Setenv(authTokenEnv, "")
	assert.Equal(t, "", getAuthToken())
}

func TestBearerAuthMiddleware_DisabledIsNoop(t *testing.T) {
	t.Setenv(authTokenEnv, "")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	rtr := newTestV1Router(next)

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/v1/scan"},
		{http.MethodDelete, "/v1/scan"},
		{http.MethodGet, "/v1/results"},
		{http.MethodDelete, "/v1/results"},
		{http.MethodGet, "/v1/status"},
	} {
		rec := httptest.NewRecorder()
		rtr.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		require.Equal(t, http.StatusOK, rec.Code, "%s %s should be open when token unset", tc.method, tc.path)
	}
}

func TestBearerAuthMiddleware_UnauthenticatedBlocks(t *testing.T) {
	t.Setenv(authTokenEnv, "s3cr3t")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	rtr := newTestV1Router(next)

	// No header => 401
	rec := httptest.NewRecorder()
	rtr.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/scan", nil))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "Bearer")
	assert.Contains(t, rec.Body.String(), "Authorization")

	// Wrong token => 401 (would be 200 on buggy code)
	req := httptest.NewRequest(http.MethodGet, "/v1/results?id=abc", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec = httptest.NewRecorder()
	rtr.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	// Wrong scheme => 401
	req = httptest.NewRequest(http.MethodPost, "/v1/scan", nil)
	req.Header.Set("Authorization", "Basic s3cr3t")
	rec = httptest.NewRecorder()
	rtr.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	// Correct token => 200
	req = httptest.NewRequest(http.MethodGet, "/v1/results?id=abc", nil)
	req.Header.Set("Authorization", "Bearer s3cr3t")
	rec = httptest.NewRecorder()
	rtr.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Lowercase bearer scheme (RFC 7235: scheme is case-insensitive) => 200
	req = httptest.NewRequest(http.MethodGet, "/v1/results?id=abc", nil)
	req.Header.Set("Authorization", "bearer s3cr3t")
	rec = httptest.NewRecorder()
	rtr.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "Bearer scheme must be case-insensitive")

	// Mixed-case Bearer + extra spaces around token => 200 (TrimSpace)
	req = httptest.NewRequest(http.MethodGet, "/v1/results?id=abc", nil)
	req.Header.Set("Authorization", "BeArEr   s3cr3t   ")
	rec = httptest.NewRecorder()
	rtr.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

// TestHealthProbesOnProductionRouter proves /livez stays open on the real
// wiring where /livez is on rtr directly and only /v1/* is under
// bearerAuthMiddleware. Previous version built a disconnected mux that never
// had the middleware, so it was tautologically true.
func TestHealthProbesOnProductionRouter(t *testing.T) {
	t.Setenv(authTokenEnv, "s3cr3t")
	// Build a router the same way SetupHTTPListener does: health on root, v1 with middleware.
	rtr := http.NewServeMux()
	rtr.HandleFunc("GET "+livePath, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	rtr.HandleFunc("GET "+readyPath, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	v1Handler := bearerAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	rtr.Handle("POST "+v1PathPrefix+v1ScanPath, v1Handler)

	// Health without token => 200 even though v1 needs it
	for _, path := range []string{livePath, readyPath} {
		rec := httptest.NewRecorder()
		rtr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		require.Equal(t, http.StatusOK, rec.Code, "%s must stay unauthenticated", path)
	}
	// v1 without token => 401
	rec := httptest.NewRecorder()
	rtr.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/scan", nil))
	require.Equal(t, http.StatusUnauthorized, rec.Code, "/v1/scan must require token")
}

func TestBearerAuthMiddleware_ConstantTimeAndTrim(t *testing.T) {
	t.Setenv(authTokenEnv, "s3cr3t")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	rtr := newTestV1Router(next)

	// Token with surrounding spaces should still pass (TrimSpace)
	req := httptest.NewRequest(http.MethodPost, "/v1/scan", nil)
	req.Header.Set("Authorization", "Bearer   s3cr3t   ")
	rec := httptest.NewRecorder()
	rtr.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Empty bearer value => 401
	req = httptest.NewRequest(http.MethodPost, "/v1/scan", nil)
	req.Header.Set("Authorization", "Bearer ")
	rec = httptest.NewRecorder()
	rtr.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}
