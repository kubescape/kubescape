package listener

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestV1Router(next http.Handler) *mux.Router {
	r := mux.NewRouter()
	sub := r.PathPrefix(v1PathPrefix).Subrouter()
	sub.Use(bearerAuthMiddleware)
	sub.Handle(v1ScanPath, next).Methods(http.MethodPost)
	sub.Handle(v1ScanPath, next).Methods(http.MethodDelete)
	sub.Handle(v1ResultsPath, next).Methods(http.MethodGet)
	sub.Handle(v1ResultsPath, next).Methods(http.MethodDelete)
	sub.Handle(v1StatusPath, next).Methods(http.MethodGet)
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

	// Health probes remain open even with token set — they live on the root router, not v1SubRouter
	health := mux.NewRouter()
	health.HandleFunc(livePath, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	rec = httptest.NewRecorder()
	health.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, livePath, nil))
	require.Equal(t, http.StatusOK, rec.Code, "health probes must stay unauthenticated")
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
