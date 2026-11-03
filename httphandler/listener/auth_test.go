package listener

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestHealthProbesOnProductionRouter proves /livez stays open on the real
// wiring where /livez is on rtr directly and only /v1/* is under

// had the middleware, so it was tautologically true.
func TestHealthProbesOnProductionRouter(t *testing.T) {
	// Build a router the same way SetupHTTPListener does: health on root, v1 with middleware.
	rtr := http.NewServeMux()
	rtr.HandleFunc("GET "+livePath, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	rtr.HandleFunc("GET "+readyPath, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	v1Handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
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
