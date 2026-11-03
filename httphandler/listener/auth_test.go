package listener

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kubescape/kubescape/v4/httphandler/docs"
	handlerequestsv1 "github.com/kubescape/kubescape/v4/httphandler/handlerequests/v1"
	"github.com/stretchr/testify/require"
)

// TestHealthProbesOnProductionRouter proves /livez and /readyz stay reachable
// through the production router (newRouter) even when the auth middleware
// rejects every request it wraps.
func TestHealthProbesOnProductionRouter(t *testing.T) {
	deny := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
	}
	rtr := newRouter(handlerequestsv1.NewHTTPHandler(true), docs.NewOpenAPIUIHandler(), deny)

	for _, path := range []string{livePath, readyPath} {
		rec := httptest.NewRecorder()
		rtr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		require.NotEqual(t, http.StatusUnauthorized, rec.Code, "%s must stay unauthenticated", path)
	}
	rec := httptest.NewRecorder()
	rtr.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/scan", nil))
	require.Equal(t, http.StatusUnauthorized, rec.Code, "/v1/scan must be behind auth")
}
