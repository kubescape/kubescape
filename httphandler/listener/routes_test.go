package listener

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kubescape/kubescape/v4/httphandler/docs"
	handlerequestsv1 "github.com/kubescape/kubescape/v4/httphandler/handlerequests/v1"
	"github.com/kubescape/storage/pkg/apiauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApiAuthRoute_Table(t *testing.T) {
	tests := []struct {
		method, path string
		protected    bool
		want         apiauth.Attributes
	}{
		{http.MethodPost, "/v1/scan", true, apiauth.Attributes{Group: "kubescape.io", Resource: "scans", Verb: "create"}},
		{http.MethodDelete, "/v1/scan", true, apiauth.Attributes{Group: "kubescape.io", Resource: "scans", Verb: "delete"}},
		{http.MethodGet, "/v1/scan", true, apiauth.Attributes{Group: "kubescape.io", Resource: "scans", Verb: "get"}},
		{http.MethodGet, "/v1/status", true, apiauth.Attributes{Group: "kubescape.io", Resource: "scans", Verb: "get"}},
		{http.MethodPost, "/v1/status", true, apiauth.Attributes{Group: "kubescape.io", Resource: "scans", Verb: "get"}},
		{http.MethodGet, "/v1/results", true, apiauth.Attributes{Group: "kubescape.io", Resource: "scanresults", Verb: "get"}},
		{http.MethodDelete, "/v1/results", true, apiauth.Attributes{Group: "kubescape.io", Resource: "scanresults", Verb: "delete"}},
		{http.MethodPost, "/v1/results", true, apiauth.Attributes{Group: "kubescape.io", Resource: "scanresults", Verb: "get"}},
		{http.MethodGet, "/v1/unknown", true, apiauth.Attributes{Group: "kubescape.io", Resource: "scans", Verb: "get"}},
		{http.MethodGet, "/v1/metrics", false, apiauth.Attributes{}},
		{http.MethodGet, "/livez", false, apiauth.Attributes{}},
		{http.MethodGet, "/readyz", false, apiauth.Attributes{}},
		{http.MethodGet, docs.OpenAPIV2Prefix, false, apiauth.Attributes{}},
		{http.MethodGet, docs.OpenAPIV2Prefix + "swagger.yaml", false, apiauth.Attributes{}},
	}
	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			got, ok := apiAuthRoute(httptest.NewRequest(tc.method, tc.path, nil))
			assert.Equal(t, tc.protected, ok)
			if tc.protected {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestNewAPIAuth_RequiresPodNamespace(t *testing.T) {
	t.Setenv(apiauth.DisabledEnv, "")
	t.Setenv("POD_NAMESPACE", "")
	mw, err := NewAPIAuth(t.Context())
	require.Error(t, err)
	assert.Nil(t, mw)
	assert.Contains(t, err.Error(), "POD_NAMESPACE must be set")
}

func TestRouter_MetricsAndProbesOpen_V1Protected(t *testing.T) {
	deny := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "denied", http.StatusUnauthorized)
		})
	}
	h := handlerequestsv1.NewHTTPHandler(true)
	rtr := newRouter(h, docs.NewOpenAPIUIHandler(), deny)

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, livePath},
		{http.MethodGet, readyPath},
		{http.MethodGet, "/v1/metrics"},
		{http.MethodGet, docs.OpenAPIV2Prefix},
	} {
		rec := httptest.NewRecorder()
		rtr.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		assert.NotEqual(t, http.StatusUnauthorized, rec.Code, "%s %s must be open", tc.method, tc.path)
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/v1/scan"},
		{http.MethodDelete, "/v1/scan"},
		{http.MethodGet, "/v1/status"},
		{http.MethodGet, "/v1/results"},
		{http.MethodDelete, "/v1/results"},
	} {
		rec := httptest.NewRecorder()
		rtr.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		assert.Equal(t, http.StatusUnauthorized, rec.Code, "%s %s must be protected", tc.method, tc.path)
	}
}
