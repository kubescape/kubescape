package listener

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/kubescape/storage/pkg/apiauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
)

const testNamespace = "kubescape"

// fakeRBACServer is a fake kube-apiserver. It answers TokenReviews (the bearer
// token is the user name) and SubjectAccessReviews from grants: user -> verbs
// on scanresults in testNamespace. It records every SubjectAccessReview. The
// apiserver authn/authz factories post through RESTClient(), which the
// client-go fake clientset leaves nil, so an HTTP fake is needed.
func fakeRBACServer(t *testing.T, grants map[string][]string) (kubernetes.Interface, func() []authorizationv1.ResourceAttributes) {
	t.Helper()
	var mu sync.Mutex
	var seen []authorizationv1.ResourceAttributes
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", func(w http.ResponseWriter, r *http.Request) {
		var ssar authorizationv1.SelfSubjectAccessReview
		_ = json.NewDecoder(r.Body).Decode(&ssar)
		ssar.TypeMeta = metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}
		ssar.Status.Allowed = true
		writeJSON(w, &ssar)
	})
	mux.HandleFunc("/apis/authentication.k8s.io/v1/tokenreviews", func(w http.ResponseWriter, r *http.Request) {
		var tr authenticationv1.TokenReview
		_ = json.NewDecoder(r.Body).Decode(&tr)
		tr.TypeMeta = metav1.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview"}
		_, known := grants[tr.Spec.Token]
		tr.Status = authenticationv1.TokenReviewStatus{
			Authenticated: known,
			Audiences:     []string{defaultAudience},
			User:          authenticationv1.UserInfo{Username: tr.Spec.Token},
		}
		writeJSON(w, &tr)
	})
	mux.HandleFunc("/apis/authorization.k8s.io/v1/subjectaccessreviews", func(w http.ResponseWriter, r *http.Request) {
		var sar authorizationv1.SubjectAccessReview
		_ = json.NewDecoder(r.Body).Decode(&sar)
		sar.TypeMeta = metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"}
		ra := sar.Spec.ResourceAttributes
		allowed := false
		if ra != nil {
			mu.Lock()
			seen = append(seen, *ra)
			mu.Unlock()
			if ra.Group == apiGroup && ra.Resource == resourceScanResult && ra.Namespace == testNamespace {
				allowed = slices.Contains(grants[sar.Spec.User], ra.Verb)
			}
		}
		sar.Status = authorizationv1.SubjectAccessReviewStatus{Allowed: allowed}
		writeJSON(w, &sar)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client, err := kubernetes.NewForConfig(&restclient.Config{
		Host:          srv.URL,
		ContentConfig: restclient.ContentConfig{ContentType: "application/json"},
	})
	require.NoError(t, err)
	return client, func() []authorizationv1.ResourceAttributes {
		mu.Lock()
		defer mu.Unlock()
		out := slices.Clone(seen)
		seen = nil
		return out
	}
}

func newTestAuth(t *testing.T, grants map[string][]string) (func(http.Handler) http.Handler, func() []authorizationv1.ResourceAttributes) {
	t.Helper()
	t.Setenv(apiauth.DisabledEnv, "")
	client, seen := fakeRBACServer(t, grants)
	auth, err := newAPIAuth(t.Context(), apiauth.Config{
		Client:    client,
		Audience:  defaultAudience,
		Namespace: testNamespace,
		Route:     apiAuthRoute,
	})
	require.NoError(t, err)
	return auth, seen
}

// serveAs sends method target with user's token through auth and reports the
// status and whether the wrapped handler ran.
func serveAs(auth func(http.Handler) http.Handler, user, method, target string) (*httptest.ResponseRecorder, bool) {
	reached := false
	h := auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("Authorization", "Bearer "+user)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, reached
}

func assertForbidden(t *testing.T, rec *httptest.ResponseRecorder, reached bool) {
	t.Helper()
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, reached, "a forbidden request must not reach the handler")
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var body struct{ Error, Reason string }
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "forbidden", body.Error)
}

func TestResultsGuard_RemovingGetNeedsGetAndDelete(t *testing.T) {
	auth, _ := newTestAuth(t, map[string][]string{
		"get-only":    {"get"},
		"delete-only": {"delete"},
		"both":        {"get", "delete"},
	})

	t.Run("get-only principal cannot remove a result", func(t *testing.T) {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			rec, reached := serveAs(auth, "get-only", method, "/v1/results?id=abc")
			if method == http.MethodHead {
				assert.Equal(t, http.StatusForbidden, rec.Code)
				assert.False(t, reached)
				continue
			}
			assertForbidden(t, rec, reached)
		}
	})
	t.Run("get-only principal can read with keep=true", func(t *testing.T) {
		rec, reached := serveAs(auth, "get-only", http.MethodGet, "/v1/results?id=abc&keep=true")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, reached)
	})
	t.Run("delete-only principal cannot read a result", func(t *testing.T) {
		rec, reached := serveAs(auth, "delete-only", http.MethodGet, "/v1/results?id=abc")
		assertForbidden(t, rec, reached)
		rec, reached = serveAs(auth, "delete-only", http.MethodGet, "/v1/results?id=abc&keep=true")
		assertForbidden(t, rec, reached)
	})
	t.Run("delete-only principal can DELETE", func(t *testing.T) {
		rec, reached := serveAs(auth, "delete-only", http.MethodDelete, "/v1/results?id=abc")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, reached)
	})
	t.Run("principal with get and delete can remove a result", func(t *testing.T) {
		rec, reached := serveAs(auth, "both", http.MethodGet, "/v1/results?id=abc")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, reached)
	})
}

// The guard asks for delete with the same attributes the middleware uses for
// get, and only for a result-removing GET.
func TestResultsGuard_ChecksDeleteOnlyForRemovingGet(t *testing.T) {
	auth, seen := newTestAuth(t, map[string][]string{"both": {"get", "delete"}})

	_, reached := serveAs(auth, "both", http.MethodGet, "/v1/results?id=abc&keep=true")
	require.True(t, reached)
	sars := seen()
	require.Len(t, sars, 1)
	assert.Equal(t, "get", sars[0].Verb)

	// A fresh authorizer, so the cached get answer does not hide the SAR.
	auth, seen = newTestAuth(t, map[string][]string{"both": {"get", "delete"}})
	_, reached = serveAs(auth, "both", http.MethodGet, "/v1/results?id=abc")
	require.True(t, reached)
	sars = seen()
	require.Len(t, sars, 2)
	want := authorizationv1.ResourceAttributes{Namespace: testNamespace, Verb: "get", Group: apiGroup, Resource: resourceScanResult}
	assert.Equal(t, want, sars[0])
	want.Verb = "delete"
	assert.Equal(t, want, sars[1], "the delete check must use the middleware's attributes")
}

func TestResultsGuard_DisabledIsPassThrough(t *testing.T) {
	t.Setenv(apiauth.DisabledEnv, "true")
	auth, err := NewAPIAuth(t.Context())
	require.NoError(t, err)
	reached := false
	h := auth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/results?id=abc", nil))
	assert.True(t, reached)
}

func TestResultsGuard_NoUserIsForbidden(t *testing.T) {
	guard := resultsDeleteGuard(nil, testNamespace, apiauth.Config{}.Logger)
	reached := false
	h := guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/results?id=abc", nil))
	assertForbidden(t, rec, reached)
}
