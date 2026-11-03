package listener

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-logr/logr"
	"github.com/go-logr/stdr"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/httphandler/docs"
	handlerequestsv1 "github.com/kubescape/kubescape/v4/httphandler/handlerequests/v1"
	"github.com/kubescape/storage/pkg/apiauth"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

const (
	apiGroup           = "kubescape.io"
	resourceScans      = "scans"
	resourceScanResult = "scanresults"

	podNamespaceEnv = "POD_NAMESPACE"
	audienceEnv     = "KS_API_AUDIENCE"
	defaultAudience = "kubescape.io"
)

// apiAuthRoute maps a request to the RBAC attributes it needs. The second
// result is false for routes that are open: probes, the OpenAPI UI and metrics.
// Any method on a protected path is protected.
func apiAuthRoute(r *http.Request) (apiauth.Attributes, bool) {
	path := r.URL.Path
	if path == livePath || path == readyPath || strings.HasPrefix(path, docs.OpenAPIV2Prefix) {
		return apiauth.Attributes{}, false
	}
	if path == v1PathPrefix+v1PrometheusMetricsPath {
		return apiauth.Attributes{}, false
	}
	if !strings.HasPrefix(path, v1PathPrefix+"/") {
		return apiauth.Attributes{}, false
	}
	attrs := apiauth.Attributes{Group: apiGroup, Resource: resourceScans, Verb: "get"}
	switch path {
	case v1PathPrefix + v1ScanPath:
		switch r.Method {
		case http.MethodPost:
			attrs.Verb = "create"
		case http.MethodDelete:
			attrs.Verb = "delete"
		}
	case v1PathPrefix + v1ResultsPath:
		attrs.Resource = resourceScanResult
		if r.Method == http.MethodDelete {
			attrs.Verb = "delete"
		}
		// A GET that removes the result also needs delete; resultsDeleteGuard
		// checks that on top of get.
	}
	return attrs, true
}

// NewAPIAuth builds the /v1/* authentication and authorization middleware.
// With KS_API_AUTH_DISABLED=true it returns a pass-through.
func NewAPIAuth(ctx context.Context) (func(http.Handler) http.Handler, error) {
	cfg := apiauth.Config{Route: apiAuthRoute, Logger: stdr.New(log.New(os.Stderr, "apiauth: ", log.LstdFlags))}
	if os.Getenv(apiauth.DisabledEnv) == "true" {
		return apiauth.New(ctx, cfg)
	}
	cfg.Namespace = os.Getenv(podNamespaceEnv)
	if cfg.Namespace == "" {
		return nil, errors.New("POD_NAMESPACE must be set for API auth (or set KS_API_AUTH_DISABLED=true)")
	}
	cfg.Audience = os.Getenv(audienceEnv)
	if cfg.Audience == "" {
		cfg.Audience = defaultAudience
	}
	cfg.Client = k8sinterface.NewKubernetesApi().KubernetesClient
	return newAPIAuth(ctx, cfg)
}

// newAPIAuth composes the apiauth middleware with resultsDeleteGuard, so a
// GET /v1/results that removes the result is checked for both get (by the
// middleware) and delete (by the guard).
func newAPIAuth(ctx context.Context, cfg apiauth.Config) (func(http.Handler) http.Handler, error) {
	mw, err := apiauth.New(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if os.Getenv(apiauth.DisabledEnv) == "true" {
		return mw, nil
	}
	authz, err := apiauth.NewAuthorizer(cfg.Client.AuthorizationV1())
	if err != nil {
		return nil, err
	}
	guard := resultsDeleteGuard(authz, cfg.Namespace, cfg.Logger)
	return func(next http.Handler) http.Handler { return mw(guard(next)) }, nil
}

// removesResults reports whether r is a GET or HEAD /v1/results that deletes
// the result after returning it (no keep=true).
func removesResults(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		r.URL.Path == v1PathPrefix+v1ResultsPath &&
		!handlerequestsv1.ResultsRequestKeepsResults(r.URL.Query())
}

type authErrorResponse struct {
	Error  string `json:"error"`
	Reason string `json:"reason"`
}

// writeAuthError writes the same JSON error body as apiauth.
func writeAuthError(w http.ResponseWriter, code int, errStr, reason string) {
	body, _ := json.Marshal(authErrorResponse{Error: errStr, Reason: reason})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// resultsDeleteGuard runs after the apiauth middleware, which has already
// authorized get on scanresults. For a GET /v1/results that removes the
// result, it also requires delete on scanresults for the same user, so
// neither a get-only nor a delete-only principal can consume a result.
func resultsDeleteGuard(authz authorizer.Authorizer, namespace string, logger logr.Logger) func(http.Handler) http.Handler {
	if logger.GetSink() == nil {
		logger = logr.Discard()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !removesResults(r) {
				next.ServeHTTP(w, r)
				return
			}
			info, ok := apiauth.UserFrom(r.Context())
			if !ok || info == nil {
				logger.Info("API request denied", "verb", "delete", "resource", resourceScanResult,
					"outcome", "forbidden", "reason", "no authenticated user", "path", r.URL.Path)
				writeAuthError(w, http.StatusForbidden, "forbidden", "no authenticated user")
				return
			}
			decision, reason, err := authz.Authorize(r.Context(), authorizer.AttributesRecord{
				User:            info,
				Verb:            "delete",
				APIGroup:        apiGroup,
				Resource:        resourceScanResult,
				Namespace:       namespace,
				ResourceRequest: true,
			})
			if err != nil {
				logger.Error(err, "API request denied: SubjectAccessReview failed", "user", info.GetName(),
					"verb", "delete", "resource", resourceScanResult, "outcome", "unavailable")
				writeAuthError(w, http.StatusServiceUnavailable, "unavailable", "authentication backend error")
				return
			}
			if decision != authorizer.DecisionAllow {
				logger.Info("API request denied", "user", info.GetName(), "verb", "delete", "resource", resourceScanResult,
					"outcome", "forbidden", "reason", reason, "path", r.URL.Path)
				writeAuthError(w, http.StatusForbidden, "forbidden", reason)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
