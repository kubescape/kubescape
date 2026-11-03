package listener

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-logr/stdr"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/httphandler/docs"
	handlerequestsv1 "github.com/kubescape/kubescape/v4/httphandler/handlerequests/v1"
	"github.com/kubescape/storage/pkg/apiauth"
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
		switch r.Method {
		case http.MethodDelete:
			attrs.Verb = "delete"
		case http.MethodGet, http.MethodHead:
			// GetResults (also served for HEAD) removes the result after
			// returning it unless keep=true, so a removing read needs delete.
			if !handlerequestsv1.ResultsRequestKeepsResults(r.URL.Query()) {
				attrs.Verb = "delete"
			}
		}
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
	return apiauth.New(ctx, cfg)
}
