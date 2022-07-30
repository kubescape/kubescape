package docs

import (
	"bytes"
	"fmt"
	"net/http"

	_ "embed"

	logger "github.com/dwertent/go-logger"
	"github.com/go-openapi/runtime/middleware"
)

const (
	OpenAPIDocsEndpoint        = "docs"
	OpenAPIRapiEndpoint        = "rapi"
	OpenAPISwaggerUIEndpoint   = "swaggerui"
	OpenAPIswaggerJSONEndpoint = "swagger.yaml"
	OpenAPIV2Prefix            = "/openapi/v2/"
)

//go:embed swagger.yaml
var specJSONBytes []byte

var lastKnownBaseHost string
var lastKnownScheme string

type fileHandler struct{}

func ServeSpecs() http.Handler {
	logstr := fmt.Sprintf("Starting swagger UI. baseURI: %v, docsEP: %v, rapidocEP: %v, swaggerui: %s", OpenAPIV2Prefix, OpenAPIDocsEndpoint, OpenAPIRapiEndpoint, OpenAPISwaggerUIEndpoint)
	logger.L().Info(logstr)

	redocOpts := middleware.RedocOpts{
		BasePath: OpenAPIV2Prefix,
		SpecURL:  OpenAPIswaggerJSONEndpoint,
	}
	RapiDocOpts := middleware.RapiDocOpts{
		BasePath: OpenAPIV2Prefix,
		SpecURL:  OpenAPIswaggerJSONEndpoint,
		Path:     OpenAPIRapiEndpoint,
	}
	opts := middleware.SwaggerUIOpts{
		BasePath: OpenAPIV2Prefix,
		SpecURL:  OpenAPIswaggerJSONEndpoint,
		Path:     OpenAPISwaggerUIEndpoint,
	}

	fs := &fileHandler{}
	redoc := middleware.Redoc(redocOpts, fs)
	rapi := middleware.RapiDoc(RapiDocOpts, redoc)
	swaggerui := middleware.SwaggerUI(opts, rapi)
	return swaggerui
}

func (f *fileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Host != "" && r.Host != lastKnownBaseHost {
		lastKnownBaseHost = r.Host
		specJSONBytes = bytes.ReplaceAll(specJSONBytes, []byte("api-dev.armo.cloud"), []byte(lastKnownBaseHost))
	}
	if fHost := r.Header.Get("X-Forwarded-Host"); fHost != "" && fHost != lastKnownBaseHost {
		lastKnownBaseHost = fHost
		specJSONBytes = bytes.ReplaceAll(specJSONBytes, []byte("api-dev.armo.cloud"), []byte(lastKnownBaseHost))
	}
	w.WriteHeader(http.StatusOK)
	w.Write(specJSONBytes)
}
