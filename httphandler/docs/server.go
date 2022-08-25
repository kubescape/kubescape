package docs

import (
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

// ServeOpenAPISpec returns the OpenAPI specification file
func ServeOpenAPISpec(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write(specJSONBytes)
}

// NewOpenAPIUIHandler returns a handler that serves OpenAPI specs via UI
func NewOpenAPIUIHandler() http.Handler {
	logstr := fmt.Sprintf("Starting swagger UI. baseURI: %v, docsEP: %v, rapidocEP: %v, swaggerui: %v", OpenAPIV2Prefix, OpenAPIDocsEndpoint, OpenAPIRapiEndpoint, OpenAPISwaggerUIEndpoint)
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

	var openAPISpecHandler http.Handler = http.HandlerFunc(ServeOpenAPISpec)

	openAPIUIHandler := middleware.Redoc(redocOpts, openAPISpecHandler)
	openAPIUIHandler = middleware.RapiDoc(RapiDocOpts, openAPIUIHandler)
	openAPIUIHandler = middleware.SwaggerUI(opts, openAPIUIHandler)

	return openAPIUIHandler
}
