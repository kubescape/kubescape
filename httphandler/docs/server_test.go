package docs

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServeOpenAPISpec(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, OpenAPIV2Prefix+OpenAPIswaggerJSONEndpoint, nil)

	ServeOpenAPISpec(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, string(specJSONBytes), response.Body.String())
}

func TestNewOpenAPIUIHandler(t *testing.T) {
	handler := NewOpenAPIUIHandler()

	tests := []struct {
		name string
		path string
	}{
		{name: "ReDoc", path: OpenAPIV2Prefix + OpenAPIDocsEndpoint},
		{name: "RapiDoc", path: OpenAPIV2Prefix + OpenAPIRapiEndpoint},
		{name: "Swagger UI", path: OpenAPIV2Prefix + OpenAPISwaggerUIEndpoint},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, test.path, nil)

			handler.ServeHTTP(response, request)

			require.Equal(t, http.StatusOK, response.Code)
			assert.Contains(t, response.Body.String(), OpenAPIswaggerJSONEndpoint)
		})
	}
}
