package reporter

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseHost(t *testing.T) {
	urlObj := url.URL{}

	urlObj.Host = "http://localhost:7555"
	parseHost(&urlObj)
	assert.Equal(t, "http", urlObj.Scheme)
	assert.Equal(t, "localhost:7555", urlObj.Host)

	urlObj.Host = "https://localhost:7555"
	parseHost(&urlObj)
	assert.Equal(t, "https", urlObj.Scheme)
	assert.Equal(t, "localhost:7555", urlObj.Host)

	urlObj.Host = "http://portal-dev.armo.cloud"
	parseHost(&urlObj)
	assert.Equal(t, "http", urlObj.Scheme)
	assert.Equal(t, "portal-dev.armo.cloud", urlObj.Host)

	urlObj.Host = "https://portal-dev.armo.cloud"
	parseHost(&urlObj)
	assert.Equal(t, "https", urlObj.Scheme)
	assert.Equal(t, "portal-dev.armo.cloud", urlObj.Host)

	urlObj.Host = "portal-dev.armo.cloud"
	parseHost(&urlObj)
	assert.Equal(t, "https", urlObj.Scheme)
	assert.Equal(t, "portal-dev.armo.cloud", urlObj.Host)

}
