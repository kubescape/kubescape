package reporter

import (
	"net/url"
	"strings"
)

func parseHost(urlObj *url.URL) {
	if strings.Contains(urlObj.Host, "http://") {
		urlObj.Scheme = "http"
		urlObj.Host = strings.Replace(urlObj.Host, "http://", "", 1)
	} else {
		urlObj.Scheme = "https"
		urlObj.Host = strings.Replace(urlObj.Host, "https://", "", 1)
	}
}
