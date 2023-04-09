package getter

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// parseHost picks a host from a hostname or an URL and detects the scheme.
//
// The default scheme is https. This may be altered by specifying an explicit http://hostname URL.
func parseHost(host string) (string, string) {
	if strings.HasPrefix(host, "http://") {
		return "http", strings.Replace(host, "http://", "", 1) // cut... index ...
	}

	// default scheme
	return "https", strings.Replace(host, "https://", "", 1)
}

func isNativeFramework(framework string) bool {
	return contains(NativeFrameworks, framework)
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if strings.EqualFold(v, str) {
			return true
		}
	}

	return false
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}

	return b
}

// errAPI reports an API error, with a cap on the length of the error message.
func errAPI(resp *http.Response) error {
	const maxSize = 1024

	reason := new(strings.Builder)
	if resp.Body != nil {
		size := min(resp.ContentLength, maxSize)
		if size > 0 {
			reason.Grow(int(size))
		}

		_, _ = io.CopyN(reason, resp.Body, size)
		defer resp.Body.Close()
	}

	return fmt.Errorf("http-error: '%s', reason: '%s'", resp.Status, reason.String())
}

// errAuth returns an authentication error.
//
// Authentication errors upon login croak a less detailed message.
func errAuth(resp *http.Response) error {
	return fmt.Errorf("error authenticating: %d", resp.StatusCode)
}

func readString(rdr io.Reader, sizeHint int64) (string, error) {
	var b strings.Builder

	b.Grow(int(sizeHint))
	_, err := io.Copy(&b, rdr)

	return b.String(), err
}
