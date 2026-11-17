package lsp

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

// pathFromURI returns the local filesystem path a file: URI names. It accepts
// the forms editors send: percent-encoded paths, the Windows drive form
// (file:///C:/dir/f.yaml, and VS Code's file:///c%3A/dir/f.yaml) and UNC hosts
// (file://server/share/f.yaml). Any other scheme is refused.
func pathFromURI(uri string) (string, error) {
	return pathFromURIFor(uri, windowsHost())
}

// pathFromURIFor is pathFromURI for a given platform, so both are testable on
// any host.
func pathFromURIFor(uri string, windows bool) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("invalid document URI: %w", err)
	}
	if u.Scheme != "file" {
		return "", fmt.Errorf("unsupported document URI scheme %q: only file URIs can be scanned", u.Scheme)
	}
	p := u.Path // already percent-decoded
	if p == "" {
		return "", errors.New("document URI has no path")
	}
	if windows {
		p = strings.ReplaceAll(p, "/", `\`)
		// "\C:\dir" -> "C:\dir"
		if len(p) >= 3 && p[0] == '\\' && p[2] == ':' && isASCIILetter(p[1]) {
			p = p[1:]
		}
		if u.Host != "" && u.Host != "localhost" {
			p = `\\` + u.Host + p
		}
		return filepath.Clean(p), nil
	}
	if u.Host != "" && u.Host != "localhost" {
		return "", fmt.Errorf("document URI names a remote host %q", u.Host)
	}
	return filepath.Clean(p), nil
}

// uriFromPath is the inverse of pathFromURI for an absolute path.
func uriFromPath(path string) string {
	return uriFromPathFor(path, windowsHost())
}

func uriFromPathFor(path string, windows bool) string {
	u := url.URL{Scheme: "file"}
	if windows {
		path = strings.ReplaceAll(path, `\`, "/")
		if strings.HasPrefix(path, "//") { // UNC
			rest := strings.TrimPrefix(path, "//")
			host, p, _ := strings.Cut(rest, "/")
			u.Host = host
			u.Path = "/" + p
			return u.String()
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
	}
	u.Path = path
	return u.String()
}

func isASCIILetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }
