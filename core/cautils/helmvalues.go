package cautils

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"helm.sh/helm/v3/pkg/strvals"
	sigsyaml "sigs.k8s.io/yaml"
)

const helmValuesHTTPTimeout = 15 * time.Second

// helmURLUserInfoPattern strips embedded userinfo from URLs and scheme-relative URLs
// appearing in URL strings or formatted error messages without disturbing path segments.
var helmURLUserInfoPattern = regexp.MustCompile(`(^|[\s"'(\[]|[a-zA-Z][a-zA-Z0-9+.-]*:)//[^\s/?#"<>\\]*@`)

var helmURLSchemePrefixPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://`)

func mergeBoundedHelmValues(o HelmValueOptions, stdin io.Reader) (map[string]any, error) {
	return mergeBoundedHelmValuesWithClient(o, stdin, helmValuesHTTPClient(nil))
}

func mergeBoundedHelmValuesWithClient(o HelmValueOptions, stdin io.Reader, client *http.Client) (map[string]any, error) {
	base := map[string]any{}

	for _, filePath := range o.ValueFiles {
		raw, err := readBoundedHelmValueSource(filePath, stdin, client)
		if err != nil {
			return nil, err
		}
		var currentMap map[string]any
		if err := sigsyaml.Unmarshal(raw, &currentMap); err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", sanitizeHelmValueSource(filePath), err)
		}
		base = mergeMaps(base, currentMap)
	}

	for _, value := range o.Values {
		if err := strvals.ParseInto(value, base); err != nil {
			return nil, fmt.Errorf("failed parsing --set data: %w", err)
		}
	}

	for _, value := range o.StringValues {
		if err := strvals.ParseIntoString(value, base); err != nil {
			return nil, fmt.Errorf("failed parsing --set-string data: %w", err)
		}
	}

	for _, value := range protectHelmFileValues(o.FileValues) {
		reader := func(rs []rune) (any, error) {
			raw, err := readBoundedHelmValueSource(string(rs), stdin, client)
			if err != nil {
				return nil, err
			}
			return string(raw), nil
		}
		if err := strvals.ParseIntoFile(value, base, reader); err != nil {
			return nil, fmt.Errorf("failed parsing --set-file data: %w", err)
		}
	}

	return base, nil
}

func readBoundedHelmValueSource(source string, stdin io.Reader, client *http.Client) ([]byte, error) {
	limit := getMaxFileSize()
	if strings.TrimSpace(source) == "-" {
		return readBoundedHelmReader(stdin, "<stdin>", limit)
	}

	if isLocalHelmValuePath(source) {
		return readHelmTemplateFile(source)
	}

	u, err := url.Parse(source)
	if err != nil {
		return nil, sanitizeHelmURLError(err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return fetchBoundedHelmValueURL(source, client, limit)
	default:
		return nil, fmt.Errorf("unsupported Helm values source scheme %q in %q", u.Scheme, sanitizeHelmValueSource(source))
	}
}

func isWindowsDriveScheme(scheme string) bool {
	return len(scheme) == 1 && ((scheme[0] >= 'a' && scheme[0] <= 'z') || (scheme[0] >= 'A' && scheme[0] <= 'Z'))
}

func isLocalHelmValuePath(source string) bool {
	if strings.HasPrefix(source, "//") {
		return false
	}
	u, err := url.Parse(source)
	if err != nil {
		return !helmURLSchemePrefixPattern.MatchString(source)
	}
	if u.Scheme == "" {
		return true
	}
	// Treat single-letter Windows drive prefixes (e.g. C:\...) as local file paths.
	return isWindowsDriveScheme(u.Scheme)
}

func readBoundedHelmReader(r io.Reader, name string, limit int64) ([]byte, error) {
	safeName := sanitizeHelmValueSource(name)
	if r == nil {
		return nil, fmt.Errorf("nil reader for %s", safeName)
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", ErrHelmTemplateTooLarge, safeName, limit)
	}
	return data, nil
}

func fetchBoundedHelmValueURL(rawURL string, client *http.Client, limit int64) ([]byte, error) {
	safeURL := sanitizeHelmValueSource(rawURL)
	resp, err := helmValuesHTTPClient(client).Get(rawURL)
	if err != nil {
		return nil, sanitizeHelmURLError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("failed to fetch %s: HTTP %d %s", safeURL, resp.StatusCode, resp.Status)
	}
	return readBoundedHelmReader(resp.Body, safeURL, limit)
}

func helmValuesHTTPClient(base *http.Client) *http.Client {
	client := http.Client{Timeout: helmValuesHTTPTimeout}
	if base != nil {
		client = *base
	}
	callerPolicy := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		history := make([]*http.Request, len(via))
		for i, previous := range via {
			history[i] = previous.Clone(previous.Context())
		}
		validate := func() error {
			if req.URL == nil {
				return errors.New("refusing redirect: destination URL is missing")
			}
			if !strings.EqualFold(req.URL.Scheme, "http") && !strings.EqualFold(req.URL.Scheme, "https") {
				return fmt.Errorf("refusing redirect to unsupported scheme %q", req.URL.Scheme)
			}
			for _, previous := range history {
				if previous == nil || previous.URL == nil {
					continue
				}
				if strings.EqualFold(previous.URL.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
					return fmt.Errorf("refusing redirect to %s: scheme downgrade from https", sanitizeHelmValueURL(req.URL))
				}
				if (previous.Header.Get("Authorization") != "" || previous.URL.User != nil) &&
					!sameHelmHTTPOrigin(previous.URL, req.URL) {
					return fmt.Errorf("refusing redirect: credentials cannot leave origin %s for %s", previous.URL.Host, req.URL.Host)
				}
			}
			return nil
		}
		if err := validate(); err != nil {
			return err
		}
		if callerPolicy != nil {
			if err := callerPolicy(req, via); err != nil {
				return err
			}
			return validate()
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &client
}

func sameHelmHTTPOrigin(a, b *url.URL) bool {
	port := func(u *url.URL) string {
		if u.Port() != "" {
			return u.Port()
		}
		if strings.EqualFold(u.Scheme, "https") {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}

func sanitizeHelmValueURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	cloned := *u
	cloned.User = nil
	return cloned.String()
}

func sanitizeHelmURLString(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	if u, err := url.Parse(rawURL); err == nil {
		return sanitizeHelmValueURL(u)
	}
	return sanitizeHelmErrorMessage(rawURL)
}

func sanitizeHelmValueSource(source string) string {
	if source == "" || strings.TrimSpace(source) == "-" {
		return source
	}
	if u, err := url.Parse(source); err == nil {
		if (u.Scheme == "" && !strings.HasPrefix(source, "//")) || isWindowsDriveScheme(u.Scheme) {
			return source
		}
		return sanitizeHelmValueURL(u)
	}
	return sanitizeHelmErrorMessage(source)
}

func sanitizeHelmErrorMessage(msg string) string {
	return helmURLUserInfoPattern.ReplaceAllString(msg, "${1}//")
}

type sanitizedHelmURLError struct {
	cause error
	msg   string
}

func (e *sanitizedHelmURLError) Error() string {
	return e.msg
}

func (e *sanitizedHelmURLError) Unwrap() error {
	return e.cause
}

func sanitizeHelmURLError(err error) error {
	sanitized, _ := sanitizeHelmURLErrorState(err)
	return sanitized
}

func sanitizeHelmURLErrorState(err error) (error, bool) {
	if err == nil {
		return nil, false
	}
	if urlErr, ok := err.(*url.Error); ok {
		safeURL := sanitizeHelmURLString(urlErr.URL)
		safeInner, innerChanged := sanitizeHelmURLErrorState(urlErr.Err)
		if safeURL == urlErr.URL && !innerChanged {
			return err, false
		}
		sanitized := *urlErr
		sanitized.URL = safeURL
		sanitized.Err = safeInner
		return &sanitized, true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		orig := joined.Unwrap()
		children := make([]error, len(orig))
		anyChanged := false
		for i, child := range orig {
			sc, changed := sanitizeHelmURLErrorState(child)
			children[i] = sc
			if changed {
				anyChanged = true
			}
		}
		msg := sanitizeHelmErrorMessage(err.Error())
		if !anyChanged {
			if msg == err.Error() {
				return err, false
			}
			return &sanitizedHelmURLError{cause: errors.Join(children...), msg: msg}, true
		}
		return errors.Join(children...), true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		safeInner, innerChanged := sanitizeHelmURLErrorState(wrapped.Unwrap())
		msg := sanitizeHelmErrorMessage(err.Error())
		if !innerChanged && msg == err.Error() {
			return err, false
		}
		return &sanitizedHelmURLError{cause: safeInner, msg: msg}, true
	}
	msg := sanitizeHelmErrorMessage(err.Error())
	if msg == err.Error() {
		return err, false
	}
	return errors.New(msg), true
}
