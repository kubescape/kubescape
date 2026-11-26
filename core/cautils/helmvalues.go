package cautils

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"helm.sh/helm/v3/pkg/strvals"
	sigsyaml "sigs.k8s.io/yaml"
)

const helmValuesHTTPTimeout = 15 * time.Second

func mergeBoundedHelmValues(o HelmValueOptions, stdin io.Reader) (map[string]any, error) {
	return mergeBoundedHelmValuesWithClient(o, stdin, &http.Client{Timeout: helmValuesHTTPTimeout})
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
			return nil, fmt.Errorf("failed to parse %s: %w", filePath, err)
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
		return nil, err
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return fetchBoundedHelmValueURL(source, client, limit)
	default:
		return nil, fmt.Errorf("unsupported Helm values source scheme %q in %q", u.Scheme, source)
	}
}

func isLocalHelmValuePath(source string) bool {
	u, err := url.Parse(source)
	if err != nil {
		return true
	}
	if u.Scheme == "" {
		return true
	}
	// Treat single-letter Windows drive prefixes (e.g. C:\...) as local file paths.
	if len(u.Scheme) == 1 && ((u.Scheme[0] >= 'a' && u.Scheme[0] <= 'z') || (u.Scheme[0] >= 'A' && u.Scheme[0] <= 'Z')) {
		return true
	}
	return false
}

func readBoundedHelmReader(r io.Reader, name string, limit int64) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("nil reader for %s", name)
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", ErrHelmTemplateTooLarge, name, limit)
	}
	return data, nil
}

func fetchBoundedHelmValueURL(rawURL string, client *http.Client, limit int64) ([]byte, error) {
	if client == nil {
		client = &http.Client{Timeout: helmValuesHTTPTimeout}
	}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("failed to fetch %s: HTTP %d %s", rawURL, resp.StatusCode, resp.Status)
	}
	return readBoundedHelmReader(resp.Body, rawURL, limit)
}
