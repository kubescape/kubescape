package imagescan

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var _ IContainerImageVulnerabilityAdaptor = (*QuayAdaptor)(nil)

var (
	// validQuayNameRegex validates namespaces and repository segments in Quay
	validQuayNameRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)
)

const (
	defaultQuayTimeout      = 15 * time.Second
	defaultQuayMaxRetries   = 3
	defaultQuayRetryBackoff = 500 * time.Millisecond
)

// QuayAPI defines the interface for Quay HTTP interactions to enable mocking in tests.
type QuayAPI interface {
	DoRequest(ctx context.Context, method, path string) ([]byte, error)
}

// QuayHeaderAPI optionally extends QuayAPI to allow callers to receive response HTTP headers.
type QuayHeaderAPI interface {
	DoRequestWithHeaders(ctx context.Context, method, path string, extraHeaders http.Header) ([]byte, http.Header, error)
}

type quayAPIWrapper struct {
	baseURL                      string
	username                     string
	password                     string
	token                        string
	httpClient                   *http.Client
	timeout                      time.Duration
	maxResponseSize              int64
	maxRetries                   int
	retryBackoff                 time.Duration
	allowInsecureHTTPCredentials bool
	cachedTokens                 map[string]string
	tokensMu                     sync.Mutex
}

const maxQuayRetryAfter = 60 * time.Second

// createQuayHTTPClient clones the base HTTP client and wraps its redirect handler to enforce
// that credentials are never transmitted over plain HTTP unless allowInsecureHTTPCredentials is true.
func createQuayHTTPClient(baseClient *http.Client, allowInsecureHTTPCredentials bool) *http.Client {
	var client http.Client
	if baseClient != nil {
		client = *baseClient
	}
	origCheckRedirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !allowInsecureHTTPCredentials {
			if !strings.EqualFold(req.URL.Scheme, "https") {
				for _, prev := range via {
					if strings.EqualFold(prev.URL.Scheme, "https") {
						return fmt.Errorf("refusing redirect to %s: scheme downgrade from https", req.URL.String())
					}
				}
				return fmt.Errorf("refusing redirect to %s: insecure http redirect not allowed; use https or enable WithInsecureHTTPCredentials", req.URL.String())
			}
		}
		if origCheckRedirect != nil {
			return origCheckRedirect(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &client
}

func isRedirectError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "refusing redirect") ||
		strings.Contains(errStr, "stopped after 10 redirects") ||
		strings.Contains(errStr, "scheme downgrade") ||
		strings.Contains(errStr, "insecure http redirect")
}

func (w *quayAPIWrapper) getCachedToken(scope string) string {
	if scope == "" {
		return ""
	}
	w.tokensMu.Lock()
	defer w.tokensMu.Unlock()
	if w.cachedTokens == nil {
		return ""
	}
	return w.cachedTokens[scope]
}

func (w *quayAPIWrapper) setCachedToken(scope, token string) {
	if scope == "" || token == "" {
		return
	}
	w.tokensMu.Lock()
	defer w.tokensMu.Unlock()
	if w.cachedTokens == nil {
		w.cachedTokens = make(map[string]string)
	}
	w.cachedTokens[scope] = token
}

func extractV2Scope(path string) string {
	if !strings.HasPrefix(path, "/v2/") {
		return ""
	}
	rest := strings.TrimPrefix(path, "/v2/")
	for _, sep := range []string{"/manifests/", "/blobs/", "/tags/"} {
		if idx := strings.Index(rest, sep); idx != -1 {
			return "repository:" + rest[:idx] + ":pull"
		}
	}
	return ""
}

func parseAuthChallenge(header string) (realm, service, scope string) {
	header = strings.TrimSpace(header)
	if len(header) < 7 || !strings.EqualFold(header[:7], "bearer ") {
		return "", "", ""
	}
	params := header[7:]
	for _, part := range strings.Split(params, ",") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.Trim(strings.TrimSpace(kv[1]), `"`)
		switch key {
		case "realm":
			realm = val
		case "service":
			service = val
		case "scope":
			scope = val
		}
	}
	return realm, service, scope
}

func (w *quayAPIWrapper) fetchChallengeToken(ctx context.Context, realm, service, scope string) (string, error) {
	authURL, err := url.Parse(realm)
	if err != nil {
		return "", fmt.Errorf("invalid auth realm %q: %w", realm, err)
	}
	if base, baseErr := url.Parse(w.baseURL); baseErr == nil {
		if strings.EqualFold(base.Scheme, "https") && !strings.EqualFold(authURL.Scheme, "https") {
			return "", fmt.Errorf("refusing auth realm %q: scheme downgrade from https", realm)
		}
		if !strings.EqualFold(authURL.Host, base.Host) {
			return "", fmt.Errorf("refusing auth realm %q: realm host does not match registry host %q", realm, base.Host)
		}
	}
	q := authURL.Query()
	if service != "" {
		q.Set("service", service)
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	if w.username != "" {
		q.Set("account", w.username)
	}
	authURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create auth challenge request: %w", err)
	}

	if w.token != "" {
		req.Header.Set("Authorization", "Bearer "+w.token)
	} else if w.username != "" && w.password != "" {
		req.SetBasicAuth(w.username, w.password)
	}
	req.Header.Set("Accept", "application/json")

	client := createQuayHTTPClient(w.httpClient, w.allowInsecureHTTPCredentials)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth challenge request to %s failed: %w", authURL.String(), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("auth challenge endpoint returned status %d", resp.StatusCode)
	}

	bodyBytes, err := readRegistryAPIResponse(resp.Body, w.maxResponseSize)
	if err != nil {
		return "", fmt.Errorf("failed to read auth challenge response: %w", err)
	}

	var tokenPayload map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &tokenPayload); err != nil {
		return "", fmt.Errorf("failed to parse auth challenge token: %w", err)
	}

	var tok string
	if t, ok := tokenPayload["token"].(string); ok && t != "" {
		tok = t
	} else if at, ok := tokenPayload["access_token"].(string); ok && at != "" {
		tok = at
	}
	if tok == "" {
		return "", fmt.Errorf("auth challenge response contained no token")
	}

	return tok, nil
}

func (w *quayAPIWrapper) DoRequest(ctx context.Context, method, path string) ([]byte, error) {
	bytes, _, err := w.DoRequestWithHeaders(ctx, method, path, nil)
	return bytes, err
}

func (w *quayAPIWrapper) DoRequestWithHeaders(ctx context.Context, method, path string, extraHeaders http.Header) ([]byte, http.Header, error) {
	reqURL := fmt.Sprintf("%s%s", w.baseURL, path)

	var lastErr error
	var rateLimitSlept bool
	var attemptToken string
	for attempt := 0; attempt <= w.maxRetries; attempt++ {
		if attempt > 0 && !rateLimitSlept {
			backoff := w.retryBackoff * time.Duration(1<<(attempt-1))
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		}
		rateLimitSlept = false

		attemptCtx := ctx
		var cancel context.CancelFunc
		if w.timeout > 0 {
			attemptCtx, cancel = context.WithTimeout(ctx, w.timeout)
		} else {
			cancel = func() {}
		}

		req, err := http.NewRequestWithContext(attemptCtx, method, reqURL, nil)
		if err != nil {
			cancel()
			return nil, nil, fmt.Errorf("failed to create request: %w", err)
		}

		scope := extractV2Scope(path)
		isV2Path := strings.HasPrefix(path, "/v2/")
		if w.token != "" {
			req.Header.Set("Authorization", "Bearer "+w.token)
		} else if attemptToken != "" {
			req.Header.Set("Authorization", "Bearer "+attemptToken)
		} else if cached := w.getCachedToken(scope); isV2Path && cached != "" {
			req.Header.Set("Authorization", "Bearer "+cached)
		} else if w.username != "" && w.password != "" {
			req.SetBasicAuth(w.username, w.password)
		}
		req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/json")

		for k, vv := range extraHeaders {
			for _, v := range vv {
				req.Header.Add(k, v)
			}
		}

		resp, err := w.httpClient.Do(req)
		if err != nil {
			cancel()
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			if errors.Is(err, context.Canceled) {
				return nil, nil, err
			}
			if isRedirectError(err) {
				return nil, nil, fmt.Errorf("failed to execute quay request: %w", err)
			}
			lastErr = err
			continue
		}

		// Handle 401 Unauthorized via Registry v2 authentication challenge flow
		if resp.StatusCode == http.StatusUnauthorized {
			authHeader := resp.Header.Get("WWW-Authenticate")
			if authHeader == "" {
				authHeader = resp.Header.Get("Www-Authenticate")
			}
			realm, service, challengeScope := parseAuthChallenge(authHeader)
			if realm != "" {
				// Boundedly drain and close the 401 response body before fetching the auth token.
				// This releases the HTTP connection (critical for custom transports with MaxConnsPerHost: 1)
				// and allows connection reuse.
				if resp.Body != nil {
					drainLimit := int64(64 * 1024)
					if w.maxResponseSize > 0 && w.maxResponseSize < drainLimit {
						drainLimit = w.maxResponseSize
					}
					_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit))
					_ = resp.Body.Close()
				}

				if challengeScope == "" {
					challengeScope = scope
				}
				tok, tokenErr := w.fetchChallengeToken(attemptCtx, realm, service, challengeScope)
				if tokenErr != nil {
					cancel()
					if ctx.Err() != nil {
						return nil, nil, ctx.Err()
					}
					if errors.Is(tokenErr, context.Canceled) {
						return nil, nil, tokenErr
					}
					return nil, nil, fmt.Errorf("failed to fetch auth challenge token: %w", tokenErr)
				}
				if tok == "" {
					cancel()
					return nil, nil, errors.New("auth challenge response contained no token")
				}

				attemptToken = tok
				w.setCachedToken(challengeScope, tok)
				if scope != "" && scope != challengeScope {
					w.setCachedToken(scope, tok)
				}
				retryReq, retryErr := http.NewRequestWithContext(attemptCtx, method, reqURL, nil)
				if retryErr != nil {
					cancel()
					if ctx.Err() != nil {
						return nil, nil, ctx.Err()
					}
					if errors.Is(retryErr, context.Canceled) {
						return nil, nil, retryErr
					}
					return nil, nil, fmt.Errorf("failed to create retry request with auth token: %w", retryErr)
				}
				for k, vv := range req.Header {
					retryReq.Header[k] = vv
				}
				retryReq.Header.Set("Authorization", "Bearer "+tok)

				resp2, err2 := w.httpClient.Do(retryReq)
				if err2 != nil {
					cancel()
					if ctx.Err() != nil {
						return nil, nil, ctx.Err()
					}
					if errors.Is(err2, context.Canceled) {
						return nil, nil, err2
					}
					if isRedirectError(err2) {
						return nil, nil, fmt.Errorf("failed to retry request with auth token: %w", err2)
					}
					lastErr = fmt.Errorf("failed to retry request with auth token: %w", err2)
					continue
				}
				resp = resp2
			}
		}

		if resp.StatusCode == http.StatusTooManyRequests && attempt < w.maxRetries {
			// Rate limited: inspect Retry-After header if present
			retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"), w.retryBackoff)
			_ = resp.Body.Close()
			cancel()
			select {
			case <-time.After(retryAfter):
				rateLimitSlept = true
				continue
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		}

		switch resp.StatusCode {
		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			if attempt < w.maxRetries {
				_ = resp.Body.Close()
				cancel()
				lastErr = fmt.Errorf("quay api returned status %d for %s", resp.StatusCode, path)
				continue
			}
		}

		bodyBytes, readErr := readRegistryAPIResponse(resp.Body, w.maxResponseSize)
		respHeader := resp.Header.Clone()
		_ = resp.Body.Close()
		cancel()
		if readErr != nil {
			return nil, nil, fmt.Errorf("failed to read quay response for %s: %w", path, readErr)
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			var quayErr struct {
				Status    int    `json:"status"`
				Message   string `json:"message"`
				ErrorType string `json:"error_type"`
				Detail    string `json:"detail"`
			}
			if jsonErr := json.Unmarshal(bodyBytes, &quayErr); jsonErr == nil && (quayErr.Message != "" || quayErr.Detail != "") {
				msg := quayErr.Message
				if msg == "" {
					msg = quayErr.Detail
				}
				return nil, nil, &quayStatusError{
					StatusCode: resp.StatusCode,
					msg:        fmt.Sprintf("quay api error (%d %s): %s", resp.StatusCode, quayErr.ErrorType, msg),
				}
			}
			return nil, nil, &quayStatusError{
				StatusCode: resp.StatusCode,
				msg:        fmt.Sprintf("quay api returned status %d for %s", resp.StatusCode, path),
			}
		}

		return bodyBytes, respHeader, nil
	}

	return nil, nil, fmt.Errorf("quay request failed after %d retries: %w", w.maxRetries, lastErr)
}

func parseRetryAfter(header string, defaultBackoff time.Duration) time.Duration {
	if header == "" {
		return defaultBackoff
	}
	if seconds, err := strconv.Atoi(header); err == nil && seconds > 0 {
		d := time.Duration(seconds) * time.Second
		if d > maxQuayRetryAfter {
			return maxQuayRetryAfter
		}
		return d
	}
	if t, err := http.ParseTime(header); err == nil {
		if d := time.Until(t); d > 0 {
			if d > maxQuayRetryAfter {
				return maxQuayRetryAfter
			}
			return d
		}
	}
	return defaultBackoff
}

// QuayAdaptorConfig defines configurable parameters for QuayAdaptor.
type QuayAdaptorConfig struct {
	HTTPClient                   *http.Client
	Timeout                      time.Duration
	MaxRetries                   int
	RetryBackoff                 time.Duration
	MaxResponseSize              int64
	AllowInsecureHTTPCredentials bool
}

// QuayAdaptorOption defines a functional option for configuring QuayAdaptor.
type QuayAdaptorOption func(*QuayAdaptorConfig)

// WithHTTPClient configures a custom HTTP client for Quay API interactions.
func WithHTTPClient(client *http.Client) QuayAdaptorOption {
	return func(c *QuayAdaptorConfig) {
		if client != nil {
			c.HTTPClient = client
		}
	}
}

// WithTimeout sets the per-request timeout for Quay API requests.
func WithTimeout(timeout time.Duration) QuayAdaptorOption {
	return func(c *QuayAdaptorConfig) {
		if timeout > 0 {
			c.Timeout = timeout
		}
	}
}

// WithMaxRetries sets the maximum number of retries for transient errors and rate limits.
func WithMaxRetries(retries int) QuayAdaptorOption {
	return func(c *QuayAdaptorConfig) {
		if retries >= 0 {
			c.MaxRetries = retries
		}
	}
}

// WithRetryBackoff sets the base backoff interval for retries.
func WithRetryBackoff(backoff time.Duration) QuayAdaptorOption {
	return func(c *QuayAdaptorConfig) {
		if backoff > 0 {
			c.RetryBackoff = backoff
		}
	}
}

// WithMaxResponseSize limits the maximum number of bytes accepted in API responses.
func WithMaxResponseSize(size int64) QuayAdaptorOption {
	return func(c *QuayAdaptorConfig) {
		if size > 0 {
			c.MaxResponseSize = size
		}
	}
}

// WithInsecureHTTPCredentials allows transmitting credentials over plain HTTP (e.g. for local test environments).
func WithInsecureHTTPCredentials() QuayAdaptorOption {
	return func(c *QuayAdaptorConfig) {
		c.AllowInsecureHTTPCredentials = true
	}
}

// defaultQuayConfig returns standard default configuration.
func defaultQuayConfig() QuayAdaptorConfig {
	return QuayAdaptorConfig{
		Timeout:         defaultQuayTimeout,
		MaxRetries:      defaultQuayMaxRetries,
		RetryBackoff:    defaultQuayRetryBackoff,
		MaxResponseSize: maxRegistryAPIResponseBytes,
	}
}

// QuayAdaptor implements IContainerImageVulnerabilityAdaptor for Red Hat Quay and quay.io.
type QuayAdaptor struct {
	config        QuayAdaptorConfig
	client        QuayAPI
	registryHost  string
	clientFactory func(baseURL, username, password, token string) QuayAPI
	mu            sync.RWMutex
}

// NewQuayAdaptor creates a new Quay adaptor instance with optional functional configurations.
func NewQuayAdaptor(opts ...QuayAdaptorOption) *QuayAdaptor {
	cfg := defaultQuayConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	adaptor := &QuayAdaptor{
		config: cfg,
	}

	adaptor.clientFactory = func(baseURL, username, password, token string) QuayAPI {
		client := adaptor.config.HTTPClient
		if client == nil {
			client = &http.Client{}
		}
		httpClient := createQuayHTTPClient(client, adaptor.config.AllowInsecureHTTPCredentials)
		return &quayAPIWrapper{
			baseURL:                      baseURL,
			username:                     username,
			password:                     password,
			token:                        token,
			httpClient:                   httpClient,
			timeout:                      adaptor.config.Timeout,
			maxResponseSize:              adaptor.config.MaxResponseSize,
			maxRetries:                   adaptor.config.MaxRetries,
			retryBackoff:                 adaptor.config.RetryBackoff,
			allowInsecureHTTPCredentials: adaptor.config.AllowInsecureHTTPCredentials,
			cachedTokens:                 make(map[string]string),
		}
	}

	return adaptor
}

// Login authenticates with Quay. The registry string may be a hostname (e.g. "quay.io" or "quay.example.com")
// or include a scheme (e.g. "https://quay.example.com" or "http://localhost:8080").
func (a *QuayAdaptor) Login(ctx context.Context, registry string, credentials RegistryCredentials) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Invalidate any previous session immediately so failed re-login does not leave stale authenticated state
	a.client = nil
	a.registryHost = ""

	trimmed := strings.TrimSpace(registry)
	if trimmed == "" {
		return fmt.Errorf("registry host cannot be empty")
	}

	scheme := "https"
	host := trimmed
	if strings.HasPrefix(trimmed, "http://") {
		scheme = "http"
		host = strings.TrimPrefix(trimmed, "http://")
	} else if strings.HasPrefix(trimmed, "https://") {
		host = strings.TrimPrefix(trimmed, "https://")
	}

	host = strings.TrimRight(host, "/")

	// Validate authority binding if specified
	trimmedAuth := strings.TrimSpace(credentials.Authority)
	if trimmedAuth != "" {
		authHost := trimmedAuth
		if strings.HasPrefix(authHost, "http://") {
			authHost = strings.TrimPrefix(authHost, "http://")
		} else if strings.HasPrefix(authHost, "https://") {
			authHost = strings.TrimPrefix(authHost, "https://")
		}
		authHost = strings.TrimRight(authHost, "/")
		if !strings.EqualFold(authHost, host) {
			return fmt.Errorf("credentials authority %q does not match registry host %q", credentials.Authority, host)
		}
	}

	if scheme == "http" && credentials.hasAuthenticator() && !a.config.AllowInsecureHTTPCredentials {
		return fmt.Errorf("refusing to send credentials over plain http to %s; use https or enable WithInsecureHTTPCredentials", host)
	}

	baseURL := fmt.Sprintf("%s://%s", scheme, host)

	var username, password, token string
	if credentials.hasAuthenticator() {
		username = credentials.Username
		password = credentials.Password
		token = credentials.Token
	}

	client := a.clientFactory(baseURL, username, password, token)

	// Ping Quay discovery endpoint to verify network reachability and API compatibility
	_, err := client.DoRequest(ctx, http.MethodGet, "/api/v1/discovery")
	if err != nil {
		return fmt.Errorf("failed to connect to quay registry at %s: %w", baseURL, err)
	}

	a.registryHost = host
	a.client = client
	return nil
}

// DescribeAdaptor provides a string description of the adaptor.
func (a *QuayAdaptor) DescribeAdaptor() string {
	return "Red Hat Quay Container Registry Vulnerability Adaptor"
}

// extractRepo extracts the organization and repository from an image repository string,
// automatically stripping any matching registry host prefixes (e.g. "quay.io/" or the configured host).
func extractRepo(repository, registryHost string) (string, string, error) {
	clean := strings.Trim(repository, "/")
	if registryHost != "" && strings.HasPrefix(clean, registryHost+"/") {
		clean = strings.TrimPrefix(clean, registryHost+"/")
	} else if strings.HasPrefix(clean, "quay.io/") && (registryHost == "" || strings.EqualFold(registryHost, "quay.io")) {
		clean = strings.TrimPrefix(clean, "quay.io/")
	} else {
		parts := strings.Split(clean, "/")
		if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":")) {
			return "", "", fmt.Errorf("unknown registry host prefix %q in repository %q", parts[0], repository)
		}
	}
	return extractQuayRepo(clean)
}

func (a *QuayAdaptor) extractRepo(repository string) (string, string, error) {
	a.mu.RLock()
	host := a.registryHost
	a.mu.RUnlock()
	return extractRepo(repository, host)
}

// QuayDiscoveryResponse represents the discovery payload from Quay's /api/v1/discovery endpoint.
type QuayDiscoveryResponse struct {
	Status   string                 `json:"status"`
	Features map[string]bool        `json:"features"`
	Paths    map[string]interface{} `json:"paths"`
}

// CheckScannerCapability queries Quay's discovery API to check if the security scanner is active.
func (a *QuayAdaptor) CheckScannerCapability(ctx context.Context) (bool, error) {
	a.mu.RLock()
	client := a.client
	a.mu.RUnlock()

	if client == nil {
		return false, fmt.Errorf("quay client not initialized, call Login first")
	}

	data, err := client.DoRequest(ctx, http.MethodGet, "/api/v1/discovery")
	if err != nil {
		return false, fmt.Errorf("failed to query discovery endpoint: %w", err)
	}

	var resp QuayDiscoveryResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return false, fmt.Errorf("failed to parse discovery response: %w", err)
	}

	// 1. Check features map if present (custom or config format)
	if resp.Features != nil {
		if enabled, ok := resp.Features["SECURITY_SCANNER"]; ok {
			return enabled, nil
		}
		if enabled, ok := resp.Features["security_scanner"]; ok {
			return enabled, nil
		}
	}

	// 2. Check Swagger paths map (standard Quay /api/v1/discovery OpenAPI spec)
	if len(resp.Paths) > 0 {
		for p := range resp.Paths {
			if strings.Contains(p, "/manifest/") && strings.HasSuffix(p, "/security") {
				return true, nil
			}
			if strings.HasSuffix(p, "/security") {
				return true, nil
			}
		}
		// Discovery specification returned paths, but security scanner route is absent
		return false, nil
	}

	return false, fmt.Errorf("unable to determine security scanner capability from discovery response")
}

// extractQuayRepo splits a Quay repository string (e.g. "myorg/myrepo" or "myorg/team/app") into organization/namespace and repo name.
func extractQuayRepo(repository string) (string, string, error) {
	clean := strings.Trim(repository, "/")
	if clean == "" {
		return "", "", fmt.Errorf("empty repository name")
	}

	parts := strings.Split(clean, "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid quay repository format %q: expected organization/repository", repository)
	}

	org := strings.ToLower(parts[0])
	if !validQuayNameRegex.MatchString(org) {
		return "", "", fmt.Errorf("invalid organization name %q: must match %s", org, validQuayNameRegex.String())
	}

	for _, seg := range parts[1:] {
		segLower := strings.ToLower(seg)
		if !validQuayNameRegex.MatchString(segLower) {
			return "", "", fmt.Errorf("invalid repository name %q: must match %s", seg, validQuayNameRegex.String())
		}
	}
	repo := strings.ToLower(strings.Join(parts[1:], "/"))

	return org, repo, nil
}

// escapeQuayRepoPath escapes each segment of a repository path individually,
// preserving literal '/' separators for nested Quay repository paths.
func escapeQuayRepoPath(repo string) string {
	parts := strings.Split(repo, "/")
	escaped := make([]string, len(parts))
	for i, seg := range parts {
		escaped[i] = url.PathEscape(seg)
	}
	return strings.Join(escaped, "/")
}

// quayManifestSecurityPath formats the canonical manifest security endpoint for Quay API v1.
func quayManifestSecurityPath(org, repo, manifestRef string, includeVulns bool) string {
	vulnParam := "false"
	if includeVulns {
		vulnParam = "true"
	}
	return fmt.Sprintf("/api/v1/repository/%s/%s/manifest/%s/security?vulnerabilities=%s",
		url.PathEscape(org),
		escapeQuayRepoPath(repo),
		url.PathEscape(manifestRef),
		vulnParam,
	)
}

// resolveQuayManifestRef resolves an image identifier to a content-addressable manifest digest.
// If the image provides a Hash, it takes precedence over Tag. Manifest-list digests supplied in
// Hash are resolved lazily when the security endpoint reports "unsupported" (see GetImagesScanStatus /
// GetImagesVulnerabilities), so single-arch digests need only one request.
// If the image provides only a Tag, it is resolved via registry manifest lookup (/v2/... supporting
// robot credentials via authentication challenge flow), falling back to Quay's REST API tag endpoint.
// If the resolved tag points to a manifest list, it is also resolved to its platform child digest.
func resolveQuayManifestRef(ctx context.Context, client QuayAPI, org, repo string, imageID ContainerImageIdentifier) (string, error) {
	targetDigest := imageID.Hash
	if targetDigest == "" {
		if imageID.Tag == "" {
			return "", nil
		}
		return resolveQuayTagToDigest(ctx, client, org, repo, imageID.Tag)
	}

	// Manifest-list digests supplied in Hash are resolved lazily when the
	// security endpoint reports "unsupported" (see GetImagesScanStatus /
	// GetImagesVulnerabilities), so single-arch digests need only one request.
	return targetDigest, nil
}

// resolveQuayTagToDigest resolves a tag to a manifest digest. It queries the registry v2 manifest
// endpoint first to support robot account credentials via the Docker authentication challenge flow,
// falling back to Quay's v1 tag listing API.
func resolveQuayTagToDigest(ctx context.Context, client QuayAPI, org, repo, tag string) (string, error) {
	// 1. Try registry manifest lookup (/v2/<repo>/manifests/<tag>)
	// This supports robot credentials challenge flow.
	v2Repo := fmt.Sprintf("%s/%s", org, repo)
	v2Path := fmt.Sprintf("/v2/%s/manifests/%s", escapeQuayRepoPath(v2Repo), url.PathEscape(tag))

	var v2Data []byte
	var v2Headers http.Header
	var v2Err error
	if headerClient, ok := client.(QuayHeaderAPI); ok {
		v2Data, v2Headers, v2Err = headerClient.DoRequestWithHeaders(ctx, http.MethodGet, v2Path, nil)
	} else {
		v2Data, v2Err = client.DoRequest(ctx, http.MethodGet, v2Path)
	}

	if v2Err == nil && len(v2Data) > 0 {
		var listCheck struct {
			MediaType string `json:"mediaType"`
			Manifests []struct {
				Digest string `json:"digest"`
			} `json:"manifests"`
		}
		if json.Unmarshal(v2Data, &listCheck) == nil && len(listCheck.Manifests) > 0 {
			// Manifest list detected! Select platform child; do not suppress errors
			return selectChildFromManifestData(string(v2Data), org, repo, tag)
		}

		// Single image manifest: extract digest from header or compute SHA256 of manifest body
		if v2Headers != nil {
			if digest := v2Headers.Get("Docker-Content-Digest"); digest != "" {
				return digest, nil
			}
		}
		var helper struct {
			Digest         string `json:"digest"`
			ManifestDigest string `json:"manifest_digest"`
		}
		if json.Unmarshal(v2Data, &helper) == nil {
			if helper.Digest != "" {
				return helper.Digest, nil
			}
			if helper.ManifestDigest != "" {
				return helper.ManifestDigest, nil
			}
		}
		return fmt.Sprintf("sha256:%x", sha256.Sum256(v2Data)), nil
	}

	// 2. Fallback to Quay API tag endpoint (/api/v1/repository/<org>/<repo>/tag/...)
	path := fmt.Sprintf("/api/v1/repository/%s/%s/tag/?specificTag=%s&onlyActiveTags=true",
		url.PathEscape(org),
		escapeQuayRepoPath(repo),
		url.QueryEscape(tag),
	)
	data, err := client.DoRequest(ctx, http.MethodGet, path)
	if err != nil {
		if v2Err != nil {
			err = errors.Join(fmt.Errorf("registry manifest lookup: %w", v2Err), fmt.Errorf("tag api lookup: %w", err))
		}
		return "", fmt.Errorf("failed to resolve tag %s for %s/%s: %w", tag, org, repo, err)
	}

	var payload struct {
		Tags []struct {
			Name           string `json:"name"`
			ManifestDigest string `json:"manifest_digest"`
			IsManifestList bool   `json:"is_manifest_list"`
		} `json:"tags"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", fmt.Errorf("failed to parse tag list for %s/%s: %w", org, repo, err)
	}

	for _, t := range payload.Tags {
		if t.Name == tag && t.ManifestDigest != "" {
			if t.IsManifestList {
				// Known manifest list! Must resolve platform child; do not suppress operational errors
				return resolveQuayListChildManifest(ctx, client, org, repo, t.ManifestDigest)
			}
			return t.ManifestDigest, nil
		}
	}

	return "", fmt.Errorf("tag %s not found in %s/%s", tag, org, repo)
}

// resolveQuayListChildManifest resolves a known manifest list to its platform child manifest digest.
// Operational, decode, and child selection errors are surfaced rather than suppressed.
func resolveQuayListChildManifest(ctx context.Context, client QuayAPI, org, repo, listDigest string) (string, error) {
	manifestPath := fmt.Sprintf("/api/v1/repository/%s/%s/manifest/%s",
		url.PathEscape(org),
		escapeQuayRepoPath(repo),
		url.PathEscape(listDigest),
	)
	manifestData, err := client.DoRequest(ctx, http.MethodGet, manifestPath)
	if err != nil {
		// Fallback to registry v2 manifest endpoint
		v2Repo := fmt.Sprintf("%s/%s", org, repo)
		v2Path := fmt.Sprintf("/v2/%s/manifests/%s", escapeQuayRepoPath(v2Repo), url.PathEscape(listDigest))
		v2Data, v2Err := client.DoRequest(ctx, http.MethodGet, v2Path)
		if v2Err != nil {
			joinedErr := errors.Join(fmt.Errorf("manifest api lookup: %w", err), fmt.Errorf("registry manifest lookup: %w", v2Err))
			return "", fmt.Errorf("failed to retrieve manifest metadata for %s/%s@%s: %w", org, repo, listDigest, joinedErr)
		}
		return selectChildFromManifestData(string(v2Data), org, repo, listDigest)
	}

	var manifestPayload struct {
		IsManifestList bool   `json:"is_manifest_list"`
		ManifestData   string `json:"manifest_data"`
	}
	if err := json.Unmarshal(manifestData, &manifestPayload); err != nil {
		return "", fmt.Errorf("failed to decode manifest metadata for %s/%s@%s: %w", org, repo, listDigest, err)
	}
	if manifestPayload.ManifestData == "" {
		return "", fmt.Errorf("manifest metadata for %s/%s@%s contained empty manifest data", org, repo, listDigest)
	}

	return selectChildFromManifestData(manifestPayload.ManifestData, org, repo, listDigest)
}

// selectChildFromManifestData parses manifest list JSON and selects the platform-specific child digest.
func selectChildFromManifestData(manifestDataJSON, org, repo, listRef string) (string, error) {
	var list struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				Architecture string `json:"architecture"`
				OS           string `json:"os"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal([]byte(manifestDataJSON), &list); err != nil {
		return "", fmt.Errorf("failed to decode manifest list data for %s/%s@%s: %w", org, repo, listRef, err)
	}
	if len(list.Manifests) == 0 {
		return "", fmt.Errorf("manifest list %s/%s@%s contains no child manifests", org, repo, listRef)
	}

	childDigest := resolveChildManifestDigest(manifestDataJSON)
	if childDigest == "" {
		return "", fmt.Errorf("failed to select compatible child manifest from manifest list %s/%s@%s", org, repo, listRef)
	}

	return childDigest, nil
}

// quayStatusError carries the HTTP status code of a failed Quay API response.
type quayStatusError struct {
	StatusCode int
	msg        string
}

func (e *quayStatusError) Error() string { return e.msg }

// isQuayNotFoundError checks if an error indicates a resource was not found (HTTP 404).
func isQuayNotFoundError(err error) bool {
	var se *quayStatusError
	return errors.As(err, &se) && se.StatusCode == http.StatusNotFound
}

// resolveQuayListChild inspects whether digest points to a multi-arch manifest list or OCI index,
// returning the child digest, a boolean indicating if it was a manifest list, and any operational error.
func resolveQuayListChild(ctx context.Context, client QuayAPI, org, repo, digest string) (string, bool, error) {
	// Try Quay API v1 manifest endpoint
	manifestPath := fmt.Sprintf("/api/v1/repository/%s/%s/manifest/%s",
		url.PathEscape(org),
		escapeQuayRepoPath(repo),
		url.PathEscape(digest),
	)
	manifestData, err := client.DoRequest(ctx, http.MethodGet, manifestPath)
	if err == nil {
		var manifestPayload struct {
			IsManifestList bool   `json:"is_manifest_list"`
			ManifestData   string `json:"manifest_data"`
		}
		if jsonErr := json.Unmarshal(manifestData, &manifestPayload); jsonErr != nil {
			return "", false, fmt.Errorf("failed to decode manifest metadata for %s/%s@%s: %w", org, repo, digest, jsonErr)
		}
		if manifestPayload.IsManifestList {
			if manifestPayload.ManifestData == "" {
				return "", true, fmt.Errorf("manifest list %s/%s@%s contained empty manifest data", org, repo, digest)
			}
			childDigest, childErr := selectChildFromManifestData(manifestPayload.ManifestData, org, repo, digest)
			if childErr != nil {
				return "", true, childErr
			}
			return childDigest, true, nil
		}
		return "", false, nil
	}

	// Also check registry v2 manifest endpoint
	v2Repo := fmt.Sprintf("%s/%s", org, repo)
	v2Path := fmt.Sprintf("/v2/%s/manifests/%s", escapeQuayRepoPath(v2Repo), url.PathEscape(digest))
	v2Data, v2Err := client.DoRequest(ctx, http.MethodGet, v2Path)
	if v2Err == nil && len(v2Data) > 0 {
		var listCheck struct {
			Manifests []struct {
				Digest string `json:"digest"`
			} `json:"manifests"`
		}
		if jsonErr := json.Unmarshal(v2Data, &listCheck); jsonErr != nil {
			return "", false, fmt.Errorf("failed to decode v2 manifest for %s/%s@%s: %w", org, repo, digest, jsonErr)
		}
		if len(listCheck.Manifests) > 0 {
			childDigest, childErr := selectChildFromManifestData(string(v2Data), org, repo, digest)
			if childErr != nil {
				return "", true, childErr
			}
			return childDigest, true, nil
		}
		return "", false, nil
	}

	// Surface non-404 operational errors (e.g. 500, 502, 503, connection timeouts)
	if err != nil && !isQuayNotFoundError(err) {
		return "", false, fmt.Errorf("failed to retrieve manifest metadata for %s/%s@%s: %w", org, repo, digest, err)
	}
	if v2Err != nil && !isQuayNotFoundError(v2Err) {
		return "", false, fmt.Errorf("failed to retrieve v2 manifest for %s/%s@%s: %w", org, repo, digest, v2Err)
	}

	return "", false, nil
}

// resolveChildManifestDigest parses an OCI Image Index or Docker Manifest List JSON string
// and returns the best matching child manifest digest (preferring linux/amd64, then any linux, then first child).
func resolveChildManifestDigest(manifestDataJSON string) string {
	var list struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				Architecture string `json:"architecture"`
				OS           string `json:"os"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal([]byte(manifestDataJSON), &list); err != nil || len(list.Manifests) == 0 {
		return ""
	}

	// 1. Prefer linux/amd64 (default container runtime architecture)
	for _, m := range list.Manifests {
		if strings.EqualFold(m.Platform.OS, "linux") && strings.EqualFold(m.Platform.Architecture, "amd64") && m.Digest != "" {
			return m.Digest
		}
	}

	// 2. Prefer any linux architecture
	for _, m := range list.Manifests {
		if strings.EqualFold(m.Platform.OS, "linux") && m.Digest != "" {
			return m.Digest
		}
	}

	// 3. Fallback to first available child manifest
	for _, m := range list.Manifests {
		if m.Digest != "" {
			return m.Digest
		}
	}

	return ""
}

// GetImagesScanStatus retrieves the scan status for a list of image identifiers.
func (a *QuayAdaptor) GetImagesScanStatus(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageScanStatus, error) {
	a.mu.RLock()
	client := a.client
	regHost := a.registryHost
	a.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("quay client not initialized, call Login first")
	}

	return ProcessImages(imageIDs, func(imageID ContainerImageIdentifier) (ContainerImageScanStatus, error) {
		status := ContainerImageScanStatus{
			ImageID:         imageID,
			IsScanAvailable: false,
			IsBomAvailable:  false,
		}

		org, repo, err := extractRepo(imageID.Repository, regHost)
		if err != nil {
			return status, fmt.Errorf("failed to parse repository for image %s: %w", imageID.Repository, err)
		}
		if imageID.Registry != "" && regHost != "" && !strings.EqualFold(imageID.Registry, regHost) {
			return status, fmt.Errorf("image registry %q does not match quay registry %q", imageID.Registry, regHost)
		}

		manifestRef, err := resolveQuayManifestRef(ctx, client, org, repo, imageID)
		if err != nil {
			return status, err
		}
		if manifestRef == "" {
			return status, nil
		}

		path := quayManifestSecurityPath(org, repo, manifestRef, false)
		data, err := client.DoRequest(ctx, http.MethodGet, path)
		if err != nil {
			return status, fmt.Errorf("failed to query scan status for %s/%s@%s: %w", org, repo, manifestRef, err)
		}

		var payload struct {
			Status string `json:"status"`
		}

		if err := json.Unmarshal(data, &payload); err != nil {
			return status, fmt.Errorf("failed to parse scan status payload for %s/%s@%s: %w", org, repo, manifestRef, err)
		}

		switch strings.ToLower(payload.Status) {
		case "scanned":
			status.IsScanAvailable = true
		case "unsupported":
			// If unsupported, target digest might be a manifest list / OCI index that was not resolved upfront.
			// Try resolving to platform child and retrying the security query.
			childDigest, isList, listErr := resolveQuayListChild(ctx, client, org, repo, manifestRef)
			if listErr != nil {
				return status, fmt.Errorf("failed to resolve manifest list child for %s/%s@%s: %w", org, repo, manifestRef, listErr)
			}
			if isList && childDigest != "" && childDigest != manifestRef {
				retryPath := quayManifestSecurityPath(org, repo, childDigest, false)
				retryData, retryErr := client.DoRequest(ctx, http.MethodGet, retryPath)
				if retryErr != nil {
					return status, fmt.Errorf("failed to query scan status for child manifest %s/%s@%s: %w", org, repo, childDigest, retryErr)
				}
				var retryPayload struct {
					Status string `json:"status"`
				}
				if err := json.Unmarshal(retryData, &retryPayload); err != nil {
					return status, fmt.Errorf("failed to parse scan status payload for child manifest %s/%s@%s: %w", org, repo, childDigest, err)
				}
				switch strings.ToLower(retryPayload.Status) {
				case "scanned":
					status.IsScanAvailable = true
					return status, nil
				case "queued", "failed", "unsupported":
					status.IsScanAvailable = false
					return status, nil
				default:
					status.IsScanAvailable = false
					return status, nil
				}
			}
			status.IsScanAvailable = false
		case "queued", "failed":
			status.IsScanAvailable = false
		default:
			status.IsScanAvailable = false
		}

		return status, nil
	})
}

// parseQuayTimestamp attempts to parse timestamps from Quay responses in common formats.
func parseQuayTimestamp(ts string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		time.RFC1123,
		time.RFC1123Z,
	}
	for _, format := range formats {
		if t, err := time.Parse(format, ts); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized timestamp format: %s", ts)
}

// quayVulnerabilityPayload represents the Clair security scanning report returned by Quay.
type quayVulnerabilityPayload struct {
	Status string `json:"status"`
	Data   *struct {
		Layer *struct {
			Name     string `json:"Name"`
			Features []struct {
				Name            string `json:"Name"`
				Version         string `json:"Version"`
				Vulnerabilities []struct {
					Name        string `json:"Name"`
					Severity    string `json:"Severity"`
					Description string `json:"Description"`
					Link        string `json:"Link"`
					FixedBy     string `json:"FixedBy"`
				} `json:"Vulnerabilities"`
			} `json:"Features"`
		} `json:"Layer"`
	} `json:"data"`
}

// GetImagesVulnerabilities retrieves vulnerability reports for a list of image identifiers.
func (a *QuayAdaptor) GetImagesVulnerabilities(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageVulnerabilityReport, error) {
	a.mu.RLock()
	client := a.client
	regHost := a.registryHost
	a.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("quay client not initialized, call Login first")
	}

	return ProcessImages(imageIDs, func(imageID ContainerImageIdentifier) (ContainerImageVulnerabilityReport, error) {
		report := ContainerImageVulnerabilityReport{
			ImageID:         imageID,
			Vulnerabilities: []Vulnerability{},
		}

		org, repo, err := extractRepo(imageID.Repository, regHost)
		if err != nil {
			return report, fmt.Errorf("failed to parse repository for image %s: %w", imageID.Repository, err)
		}
		if imageID.Registry != "" && regHost != "" && !strings.EqualFold(imageID.Registry, regHost) {
			return report, fmt.Errorf("image registry %q does not match quay registry %q", imageID.Registry, regHost)
		}

		manifestRef, err := resolveQuayManifestRef(ctx, client, org, repo, imageID)
		if err != nil {
			return report, err
		}
		if manifestRef == "" {
			return report, nil
		}

		path := quayManifestSecurityPath(org, repo, manifestRef, true)
		data, err := client.DoRequest(ctx, http.MethodGet, path)
		if err != nil {
			return report, fmt.Errorf("failed to query vulnerabilities for %s/%s@%s: %w", org, repo, manifestRef, err)
		}

		var payload quayVulnerabilityPayload
		if err := json.Unmarshal(data, &payload); err != nil {
			return report, fmt.Errorf("failed to parse vulnerability payload for %s/%s@%s: %w", org, repo, manifestRef, err)
		}

	scanStatusSwitch:
		switch strings.ToLower(payload.Status) {
		case "scanned":
			if payload.Data == nil || payload.Data.Layer == nil {
				return report, nil
			}
		case "unsupported":
			// If unsupported, target digest might be a manifest list / OCI index that was not resolved upfront.
			// Try resolving to platform child and retrying the security query.
			childDigest, isList, listErr := resolveQuayListChild(ctx, client, org, repo, manifestRef)
			if listErr != nil {
				return report, fmt.Errorf("failed to resolve manifest list child for %s/%s@%s: %w", org, repo, manifestRef, listErr)
			}
			if isList && childDigest != "" && childDigest != manifestRef {
				retryPath := quayManifestSecurityPath(org, repo, childDigest, true)
				retryData, retryErr := client.DoRequest(ctx, http.MethodGet, retryPath)
				if retryErr != nil {
					return report, fmt.Errorf("failed to query vulnerabilities for child manifest %s/%s@%s: %w", org, repo, childDigest, retryErr)
				}
				var retryPayload quayVulnerabilityPayload
				if err := json.Unmarshal(retryData, &retryPayload); err != nil {
					return report, fmt.Errorf("failed to parse vulnerability payload for child manifest %s/%s@%s: %w", org, repo, childDigest, err)
				}
				switch strings.ToLower(retryPayload.Status) {
				case "scanned":
					if retryPayload.Data == nil || retryPayload.Data.Layer == nil {
						return report, nil
					}
					payload = retryPayload
					break scanStatusSwitch
				case "failed":
					return report, fmt.Errorf("quay security scan failed for child manifest %s/%s@%s", org, repo, childDigest)
				case "queued":
					return report, fmt.Errorf("quay security scan is queued for child manifest %s/%s@%s", org, repo, childDigest)
				case "unsupported":
					return report, fmt.Errorf("quay security scan unsupported for child manifest %s/%s@%s", org, repo, childDigest)
				default:
					return report, fmt.Errorf("unknown scan status %q for child manifest %s/%s@%s", retryPayload.Status, org, repo, childDigest)
				}
			}
			return report, fmt.Errorf("quay security scan unsupported for %s/%s@%s", org, repo, manifestRef)
		case "failed":
			return report, fmt.Errorf("quay security scan failed for %s/%s@%s", org, repo, manifestRef)
		case "queued":
			return report, fmt.Errorf("quay security scan is queued for %s/%s@%s", org, repo, manifestRef)
		default:
			return report, fmt.Errorf("quay security scan unavailable for %s/%s@%s (status: %s)", org, repo, manifestRef, payload.Status)
		}

		seenVulns := make(map[string]int)

		for _, feature := range payload.Data.Layer.Features {
			for _, v := range feature.Vulnerabilities {
				if v.Name == "" {
					continue
				}

				// Deduplicate findings if reported across multiple layers or feature packages,
				// retaining the highest reported severity across occurrences.
				if idx, seen := seenVulns[v.Name]; seen {
					if sev := normalizeQuaySeverity(v.Severity); quaySeverityRank(sev) > quaySeverityRank(report.Vulnerabilities[idx].Severity) {
						report.Vulnerabilities[idx].Severity = sev
					}
					continue
				}
				seenVulns[v.Name] = len(report.Vulnerabilities)

				desc := v.Description
				if desc == "" && feature.Name != "" {
					if feature.Version != "" {
						desc = fmt.Sprintf("Vulnerability in package %s (%s)", feature.Name, feature.Version)
					} else {
						desc = fmt.Sprintf("Vulnerability in package %s", feature.Name)
					}
				}
				if v.FixedBy != "" && desc != "" && !strings.Contains(desc, v.FixedBy) {
					desc = fmt.Sprintf("%s (fixed in %s)", desc, v.FixedBy)
				}

				vuln := Vulnerability{
					ID:          v.Name,
					Severity:    normalizeQuaySeverity(v.Severity),
					Description: desc,
				}

				if links := strings.Fields(v.Link); len(links) > 0 {
					vuln.Links = links
				} else if strings.HasPrefix(strings.ToUpper(v.Name), "CVE-") {
					vuln.Links = []string{fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", v.Name)}
				}

				report.Vulnerabilities = append(report.Vulnerabilities, vuln)
			}
		}

		return report, nil
	})
}

// normalizeQuaySeverity maps Quay/Clair specific severity labels to Kubescape canonical standards.
func normalizeQuaySeverity(severity string) string {
	s := strings.TrimSpace(severity)
	switch strings.ToLower(s) {
	case "defcon1":
		return "Critical"
	default:
		return NormalizeSeverity(s)
	}
}

// quaySeverityRank provides numeric precedence for severity comparison during deduplication.
func quaySeverityRank(s string) int {
	switch s {
	case "Critical":
		return 5
	case "High":
		return 4
	case "Medium":
		return 3
	case "Low":
		return 2
	case "Negligible":
		return 1
	default:
		return 0
	}
}

// GetImagesInformation retrieves the BOM and manifest information for a list of image identifiers.
func (a *QuayAdaptor) GetImagesInformation(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageInformation, error) {
	a.mu.RLock()
	client := a.client
	a.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("quay client not initialized, call Login first")
	}

	return FetchImagesInformation(imageIDs)
}

// Destroy cleans up any persistent resources used by the adaptor.
func (a *QuayAdaptor) Destroy() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.client = nil
	return nil
}
