// Package notification delivers generic scan summary webhooks.
package notification

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultTimeout  = 5 * time.Second
	maxResponseBody = 4 << 10
)

// Doer is implemented by http.Client and makes delivery testable.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// NewClient returns the bounded, no-redirect client used by scan notifications.
func NewClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// SafeTarget returns only non-secret endpoint components suitable for logs.
func SafeTarget(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return "invalid endpoint"
	}
	host := u.Hostname()
	if port := u.Port(); port != "" {
		host += ":" + port
	}
	return u.Scheme + "://" + host
}

func validateEndpoint(endpoint string) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("invalid notification endpoint")
	}
	return u, nil
}

// Send POSTs already-marshaled JSON to endpoint. Errors never include secrets
// from endpoint paths, queries, fragments, or userinfo.
func Send(ctx context.Context, client Doer, endpoint string, payload []byte) error {
	u, err := validateEndpoint(endpoint)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create notification request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send notification to %s failed", SafeTarget(endpoint))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("notification endpoint %s returned %s", SafeTarget(endpoint), strings.TrimSpace(resp.Status))
	}
	return nil
}
