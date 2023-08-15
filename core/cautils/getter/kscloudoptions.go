package getter

import (
	"context"
	"log"
	"net/http"
	"net/http/httputil"
	"time"
)

type (
	// KSCloudOption allows to configure the behavior of the KS Cloud client.
	KSCloudOption func(*ksCloudOptions)

	// ksCloudOptions holds all the configurable parts of the KS Cloud client.
	ksCloudOptions struct {
		httpClient     *http.Client
		cloudReportURL string
		timeout        *time.Duration
		withTrace      bool
	}

	// request option instructs post/get/delete to alter the outgoing request
	requestOption func(*requestOptions)

	// requestOptions knows how to enrich a request with headers
	requestOptions struct {
		withJSON   bool
		withTrace  bool
		headers    map[string]string
		reqContext context.Context
	}
)

// KS Cloud client options

// WithHTTPClient overrides the default http.Client used by the KS Cloud client.
func WithHTTPClient(client *http.Client) KSCloudOption {
	return func(o *ksCloudOptions) {
		o.httpClient = client
	}
}

// WithTimeout sets a global timeout on a operations performed by the KS Cloud client.
//
// A value of 0 means no timeout.
//
// The default is 61s.
func WithTimeout(timeout time.Duration) KSCloudOption {
	duration := timeout

	return func(o *ksCloudOptions) {
		o.timeout = &duration
	}
}

// WithReportURL specifies the URL to post reports.
func WithReportURL(u string) KSCloudOption {
	return func(o *ksCloudOptions) {
		o.cloudReportURL = u
	}
}

// WithTrace toggles requests dump for inspection & debugging.
func WithTrace(enabled bool) KSCloudOption {
	return func(o *ksCloudOptions) {
		o.withTrace = enabled
	}
}

var defaultClient = &http.Client{
	Timeout: 61 * time.Second,
}

// ksCloudOptionsWithDefaults sets defaults for the KS client and applies overrides.
func ksCloudOptionsWithDefaults(opts []KSCloudOption) *ksCloudOptions {
	options := &ksCloudOptions{
		httpClient: defaultClient,
	}

	for _, apply := range opts {
		apply(options)
	}

	if options.timeout != nil {
		// non-default timeout (0 means no timeout)
		// clone the client and override the timeout
		client := *options.httpClient
		client.Timeout = *options.timeout
		options.httpClient = &client
	}

	return options
}

// http request options

// withContentJSON sets JSON content type for a request
func withContentJSON(enabled bool) requestOption {
	return func(o *requestOptions) {
		o.withJSON = enabled
	}
}

// withExtraHeaders adds extra headers to a request
func withExtraHeaders(headers map[string]string) requestOption {
	return func(o *requestOptions) {
		o.headers = headers
	}
}

/* not used yet
// withContext sets the context of a request.
//
// By default, context.Background() is used.
func withContext(ctx context.Context) requestOption {
	return func(o *requestOptions) {
		o.reqContext = ctx
	}
}
*/

// withTrace dumps requests for debugging
func withTrace(enabled bool) requestOption {
	return func(o *requestOptions) {
		o.withTrace = enabled
	}
}

func (o *requestOptions) setHeaders(req *http.Request) {
	if o.withJSON {
		req.Header.Set("Content-Type", "application/json")
	}

	for k, v := range o.headers {
		req.Header.Set(k, v)
	}
}

// traceReq dumps the content of an outgoing request for inspecting or debugging the client.
func (o *requestOptions) traceReq(req *http.Request) {
	if !o.withTrace {
		return
	}

	dump, _ := httputil.DumpRequestOut(req, true)
	log.Printf("%s\n", dump)
}

// traceResp dumps the content of an API response for inspecting or debugging the client.
func (o *requestOptions) traceResp(resp *http.Response) {
	if !o.withTrace {
		return
	}

	dump, _ := httputil.DumpResponse(resp, true)
	log.Printf("%s\n", dump)
}

func requestOptionsWithDefaults(opts []requestOption) *requestOptions {
	o := &requestOptions{
		reqContext: context.Background(),
	}
	for _, apply := range opts {
		apply(o)
	}

	return o
}
