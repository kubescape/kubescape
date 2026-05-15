package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

// ---------------------------------------------------------------------------
// serverState unit tests
// These cover the core state machine that drives Status and Results handlers.
// No tests existed for this type before; a regression here silently breaks
// every async scan polling loop (in-cluster operator, CI/CD pipelines).
// ---------------------------------------------------------------------------

func TestServerState_InitialState(t *testing.T) {
	s := newServerState()

	// Freshly created state must report not-busy for any ID,
	// including empty string — callers use "" to mean "latest".
	if s.isBusy("") {
		t.Errorf("isBusy(\"\") on fresh state = true; want false: no scan has been registered yet")
	}
	if s.isBusy("some-id") {
		t.Errorf("isBusy(\"some-id\") on fresh state = true; want false")
	}
	if id := s.getLatestID(); id != "" {
		t.Errorf("getLatestID() on fresh state = %q; want empty string", id)
	}
	if l := s.len(); l != 0 {
		t.Errorf("len() on fresh state = %d; want 0", l)
	}
}

func TestServerState_SetBusyMakesIDReachable(t *testing.T) {
	s := newServerState()
	s.setBusy("scan-abc")

	// After setBusy the ID must be visible.
	if !s.isBusy("scan-abc") {
		t.Errorf("isBusy(\"scan-abc\") after setBusy = false; want true")
	}
	// latestID must be updated so empty-string queries resolve to the new scan.
	if id := s.getLatestID(); id != "scan-abc" {
		t.Errorf("getLatestID() after setBusy(\"scan-abc\") = %q; want \"scan-abc\"", id)
	}
	// isBusy("") resolves via latestID — this is the code path exercised by
	// the operator when it polls without knowing the exact scan UUID.
	if !s.isBusy("") {
		t.Errorf("isBusy(\"\") after setBusy(\"scan-abc\") = false; want true: empty-ID must resolve via latestID")
	}
	if l := s.len(); l != 1 {
		t.Errorf("len() after one setBusy = %d; want 1", l)
	}
}

func TestServerState_SetNotBusyClearsID(t *testing.T) {
	s := newServerState()
	s.setBusy("scan-xyz")
	s.setNotBusy("scan-xyz")

	// After completion the scan must report not-busy.
	if s.isBusy("scan-xyz") {
		t.Errorf("isBusy(\"scan-xyz\") after setNotBusy = true; want false: completed scan must not appear busy")
	}
	// Empty-ID query must also resolve to not-busy:
	// the operator polls with "" before it has the UUID and must see "done".
	if s.isBusy("") {
		t.Errorf("isBusy(\"\") after setNotBusy = true; want false: latestID still points to the completed scan")
	}
	// latestID is intentionally NOT cleared by setNotBusy so the Results
	// handler can resolve the most-recent scan ID for result retrieval.
	if id := s.getLatestID(); id != "scan-xyz" {
		t.Errorf("getLatestID() after setNotBusy = %q; want \"scan-xyz\": latestID must survive for results lookup", id)
	}
	if l := s.len(); l != 0 {
		t.Errorf("len() after setNotBusy = %d; want 0", l)
	}
}

func TestServerState_LatestIDTracksLastRegisteredScan(t *testing.T) {
	s := newServerState()
	s.setBusy("first")
	s.setBusy("second")

	// latestID must always reflect the most recent setBusy call.
	if id := s.getLatestID(); id != "second" {
		t.Errorf("getLatestID() after two setBusy calls = %q; want \"second\"", id)
	}
	// Both scans must be independently trackable.
	if !s.isBusy("first") {
		t.Errorf("isBusy(\"first\") with two concurrent scans = false; want true")
	}
	if !s.isBusy("second") {
		t.Errorf("isBusy(\"second\") with two concurrent scans = false; want true")
	}
	if l := s.len(); l != 2 {
		t.Errorf("len() with two concurrent scans = %d; want 2", l)
	}
}

// ---------------------------------------------------------------------------
// HTTPHandler.Status endpoint tests
//
// The original TestStatus was commented out (requestshandler_test.go:59-88),
// leaving the entire Status handler path untested. The Status endpoint is the
// primary polling mechanism used by the in-cluster operator and CI/CD
// pipelines to detect when an async scan has finished. A regression that
// returns the wrong response type will cause infinite polling loops or
// premature result reads.
// ---------------------------------------------------------------------------

// decodeResponse is a test helper that decodes the JSON response body.
func decodeResponse(t *testing.T, w *httptest.ResponseRecorder) utilsmetav1.Response {
	t.Helper()
	var resp utilsmetav1.Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode Status response body: %v", err)
	}
	return resp
}

func TestStatus_WhenNoScanHasRun_ReturnsNotBusy(t *testing.T) {
	h := &HTTPHandler{state: newServerState()}

	rq := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	h.Status(w, rq)

	rs := w.Result()
	// HTTP 200 is always returned by Status regardless of busy state.
	if rs.StatusCode != http.StatusOK {
		t.Errorf("Status with no scan = HTTP %d; want %d", rs.StatusCode, http.StatusOK)
	}
	resp := decodeResponse(t, w)
	// The response type drives all polling logic — an empty or wrong type
	// would cause the operator to spin forever or read results prematurely.
	if resp.Type != utilsapisv1.NotBusyScanResponseType {
		t.Errorf("Status with no scan: response.Type = %q; want %q", resp.Type, utilsapisv1.NotBusyScanResponseType)
	}
}

func TestStatus_WhenScanIsRunning_WithExplicitID_ReturnsBusy(t *testing.T) {
	h := &HTTPHandler{state: newServerState()}
	h.state.setBusy("scan-123")

	rq := httptest.NewRequest(http.MethodGet, "/status?id=scan-123", nil)
	w := httptest.NewRecorder()
	h.Status(w, rq)

	rs := w.Result()
	if rs.StatusCode != http.StatusOK {
		t.Errorf("Status during scan = HTTP %d; want %d", rs.StatusCode, http.StatusOK)
	}
	resp := decodeResponse(t, w)
	if resp.Type != utilsapisv1.BusyScanResponseType {
		t.Errorf("Status during scan: response.Type = %q; want %q (scan is still running)", resp.Type, utilsapisv1.BusyScanResponseType)
	}
	// The response must echo back the scan ID so the caller can correlate.
	if resp.ID != "scan-123" {
		t.Errorf("Status during scan: response.ID = %q; want \"scan-123\"", resp.ID)
	}
}

func TestStatus_WhenScanIsRunning_WithEmptyID_ResolvesViaLatestID(t *testing.T) {
	// This is the critical path for the in-cluster operator: it calls /status
	// without an ID to check whether any scan is currently running.
	// isBusy("") resolves to statusID[latestID], and then the handler
	// populates the response ID from getLatestID(). Both steps are untested.
	h := &HTTPHandler{state: newServerState()}
	h.state.setBusy("scan-456")

	rq := httptest.NewRequest(http.MethodGet, "/status", nil) // no ?id= param
	w := httptest.NewRecorder()
	h.Status(w, rq)

	resp := decodeResponse(t, w)
	if resp.Type != utilsapisv1.BusyScanResponseType {
		t.Errorf("Status with empty ID during scan: response.Type = %q; want %q: operator cannot detect running scan without latestID resolution",
			resp.Type, utilsapisv1.BusyScanResponseType)
	}
	if resp.ID != "scan-456" {
		t.Errorf("Status with empty ID during scan: response.ID = %q; want \"scan-456\": latestID must be reflected in response",
			resp.ID)
	}
}

func TestStatus_AfterScanCompletes_ReturnsNotBusy(t *testing.T) {
	// Simulates the full lifecycle: scan starts, completes, then operator polls.
	// Without this test a regression where setNotBusy fails to clear the state
	// would cause the operator to believe a scan is running indefinitely.
	h := &HTTPHandler{state: newServerState()}
	h.state.setBusy("scan-789")
	h.state.setNotBusy("scan-789") // scan finished

	rq := httptest.NewRequest(http.MethodGet, "/status?id=scan-789", nil)
	w := httptest.NewRecorder()
	h.Status(w, rq)

	resp := decodeResponse(t, w)
	if resp.Type != utilsapisv1.NotBusyScanResponseType {
		t.Errorf("Status after scan completes: response.Type = %q; want %q: completed scan must not appear busy",
			resp.Type, utilsapisv1.NotBusyScanResponseType)
	}
}

func TestStatus_NonGetMethod_Returns405(t *testing.T) {
	h := &HTTPHandler{state: newServerState()}

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			rq := httptest.NewRequest(method, "/status", nil)
			w := httptest.NewRecorder()
			h.Status(w, rq)
			if w.Result().StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("Status with method %s = HTTP %d; want %d",
					method, w.Result().StatusCode, http.StatusMethodNotAllowed)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// executeScan error-path test
//
// The existing TestScan only covers the happy path (scanImpl returns nil, nil).
// The error path — where scanImpl returns an error with wait=true — is
// critical: CI/CD pipelines rely on HTTP 500 to detect scan failures.
// If this path regresses to return HTTP 200, pipelines would pass on broken scans.
// ---------------------------------------------------------------------------

func TestScan_WhenScanFails_Returns500WithErrorType(t *testing.T) {
	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanImpl = func(_ context.Context, _ *cautils.ScanInfo, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
		return nil, fmt.Errorf("rego evaluation failed: module not found")
	}

	h := NewHTTPHandler(false)
	rq := httptest.NewRequest(http.MethodPost, "/scan?wait=true", testBody(t))
	w := httptest.NewRecorder()
	h.Scan(w, rq)

	rs := w.Result()
	// CI/CD pipelines check the HTTP status code to detect scan failure.
	// A regression returning 200 here would silently pass a broken scan.
	if rs.StatusCode != http.StatusInternalServerError {
		t.Errorf("Scan failure: HTTP status = %d; want %d (scan error must not return 200)",
			rs.StatusCode, http.StatusInternalServerError)
	}

	var resp utilsmetav1.Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode Scan error response: %v", err)
	}
	// The response type must signal error so consumers don't treat failure as success.
	if resp.Type != utilsapisv1.ErrorScanResponseType {
		t.Errorf("Scan failure: response.Type = %q; want %q", resp.Type, utilsapisv1.ErrorScanResponseType)
	}
	// The error message must be present so operators can surface it.
	if resp.Response == "" {
		t.Errorf("Scan failure: response.Response is empty; want scan error message")
	}
}
