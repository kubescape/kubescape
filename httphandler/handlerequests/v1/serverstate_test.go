package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
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
	s.setBusy("scan-abc", func() {})

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
	s.setBusy("scan-xyz", func() {})
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
	s.setBusy("first", func() {})
	s.setBusy("second", func() {})

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
	h.state.setBusy("scan-123", func() {})

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

func TestStatus_WhenScanIsRunning_WithEmptyID_ResolvesViaLatestUserScanID(t *testing.T) {
	// This is the critical path for the in-cluster operator: it calls /status
	// without an ID to check whether any scan is currently running. The empty
	// ID resolves via latestUserScanID (set by Scan when the request is
	// queued), and the handler echoes that ID back in the response.
	h := &HTTPHandler{state: newServerState()}
	h.state.setBusy("scan-456", func() {})
	h.state.setLatestUserScanID("scan-456")

	rq := httptest.NewRequest(http.MethodGet, "/status", nil) // no ?id= param
	w := httptest.NewRecorder()
	h.Status(w, rq)

	resp := decodeResponse(t, w)
	if resp.Type != utilsapisv1.BusyScanResponseType {
		t.Errorf("Status with empty ID during scan: response.Type = %q; want %q: operator cannot detect running scan without latest-user-scan resolution",
			resp.Type, utilsapisv1.BusyScanResponseType)
	}
	if resp.ID != "scan-456" {
		t.Errorf("Status with empty ID during scan: response.ID = %q; want \"scan-456\": latestUserScanID must be reflected in response",
			resp.ID)
	}
}

// TestStatus_EmptyID_IgnoresMetricsScan guards the /v1/status half of the
// hijack: Metrics() calls setBusy but never setLatestUserScanID, so a scrape
// running on its own must not make /v1/status report a scan the caller never
// asked for.
func TestStatus_EmptyID_IgnoresMetricsScan(t *testing.T) {
	h := &HTTPHandler{state: newServerState()}
	h.state.setBusy("metrics-scan", func() {}) // what Metrics() does, and only that

	rq := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	h.Status(w, rq)

	resp := decodeResponse(t, w)
	if resp.Type != utilsapisv1.NotBusyScanResponseType {
		t.Errorf("Status with empty ID during a metrics-only scan: response.Type = %q; want %q: a /v1/metrics scrape must not be reported as the caller's scan",
			resp.Type, utilsapisv1.NotBusyScanResponseType)
	}
	if resp.ID != "" {
		t.Errorf("Status with empty ID during a metrics-only scan: response.ID = %q; want empty", resp.ID)
	}
}

// TestStatus_EmptyID_PrefersUserScanOverConcurrentMetricsScan is the exact
// race from the bug report: a metrics scrape lands while a user scan is still
// running, overwriting latestID. /v1/status must still report the user scan.
func TestStatus_EmptyID_PrefersUserScanOverConcurrentMetricsScan(t *testing.T) {
	h := &HTTPHandler{state: newServerState()}
	h.state.setBusy("user-scan", func() {})
	h.state.setLatestUserScanID("user-scan")
	h.state.setBusy("metrics-scan", func() {}) // scrape lands second, wins latestID

	if got := h.state.getLatestID(); got != "metrics-scan" {
		t.Fatalf("precondition: getLatestID() = %q; want \"metrics-scan\"", got)
	}

	rq := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	h.Status(w, rq)

	resp := decodeResponse(t, w)
	if resp.Type != utilsapisv1.BusyScanResponseType {
		t.Errorf("Status with empty ID: response.Type = %q; want %q", resp.Type, utilsapisv1.BusyScanResponseType)
	}
	if resp.ID != "user-scan" {
		t.Errorf("Status with empty ID: response.ID = %q; want \"user-scan\": a concurrent /v1/metrics scrape must not hijack the response",
			resp.ID)
	}
}

// TestServerState_UserScanIDLifecycle pins the split between the two
// user-scan fields. latestUserScanID must outlive the scan so the offline
// /v1/results fallback can still resolve it, while runningUserScanID must be
// cleared so CancelScan with no ID does not target a finished scan.
func TestServerState_UserScanIDLifecycle(t *testing.T) {
	s := newServerState()
	s.setBusy("user-scan", func() {})
	s.setLatestUserScanID("user-scan")  // Scan(), at enqueue
	s.setRunningUserScanID("user-scan") // watchForScan(), at dequeue

	if id := s.getRunningUserScanID(); id != "user-scan" {
		t.Errorf("getRunningUserScanID() while running = %q; want \"user-scan\"", id)
	}

	s.setNotBusy("user-scan") // scan finished

	if id := s.getLatestUserScanID(); id != "user-scan" {
		t.Errorf("getLatestUserScanID() after setNotBusy = %q; want \"user-scan\": must survive for the offline results fallback", id)
	}
	if id := s.getRunningUserScanID(); id != "" {
		t.Errorf("getRunningUserScanID() after setNotBusy = %q; want empty: no user scan is running", id)
	}
}

// ---------------------------------------------------------------------------
// admitUserScan concurrency tests
//
// Scan() runs one goroutine per HTTP request, so nothing orders two handlers
// against each other. If the enqueue and the latestUserScanID write are not in
// the same critical section, two requests accepted as A-then-B can record
// themselves as B-then-A, leaving "latest" on the older scan -- the same wrong
// -scan-reported-as-latest bug as the metrics hijack, from a different source.
// ---------------------------------------------------------------------------

func TestServerState_AdmitUserScan_BookkeepingFollowsAcceptanceOrder(t *testing.T) {
	s := newServerState()

	inFirstEnqueue := make(chan struct{})
	firstDone := make(chan struct{})
	secondDone := make(chan struct{})

	go func() {
		defer close(firstDone)
		// scan-A is accepted first and stalls inside its enqueue step. That
		// stall is the window the race needs: with the steps unserialized,
		// scan-B runs to completion during it and scan-A's write still lands
		// last, so "latest" ends up on scan-A.
		s.admitUserScan("scan-A", func() {}, func() bool {
			close(inFirstEnqueue)
			time.Sleep(100 * time.Millisecond)
			return true
		})
	}()

	<-inFirstEnqueue
	go func() {
		defer close(secondDone)
		s.admitUserScan("scan-B", func() {}, func() bool { return true })
	}()

	<-firstDone
	<-secondDone

	if id := s.getLatestUserScanID(); id != "scan-B" {
		t.Errorf("getLatestUserScanID() = %q; want \"scan-B\": latestUserScanID must follow acceptance order, not handler-goroutine scheduling", id)
	}
}

// TestServerState_AdmitUserScan_RejectedScanNeverBecomesLatest covers the
// rollback half: a request that loses the queue-full race must leave no trace,
// or a 429'd scan becomes the one Status and Results resolve to.
func TestServerState_AdmitUserScan_RejectedScanNeverBecomesLatest(t *testing.T) {
	s := newServerState()

	if !s.admitUserScan("accepted", func() {}, func() bool { return true }) {
		t.Fatal("admitUserScan returned false for a successful enqueue")
	}
	if s.admitUserScan("rejected", func() {}, func() bool { return false }) {
		t.Fatal("admitUserScan returned true for a failed enqueue")
	}

	if id := s.getLatestUserScanID(); id != "accepted" {
		t.Errorf("getLatestUserScanID() = %q; want \"accepted\": a rejected scan must not become the latest user scan", id)
	}
	if s.isBusy("rejected") {
		t.Errorf("isBusy(\"rejected\") = true; want false: a failed admission must roll its busy entry back")
	}
	if l := s.len(); l != 1 {
		t.Errorf("len() = %d; want 1: only the accepted scan may remain registered", l)
	}
}

// TestServerState_AdmitUserScan_ConcurrentAdmissions is the stress form, most
// useful under -race: every concurrent admission must register exactly once,
// and "latest" must be one of the scans that was actually accepted.
func TestServerState_AdmitUserScan_ConcurrentAdmissions(t *testing.T) {
	s := newServerState()

	const admissions = 50
	ids := make([]string, admissions)
	var wg sync.WaitGroup
	for i := range ids {
		ids[i] = fmt.Sprintf("scan-%02d", i)
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			if !s.admitUserScan(id, func() {}, func() bool { return true }) {
				t.Errorf("admitUserScan(%q) = false; want true", id)
			}
		}(ids[i])
	}
	wg.Wait()

	if l := s.len(); l != admissions {
		t.Errorf("len() = %d; want %d: every accepted scan must be registered exactly once", l, admissions)
	}

	latest := s.getLatestUserScanID()
	if !slices.Contains(ids, latest) {
		t.Errorf("getLatestUserScanID() = %q; want one of the admitted scan IDs", latest)
	}
}

func TestStatus_AfterScanCompletes_ReturnsNotBusy(t *testing.T) {
	// Simulates the full lifecycle: scan starts, completes, then operator polls.
	// Without this test a regression where setNotBusy fails to clear the state
	// would cause the operator to believe a scan is running indefinitely.
	h := &HTTPHandler{state: newServerState()}
	h.state.setBusy("scan-789", func() {})
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

// TestStatus_InvalidQueryParams_Returns400 guards against a regression where
// Status called w.WriteHeader(500) before handler.writeError(), which itself
// calls w.WriteHeader(400) - the second call is a silent no-op in net/http,
// so the client always got 500 regardless of the intended 400.
func TestStatus_InvalidQueryParams_Returns400(t *testing.T) {
	h := &HTTPHandler{state: newServerState()}

	// StatusQueryParams only declares "id"; an unknown key makes gorilla/schema's
	// decoder return an error.
	rq := httptest.NewRequest(http.MethodGet, "/status?unknownParam=x", nil)
	w := httptest.NewRecorder()
	h.Status(w, rq)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("Status with invalid query params = HTTP %d; want %d", w.Result().StatusCode, http.StatusBadRequest)
	}

	resp := decodeResponse(t, w)
	if resp.Type != utilsapisv1.ErrorScanResponseType {
		t.Errorf("Status with invalid query params: response.Type = %q; want %q", resp.Type, utilsapisv1.ErrorScanResponseType)
	}
	message, _ := resp.Response.(string)
	if !strings.Contains(message, "failed to parse query params") {
		t.Errorf("Status with invalid query params: response.Response = %q; want it to describe the decode failure", resp.Response)
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
	scanImpl = func(_ context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
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

func TestScan_WhenScanPanics_RecoversAndReturns500(t *testing.T) {
	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanImpl = func(_ context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
		panic("boom")
	}

	h := NewHTTPHandler(false)
	rq := httptest.NewRequest(http.MethodPost, "/scan?wait=true", testBody(t))
	w := httptest.NewRecorder()

	// Must not crash the test process — the panic recovery in executeScan must
	// contain the failure to a single scan and keep the operator alive.
	h.Scan(w, rq)

	rs := w.Result()
	if rs.StatusCode != http.StatusInternalServerError {
		t.Errorf("Scan panic: HTTP status = %d; want %d", rs.StatusCode, http.StatusInternalServerError)
	}

	var resp utilsmetav1.Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode Scan panic response: %v", err)
	}
	if resp.Type != utilsapisv1.ErrorScanResponseType {
		t.Errorf("Scan panic: response.Type = %q; want %q", resp.Type, utilsapisv1.ErrorScanResponseType)
	}
	if resp.Response == "" {
		t.Errorf("Scan panic: response.Response is empty; want panic message")
	}

	// The scan slot must be released so the operator is not stuck busy forever.
	if h.state.isBusy("") {
		t.Errorf("Scan panic: handler state is still busy after recovery; scan slot must be released")
	}
}
