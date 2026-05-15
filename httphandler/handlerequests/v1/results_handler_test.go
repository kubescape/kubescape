package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
)

// ---------------------------------------------------------------------------
// HTTPHandler.Results endpoint tests
//
// The only existing test for Results — TestResultsDeleteAll — exercises an
// idle handler. Every branch of Results() that depends on handler.state being
// busy, on handler.offline being true, or on the isLatestFallback flag is
// completely uncovered. Those branches govern:
//   - whether an in-flight scan can be wiped by DELETE ?all=true,
//   - whether a polling operator sees a BUSY signal vs. silent 204,
//   - whether the "last good" posture report is preserved on offline GET.
// Regressing any of them produces a silent failure (false-green compliance
// result, result-data loss, infinite poll loop). These tests pin each branch.
// ---------------------------------------------------------------------------

// newResultsHandler returns a minimally-initialised handler suitable for
// driving Results() directly. We intentionally avoid NewHTTPHandler() so the
// watcher goroutine and scan channel are not started; Results() never reads
// from the scan channel, so this keeps tests hermetic.
func newResultsHandler(offline bool) *HTTPHandler {
	return &HTTPHandler{
		offline: offline,
		state:   newServerState(),
	}
}

// withTempOutputDirs redirects OutputDir / FailedOutputDir into t.TempDir()
// for the lifetime of the test, restoring the originals on cleanup.
func withTempOutputDirs(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "results")
	failed := filepath.Join(dir, "failed")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatalf("setup: mkdir results: %v", err)
	}
	if err := os.MkdirAll(failed, 0o755); err != nil {
		t.Fatalf("setup: mkdir failed: %v", err)
	}
	oldOut, oldFailed := OutputDir, FailedOutputDir
	OutputDir, FailedOutputDir = out, failed
	t.Cleanup(func() {
		OutputDir, FailedOutputDir = oldOut, oldFailed
	})
	return out
}

func decodeResultsResponse(t *testing.T, w *httptest.ResponseRecorder) utilsmetav1.Response {
	t.Helper()
	var resp utilsmetav1.Response
	if w.Body.Len() == 0 {
		return resp
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode Results response body: %v", err)
	}
	return resp
}

// ---------------------------------------------------------------------------
// 1. DELETE /results?all=true while a scan is in progress.
//
// state.removeAllIfIdle is the *only* guard preventing routine cleanup from
// wiping an in-flight scan's working directory. No test today fires this
// guard. If a regression inverts the guard, this test catches it before it
// reaches production — where it would silently delete an active scan's
// outputs and lead to a green-but-empty posture report.
// ---------------------------------------------------------------------------

func TestResults_DeleteAll_RefusedWhileScanInProgress(t *testing.T) {
	out := withTempOutputDirs(t)

	// Plant a sentinel file that *must* survive the rejected delete-all.
	sentinel := filepath.Join(out, "in-flight.sentinel")
	if err := os.WriteFile(sentinel, []byte("running"), 0o644); err != nil {
		t.Fatalf("setup: write sentinel: %v", err)
	}

	h := newResultsHandler(false)
	h.state.setBusy("scan-in-flight") // simulate an active scan

	rq := httptest.NewRequest(http.MethodDelete, "/results?all=true", nil)
	w := httptest.NewRecorder()
	h.Results(w, rq)

	// writeError() returns 400; the exact code matters less than the fact
	// that the request did NOT succeed (200) — a 200 would mean the guard
	// fired but the directory was still nuked.
	if w.Result().StatusCode == http.StatusOK {
		t.Errorf("DELETE ?all=true during scan returned HTTP 200; want non-200: "+
			"removeAllIfIdle guard must refuse to wipe an in-flight scan (got body %q)",
			w.Body.String())
	}

	// The sentinel proves the guard *also* prevented the destructive call,
	// not just produced a misleading status code. This catches a future
	// regression where the guard reports failure but executes anyway.
	if _, err := os.Stat(sentinel); err != nil {
		t.Errorf("in-flight sentinel was deleted by DELETE ?all=true during busy state: %v; "+
			"removeAllIfIdle must short-circuit before calling removeResultDirs", err)
	}

	resp := decodeResultsResponse(t, w)
	if resp.Type != utilsapisv1.ErrorScanResponseType {
		t.Errorf("DELETE ?all=true during scan: response.Type = %q; want %q "+
			"(callers detect the guard via the error type)",
			resp.Type, utilsapisv1.ErrorScanResponseType)
	}
}

// ---------------------------------------------------------------------------
// 2. GET /results?id=<busy-id>.
//
// The operator's poll loop relies on Results returning BusyScanResponseType
// while a scan is still running. A regression that drops into the "read
// results file" branch (which returns 204 No Content because the file does
// not yet exist) would cause the operator to mark the scan finished early
// and report "no findings" — i.e. a silent false-green.
// ---------------------------------------------------------------------------

func TestResults_GetWhileBusy_ReturnsBusyResponse(t *testing.T) {
	withTempOutputDirs(t)

	h := newResultsHandler(false)
	id := "123e4567-e89b-12d3-a456-426614174000"
	h.state.setBusy(id)

	rq := httptest.NewRequest(http.MethodGet, "/results?id="+id, nil)
	w := httptest.NewRecorder()
	h.Results(w, rq)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("GET /results?id=<busy> = HTTP %d; want %d "+
			"(busy branch must return 200 with Busy type, not 204/4xx)",
			w.Result().StatusCode, http.StatusOK)
	}

	resp := decodeResultsResponse(t, w)
	if resp.Type != utilsapisv1.BusyScanResponseType {
		t.Errorf("GET /results?id=<busy>: response.Type = %q; want %q "+
			"(operator polling logic terminates early without this signal)",
			resp.Type, utilsapisv1.BusyScanResponseType)
	}
	if resp.ID != id {
		t.Errorf("GET /results?id=<busy>: response.ID = %q; want %q "+
			"(callers correlate poll responses by ID)", resp.ID, id)
	}
}

// ---------------------------------------------------------------------------
// 3. GET /results with empty ID, server NOT in offline mode.
//
// Non-offline servers must reject empty-ID GETs with 400. This branch is the
// API contract for the SaaS-style configuration: there is no "latest" concept
// online because results are streamed off-box. A regression that returns the
// offline fallback here would expose another user's scan results.
// ---------------------------------------------------------------------------

func TestResults_GetEmptyID_NonOfflineReturns400(t *testing.T) {
	withTempOutputDirs(t)

	h := newResultsHandler(false) // offline = false

	rq := httptest.NewRequest(http.MethodGet, "/results", nil)
	w := httptest.NewRecorder()
	h.Results(w, rq)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("GET /results (empty id, non-offline) = HTTP %d; want %d "+
			"(empty ID in non-offline mode is a contract violation)",
			w.Result().StatusCode, http.StatusBadRequest)
	}
	resp := decodeResultsResponse(t, w)
	if resp.Type != utilsapisv1.ErrorScanResponseType {
		t.Errorf("GET /results (empty id, non-offline): response.Type = %q; want %q",
			resp.Type, utilsapisv1.ErrorScanResponseType)
	}
}

// ---------------------------------------------------------------------------
// 4. isLatestFallback preservation — table-driven for the boundary cases.
//
// The most-recently-added behaviour: in offline mode, when the client GETs
// /results with no ID, the handler resolves "latest", returns the file, but
// must NOT delete it even though KeepResults defaults to false. This is the
// "last good posture report" footgun that the isLatestFallback branch was
// introduced to fix. Currently zero tests touch it.
// ---------------------------------------------------------------------------

func TestResults_GetEmptyID_OfflineFallback_TableDriven(t *testing.T) {
	const validUUID = "11111111-2222-3333-4444-555555555555"

	type tc struct {
		name       string
		seedLatest bool                         // call setBusy/setNotBusy so latestID == validUUID
		writeFile  bool                         // create the result file on disk
		query      string                       // query string appended to /results
		wantStatus int
		wantType   utilsapisv1.ScanResponseType // zero value means "don't assert type"
		wantKept   bool                         // must the file still exist after the call?
	}

	cases := []tc{
		{
			name:       "no scan ever ran -> 400 latest-not-found",
			seedLatest: false,
			writeFile:  false,
			query:      "",
			wantStatus: http.StatusBadRequest,
			wantType:   utilsapisv1.ErrorScanResponseType,
			wantKept:   false,
		},
		{
			name:       "fallback resolves to latest, file MUST be preserved (KeepResults=false)",
			seedLatest: true,
			writeFile:  true,
			query:      "",
			wantStatus: http.StatusOK,
			wantType:   utilsapisv1.ResultsV1ScanResponseType,
			wantKept:   true,
		},
		{
			name:       "fallback resolves to latest, KeepResults=true also preserves",
			seedLatest: true,
			writeFile:  true,
			query:      "?keep=true",
			wantStatus: http.StatusOK,
			wantType:   utilsapisv1.ResultsV1ScanResponseType,
			wantKept:   true,
		},
		{
			name:       "explicit ID + KeepResults=false deletes (control case proving the test rig works)",
			seedLatest: true,
			writeFile:  true,
			query:      "?id=" + validUUID,
			wantStatus: http.StatusOK,
			wantType:   utilsapisv1.ResultsV1ScanResponseType,
			wantKept:   false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := withTempOutputDirs(t)
			h := newResultsHandler(true) // offline = true

			if c.seedLatest {
				h.state.setBusy(validUUID)
				h.state.setNotBusy(validUUID) // latestID survives, scan finished
			}
			resultFile := filepath.Join(out, validUUID)
			if c.writeFile {
				if err := os.WriteFile(resultFile, []byte("{}"), 0o644); err != nil {
					t.Fatalf("setup: write result file: %v", err)
				}
			}

			rq := httptest.NewRequest(http.MethodGet, "/results"+c.query, nil)
			w := httptest.NewRecorder()
			h.Results(w, rq)

			if w.Result().StatusCode != c.wantStatus {
				t.Errorf("status = %d; want %d (body=%q)",
					w.Result().StatusCode, c.wantStatus, w.Body.String())
			}

			// Assert response type when the case specifies one. This verifies
			// the API contract (e.g. ErrorScanResponseType on 400) so callers
			// that switch on Type rather than status code also behave correctly.
			if c.wantType != "" {
				resp := decodeResultsResponse(t, w)
				if resp.Type != c.wantType {
					t.Errorf("response.Type = %q; want %q", resp.Type, c.wantType)
				}
			}

			// Critical assertion: the isLatestFallback branch protects the
			// file from `defer removeResultsFile(...)`. If a refactor removes
			// that branch, the file will be gone here.
			if c.writeFile {
				_, statErr := os.Stat(resultFile)
				gotKept := statErr == nil
				if gotKept != c.wantKept {
					t.Errorf("result file kept = %v; want %v "+
						"(isLatestFallback must preserve last-good report when "+
						"ID was resolved from latest)", gotKept, c.wantKept)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 5. DELETE /results with empty ID in offline mode MUST be rejected.
//
// The same isLatestFallback guard also rejects deletion without an explicit
// ID — otherwise a single misrouted DELETE wipes the only copy of the latest
// report. This branch (requestshandler.go:236) is uncovered.
// ---------------------------------------------------------------------------

func TestResults_DeleteEmptyID_OfflineRejected(t *testing.T) {
	const validUUID = "22222222-3333-4444-5555-666666666666"
	out := withTempOutputDirs(t)

	h := newResultsHandler(true)
	h.state.setBusy(validUUID)
	h.state.setNotBusy(validUUID) // latestID == validUUID, scan idle

	resultFile := filepath.Join(out, validUUID)
	if err := os.WriteFile(resultFile, []byte("{}"), 0o644); err != nil {
		t.Fatalf("setup: write result file: %v", err)
	}

	rq := httptest.NewRequest(http.MethodDelete, "/results", nil)
	w := httptest.NewRecorder()
	h.Results(w, rq)

	// writeError() short-circuits with 400; what matters is that the file
	// survives. A regression where the isLatestFallback check is dropped
	// from the DELETE branch will silently remove the last-good report.
	if _, err := os.Stat(resultFile); err != nil {
		t.Errorf("DELETE /results (empty id, offline) removed the last-good report "+
			"resolved via latestID: %v; isLatestFallback must reject deletion", err)
	}

	resp := decodeResultsResponse(t, w)
	if resp.Type != utilsapisv1.ErrorScanResponseType {
		t.Errorf("DELETE /results (empty id, offline): response.Type = %q; want %q "+
			"(callers detect the rejection via error type)",
			resp.Type, utilsapisv1.ErrorScanResponseType)
	}
}
