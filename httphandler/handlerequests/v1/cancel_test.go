package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v3/core/cautils"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

// ---------------------------------------------------------------------------
// HTTPHandler.CancelScan endpoint tests
//
// CancelScan is the only way to stop a scan once it has been accepted: the
// scan context is otherwise detached from the request via
// context.WithoutCancel, so a stuck scan can only be cleared by cancelling
// its stored context. These tests drive a real in-flight scan through the
// watchForScan goroutine to prove cancellation actually reaches scanImpl.
// ---------------------------------------------------------------------------

func TestCancelScan_UnblocksBlockedScan_ReturnsErrorType(t *testing.T) {
	withTempOutputDirs(t)

	scanStarted := make(chan struct{})
	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanImpl = func(ctx context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
		close(scanStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	}

	h := NewHTTPHandler(false)

	scanDone := make(chan *http.Response, 1)
	go func() {
		rq := httptest.NewRequest(http.MethodPost, "/scan?wait=true", testBody(t))
		w := httptest.NewRecorder()
		h.Scan(w, rq)
		scanDone <- w.Result()
	}()

	select {
	case <-scanStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("scan was never picked up by watchForScan")
	}

	scanID := h.state.getLatestID()

	cancelRq := httptest.NewRequest(http.MethodDelete, "/scan?id="+scanID, nil)
	cancelW := httptest.NewRecorder()
	h.CancelScan(cancelW, cancelRq)

	if cancelW.Result().StatusCode != http.StatusOK {
		t.Fatalf("CancelScan status = %d, want %d", cancelW.Result().StatusCode, http.StatusOK)
	}

	select {
	case rs := <-scanDone:
		var resp utilsmetav1.Response
		if err := json.NewDecoder(rs.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode Scan response: %v", err)
		}
		if resp.Type != utilsapisv1.ErrorScanResponseType {
			t.Errorf("Scan response type after cancellation = %v, want %v", resp.Type, utilsapisv1.ErrorScanResponseType)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked scan did not unblock after cancellation")
	}
}

func TestCancelScan_MarksNotBusy(t *testing.T) {
	withTempOutputDirs(t)

	scanStarted := make(chan struct{})
	releaseScan := make(chan struct{})
	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanImpl = func(ctx context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
		close(scanStarted)
		<-ctx.Done()
		<-releaseScan
		return nil, ctx.Err()
	}

	h := NewHTTPHandler(false)

	scanDone := make(chan *http.Response, 1)
	go func() {
		rq := httptest.NewRequest(http.MethodPost, "/scan?wait=true", testBody(t))
		w := httptest.NewRecorder()
		h.Scan(w, rq)
		scanDone <- w.Result()
	}()

	select {
	case <-scanStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("scan was never picked up by watchForScan")
	}

	scanID := h.state.getLatestID()

	cancelRq := httptest.NewRequest(http.MethodDelete, "/scan?id="+scanID, nil)
	cancelW := httptest.NewRecorder()
	h.CancelScan(cancelW, cancelRq)

	if cancelW.Result().StatusCode != http.StatusOK {
		t.Fatalf("CancelScan status = %d, want %d", cancelW.Result().StatusCode, http.StatusOK)
	}

	// cancel() only invokes the CancelFunc and marks the entry cancelled; it
	// must not remove it. The scan stays busy until executeScan itself calls
	// setNotBusy once scanImpl actually returns.
	if !h.state.isBusy(scanID) {
		t.Errorf("isBusy(%q) immediately after CancelScan = false; want true: entry must survive until executeScan calls setNotBusy", scanID)
	}

	close(releaseScan)

	select {
	case <-scanDone:
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not complete after being released")
	}

	if h.state.isBusy(scanID) {
		t.Errorf("isBusy(%q) after executeScan completes = true; want false", scanID)
	}
}

func TestCancelScan_UnknownID_Returns404(t *testing.T) {
	h := &HTTPHandler{state: newServerState()}

	rq := httptest.NewRequest(http.MethodDelete, "/scan?id=does-not-exist", nil)
	w := httptest.NewRecorder()
	h.CancelScan(w, rq)

	if w.Result().StatusCode != http.StatusNotFound {
		t.Errorf("CancelScan with unknown ID = HTTP %d; want %d", w.Result().StatusCode, http.StatusNotFound)
	}

	var resp utilsmetav1.Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode CancelScan response: %v", err)
	}
	if resp.Type != utilsapisv1.ErrorScanResponseType {
		t.Errorf("CancelScan with unknown ID: response.Type = %q; want %q", resp.Type, utilsapisv1.ErrorScanResponseType)
	}
}

func TestCancelScan_EmptyID_CancelsLatest(t *testing.T) {
	withTempOutputDirs(t)

	scanStarted := make(chan struct{})
	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanImpl = func(ctx context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
		close(scanStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	}

	h := NewHTTPHandler(false)

	scanDone := make(chan *http.Response, 1)
	go func() {
		rq := httptest.NewRequest(http.MethodPost, "/scan?wait=true", testBody(t))
		w := httptest.NewRecorder()
		h.Scan(w, rq)
		scanDone <- w.Result()
	}()

	select {
	case <-scanStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("scan was never picked up by watchForScan")
	}

	scanID := h.state.getLatestID()

	// No ?id= query param: must resolve to the currently-executing user scan.
	cancelRq := httptest.NewRequest(http.MethodDelete, "/scan", nil)
	cancelW := httptest.NewRecorder()
	h.CancelScan(cancelW, cancelRq)

	if cancelW.Result().StatusCode != http.StatusOK {
		t.Fatalf("CancelScan with empty ID status = %d, want %d", cancelW.Result().StatusCode, http.StatusOK)
	}

	var resp utilsmetav1.Response
	if err := json.NewDecoder(cancelW.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode CancelScan response: %v", err)
	}
	if resp.ID != scanID {
		t.Errorf("CancelScan with empty ID: response.ID = %q; want %q (currently executing scan)", resp.ID, scanID)
	}

	select {
	case <-scanDone:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked scan did not unblock after cancelling via empty ID")
	}
}

// TestCancelScan_SkipsCancelledQueuedRequest_UnblocksWaitingCaller cancels a
// request that is still sitting in scanRequestChan, behind another scan that
// is currently executing. watchForScan must not run scanImpl for it once
// dequeued; it must instead respond with an error and release the busy slot.
// The second request is submitted directly (bypassing Scan's HTTP path) via a
// signal channel closed once it lands in scanRequestChan, so the test does
// not depend on timing.
func TestCancelScan_SkipsCancelledQueuedRequest_UnblocksWaitingCaller(t *testing.T) {
	withTempOutputDirs(t)

	firstStarted := make(chan struct{})
	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanImpl = func(ctx context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
		close(firstStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	}

	h := NewHTTPHandler(false)

	firstDone := make(chan *http.Response, 1)
	go func() {
		rq := httptest.NewRequest(http.MethodPost, "/scan?wait=true", testBody(t))
		w := httptest.NewRecorder()
		h.Scan(w, rq)
		firstDone <- w.Result()
	}()

	select {
	case <-firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("first scan was never picked up by watchForScan")
	}
	firstID := h.state.getLatestID()

	secondID := "22222222-3333-4444-5555-666666666666"
	secondCtx, secondCancel := context.WithCancel(context.Background())
	secondResp := make(chan *utilsmetav1.Response, 1)

	submitted := make(chan struct{})
	go func() {
		h.state.setBusy(secondID, secondCancel)
		h.scanRequestChan <- &scanRequestParams{
			scanID:          secondID,
			scanInfo:        &cautils.ScanInfo{},
			scanQueryParams: &ScanQueryParams{ReturnResults: true},
			ctx:             secondCtx,
			resp:            secondResp,
			isUserScan:      true,
		}
		close(submitted)
	}()

	select {
	case <-submitted:
	case <-time.After(2 * time.Second):
		t.Fatal("second request was never submitted to scanRequestChan")
	}

	cancelRq := httptest.NewRequest(http.MethodDelete, "/scan?id="+secondID, nil)
	cancelW := httptest.NewRecorder()
	h.CancelScan(cancelW, cancelRq)

	if cancelW.Result().StatusCode != http.StatusOK {
		t.Fatalf("CancelScan status = %d, want %d", cancelW.Result().StatusCode, http.StatusOK)
	}

	cleanupRq := httptest.NewRequest(http.MethodDelete, "/scan?id="+firstID, nil)
	cleanupW := httptest.NewRecorder()
	h.CancelScan(cleanupW, cleanupRq)
	<-firstDone

	select {
	case resp := <-secondResp:
		if resp.Type != utilsapisv1.ErrorScanResponseType {
			t.Errorf("queued scan response type = %v, want %v", resp.Type, utilsapisv1.ErrorScanResponseType)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued scan caller blocked forever after cancellation")
	}

	if h.state.isBusy(secondID) {
		t.Errorf("isBusy(%q) after skipped cancelled scan = true; want false", secondID)
	}
}

// TestCancelScan_WaitFalse_NoFailedArtifactLeftBehind covers a wait=false
// scan whose scanImpl writes a failure artifact before observing
// cancellation (mirroring what the real scan() does via
// writeScanErrorToFile). executeScan must remove that artifact on genuine
// cancellation rather than leave it in FailedOutputDir.
func TestCancelScan_WaitFalse_NoFailedArtifactLeftBehind(t *testing.T) {
	withTempOutputDirs(t)

	scanStarted := make(chan struct{})
	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanImpl = func(ctx context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier, scanID string, _ bool) (*reporthandlingv2.PostureReport, error) {
		close(scanStarted)
		<-ctx.Done()
		return nil, writeScanErrorToFile(ctx.Err(), scanID)
	}

	h := NewHTTPHandler(false)

	rq := httptest.NewRequest(http.MethodPost, "/scan", testBody(t)) // wait=false
	w := httptest.NewRecorder()
	h.Scan(w, rq)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("Scan (wait=false) status = %d, want %d", w.Result().StatusCode, http.StatusOK)
	}
	var acceptResp utilsmetav1.Response
	if err := json.NewDecoder(w.Body).Decode(&acceptResp); err != nil {
		t.Fatalf("failed to decode Scan (wait=false) response: %v", err)
	}
	scanID := acceptResp.ID

	select {
	case <-scanStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("scan was never picked up by watchForScan")
	}

	cancelRq := httptest.NewRequest(http.MethodDelete, "/scan?id="+scanID, nil)
	cancelW := httptest.NewRecorder()
	h.CancelScan(cancelW, cancelRq)

	if cancelW.Result().StatusCode != http.StatusOK {
		t.Fatalf("CancelScan status = %d, want %d", cancelW.Result().StatusCode, http.StatusOK)
	}

	deadline := time.Now().Add(2 * time.Second)
	for h.state.isBusy(scanID) {
		if time.Now().After(deadline) {
			t.Fatal("scan never released its busy slot after cancellation")
		}
		time.Sleep(10 * time.Millisecond)
	}

	failedPath := filepath.Join(FailedOutputDir, scanID)
	if _, err := os.Stat(failedPath); err == nil {
		t.Errorf("FailedOutputDir artifact %q exists after cancellation; want it removed", failedPath)
	}
}
