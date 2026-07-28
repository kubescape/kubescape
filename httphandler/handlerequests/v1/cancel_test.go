package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	scanImpl = func(ctx context.Context, _ *cautils.ScanInfo, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
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
	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanImpl = func(ctx context.Context, _ *cautils.ScanInfo, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
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

	if h.state.isBusy(scanID) {
		t.Errorf("isBusy(%q) after CancelScan = true; want false", scanID)
	}

	// Drain the goroutine so it doesn't leak past the test.
	<-scanDone
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
	scanImpl = func(ctx context.Context, _ *cautils.ScanInfo, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
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

	// No ?id= query param: must resolve to the latest (only) running scan.
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
		t.Errorf("CancelScan with empty ID: response.ID = %q; want %q (latest scan)", resp.ID, scanID)
	}

	select {
	case <-scanDone:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked scan did not unblock after cancelling via empty ID")
	}
}

func TestCancelScan_DrainsQueuedRequest_UnblocksWaitingCaller(t *testing.T) {
	withTempOutputDirs(t)

	firstStarted := make(chan struct{})
	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanImpl = func(ctx context.Context, _ *cautils.ScanInfo, _ string, _ bool) (*reporthandlingv2.PostureReport, error) {
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

	secondDone := make(chan *http.Response, 1)
	go func() {
		rq := httptest.NewRequest(http.MethodPost, "/scan?wait=true", testBody(t))
		w := httptest.NewRecorder()
		h.Scan(w, rq)
		secondDone <- w.Result()
	}()

	var secondID string
	for i := 0; i < 200; i++ {
		if h.state.len() == 2 {
			secondID = h.state.getLatestID()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if secondID == "" || secondID == firstID {
		t.Fatalf("second scan was never queued (secondID=%q, firstID=%q)", secondID, firstID)
	}

	cancelRq := httptest.NewRequest(http.MethodDelete, "/scan?id="+secondID, nil)
	cancelW := httptest.NewRecorder()
	h.CancelScan(cancelW, cancelRq)

	if cancelW.Result().StatusCode != http.StatusOK {
		t.Fatalf("CancelScan status = %d, want %d", cancelW.Result().StatusCode, http.StatusOK)
	}

	select {
	case rs := <-secondDone:
		var resp utilsmetav1.Response
		if err := json.NewDecoder(rs.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode second Scan response: %v", err)
		}
		if resp.Type != utilsapisv1.ErrorScanResponseType {
			t.Errorf("queued scan response type = %v, want %v", resp.Type, utilsapisv1.ErrorScanResponseType)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued scan caller blocked forever after cancellation")
	}

	cleanupRq := httptest.NewRequest(http.MethodDelete, "/scan?id="+firstID, nil)
	cleanupW := httptest.NewRecorder()
	h.CancelScan(cleanupW, cleanupRq)
	<-firstDone
}
