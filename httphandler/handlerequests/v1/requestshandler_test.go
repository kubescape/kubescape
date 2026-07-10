package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

func testBody(t *testing.T) io.Reader {
	t.Helper()
	b, err := json.Marshal(utilsmetav1.PostScanRequest{Account: "fakeFoobar"})
	if err != nil {
		t.Fatal("Can not marshal")
	}
	return bytes.NewReader(b)
}

type scanner func(_ context.Context, _ *cautils.ScanInfo, _ string, _ bool) (*reporthandlingv2.PostureReport, error)

// TestScan tests that the scan handler passes the scan requests correctly to the underlying scan engine.
func TestScan(t *testing.T) {

	// Our scanner is not setting up the k8s connection; the test is covering the rest of the wiring
	// that the signaling from the http handler goes all the way to the scanner implementation.
	withTempOutputDirs(t)

	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanImpl = func(_ context.Context, _ *cautils.ScanInfo, scanID string, _ bool) (*reporthandlingv2.PostureReport, error) {
		report := &reporthandlingv2.PostureReport{}
		b, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(OutputDir, scanID+".json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
		return nil, nil
	}

	var (
		h  = NewHTTPHandler(false)
		rq = httptest.NewRequest("POST", "/scan?wait=true&keep=true", testBody(t))
		w  = httptest.NewRecorder()
	)
	h.Scan(w, rq)
	rs := w.Result()
	body, _ := io.ReadAll(rs.Body)

	var resp utilsmetav1.Response
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("failed to decode Scan response body: %v", err)
	}

	if rs.StatusCode != http.StatusOK {
		t.Errorf("Scan status code = %d, want %d", rs.StatusCode, http.StatusOK)
	}
	if resp.Type != utilsapisv1.ResultsV1ScanResponseType {
		t.Errorf("Scan response type = %v, want %v", resp.Type, utilsapisv1.ResultsV1ScanResponseType)
	}
	if resp.Response == nil {
		t.Errorf("Scan response.Response is nil, want populated PostureReport")
	}
}

// TestScan_SyncResponse covers the sync response branch that populates
// response.Response from the on-disk results file (requestshandler.go:130-138).
func TestScan_SyncResponse(t *testing.T) {
	tests := []struct {
		name         string
		writeResults bool
		wantType     utilsapisv1.ScanResponseType
	}{
		{
			name:         "results file present returns populated report",
			writeResults: true,
			wantType:     utilsapisv1.ResultsV1ScanResponseType,
		},
		{
			name:         "results file missing returns error",
			writeResults: false,
			wantType:     utilsapisv1.ErrorScanResponseType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withTempOutputDirs(t)

			defer func(o scanner) { scanImpl = o }(scanImpl)
			scanImpl = func(_ context.Context, _ *cautils.ScanInfo, scanID string, _ bool) (*reporthandlingv2.PostureReport, error) {
				if tt.writeResults {
					b, err := json.Marshal(&reporthandlingv2.PostureReport{})
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(OutputDir, scanID+".json"), b, 0o644); err != nil {
						t.Fatal(err)
					}
				}
				return nil, nil
			}

			var (
				h  = NewHTTPHandler(false)
				rq = httptest.NewRequest("POST", "/scan?wait=true&keep=true", testBody(t))
				w  = httptest.NewRecorder()
			)
			h.Scan(w, rq)
			rs := w.Result()
			body, _ := io.ReadAll(rs.Body)

			var resp utilsmetav1.Response
			if err := json.Unmarshal(body, &resp); err != nil {
				t.Fatalf("failed to decode Scan response body: %v", err)
			}

			if resp.Type != tt.wantType {
				t.Errorf("response type = %v, want %v", resp.Type, tt.wantType)
			}

			switch tt.wantType {
			case utilsapisv1.ResultsV1ScanResponseType:
				if resp.Response == nil {
					t.Errorf("response.Response is nil, want populated PostureReport")
				}
			case utilsapisv1.ErrorScanResponseType:
				msg, ok := resp.Response.(string)
				if !ok || msg == "" {
					t.Errorf("response.Response = %v, want non-empty error message", resp.Response)
				}
			}
		})
	}
}

// ============================================== STATUS ========================================================
// Status API
// func TestStatus(t *testing.T) {

// 	{
// 		httpHandler := NewHTTPHandler()

// 		u := url.URL{
// 			Scheme:   "http",
// 			Host:     "bla",
// 			Path:     "bla",
// 			RawQuery: "wait=true&keep=true",
// 		}
// 		request, err := http.NewRequest(http.MethodPost, u.String(), nil)
// 		httpHandler.Status(nil, request)

// 		assert.NoError(t, err)

// 		scanID := "ccccccc"

// 		req, err := getScanParamsFromRequest(request, scanID)
// 		assert.NoError(t, err)
// 		assert.Equal(t, scanID, req.scanID)
// 		assert.True(t, req.scanQueryParams.KeepResults)
// 		assert.True(t, req.scanQueryParams.ReturnResults)
// 		assert.True(t, *req.scanRequest.HostScanner)
// 		assert.True(t, *req.scanRequest.Submit)
// 		assert.Equal(t, "aaaaaaaaaa", req.scanRequest.Account)
// 	}
// }

func TestResultsDeleteAll(t *testing.T) {
	h := NewHTTPHandler(false)

	rq := httptest.NewRequest("DELETE", "/results?all=true", nil)
	w := httptest.NewRecorder()

	h.Results(w, rq)
	rs := w.Result()

	if rs.StatusCode != http.StatusOK {
		t.Errorf("Expected StatusOK (200), got %v", rs.StatusCode)
	}

	// Also verify that a normal DELETE without all=true and no ScanID fails
	rq = httptest.NewRequest("DELETE", "/results", nil)
	w = httptest.NewRecorder()

	h.Results(w, rq)
	rs = w.Result()

	if rs.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected StatusBadRequest (400) for missing ScanID, got %v", rs.StatusCode)
	}
}
