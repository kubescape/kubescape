package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
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
	defer func(o scanner) { scanImpl = o }(scanImpl)
	scanImpl = func(context.Context, *cautils.ScanInfo, string, bool) (*reporthandlingv2.PostureReport, error) {
		return nil, nil
	}

	var (
		h  = NewHTTPHandler(false)
		rq = httptest.NewRequest("POST", "/scan?wait=true", testBody(t))
		w  = httptest.NewRecorder()
	)
	h.Scan(w, rq)
	rs := w.Result()
	body, _ := io.ReadAll(rs.Body)

	type out struct {
		code  int
		ctype string
		body  string
	}
	want := out{200, "application/json", `{"id":"","type":"v1results"}`}
	got := out{rs.StatusCode, rs.Header.Get("Content-type"), string(body)}

	if got != want {
		t.Errorf("Scan result: %v,  want %v", got, want)
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
