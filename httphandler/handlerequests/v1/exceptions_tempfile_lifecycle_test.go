package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every request in these tests that carries exceptions makes ToScanInfo write
// a kubescape-exceptions-*.json file. Each test asserts that no such file is
// left once the request's lifecycle has ended, whichever way it ended.
const exceptionsScanBody = `{"exceptions":[{"name":"exclude-kube-system","policyType":"postureExceptionPolicy","actions":["alertOnly"],"resources":[{"designatorType":"Attributes","attributes":{"namespace":"kube-system"}}],"posturePolicies":[{"controlID":"C-0034"}]}]}`

// isolateExceptionsTempDir points os.TempDir at a fresh directory, so the test
// sees exactly the exceptions files this handler creates.
func isolateExceptionsTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, env := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(env, dir)
	}
	require.Equal(t, filepath.Clean(dir), filepath.Clean(os.TempDir()))
	return dir
}

// exceptionsTempFiles lists the exceptions temp files currently in dir.
func exceptionsTempFiles(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "kubescape-exceptions-*.json"))
	require.NoError(t, err)
	return files
}

// coreScanHarness replaces only the scanner construction seam. A request
// without exceptions is the "blocker": it holds the worker until released or
// cancelled. A request with exceptions runs the real core scanner, which fails
// fast during initialization because its artifacts directory does not exist.
// Executed requests therefore clean up through core's own lifecycle, never
// through the test.
type coreScanHarness struct {
	blockerStarted chan string
	releaseBlocker chan struct{}

	mu       sync.Mutex
	executed []string // UseExceptions paths of requests that reached the scanner
}

// installCoreScanHarness installs the harness described on coreScanHarness
// and restores the original scanner seams when the test ends.
func installCoreScanHarness(t *testing.T) *coreScanHarness {
	t.Helper()
	withTempOutputDirs(t)
	// Never let the real scanner reach a contributor's cluster.
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing-kubeconfig"))
	missingArtifacts := filepath.Join(t.TempDir(), "missing-artifacts")

	h := &coreScanHarness{
		blockerStarted: make(chan string, 16),
		releaseBlocker: make(chan struct{}),
	}
	originalScan, originalRun := scanImpl, runKubescapeScan
	t.Cleanup(func() { scanImpl, runKubescapeScan = originalScan, originalRun })
	scanImpl = scan
	runKubescapeScan = func(ctx context.Context, scanInfo *cautils.ScanInfo, policyIdentifiers []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
		if scanInfo.UseExceptions == "" {
			h.blockerStarted <- scanInfo.ScanID
			select {
			case <-h.releaseBlocker:
			case <-ctx.Done():
			}
			return nil, fmt.Errorf("blocker scan finished")
		}
		h.mu.Lock()
		h.executed = append(h.executed, scanInfo.UseExceptions)
		h.mu.Unlock()
		scanInfo.UseArtifactsFrom = missingArtifacts
		return core.NewKubescape(ctx).Scan(scanInfo, policyIdentifiers)
	}
	return h
}

// executedCount reports how many requests with exceptions reached the scanner.
func (h *coreScanHarness) executedCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.executed)
}

// postScan sends POST /v1/scan through the handler and records the response.
func postScan(handler *HTTPHandler, query, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	handler.Scan(w, httptest.NewRequest(http.MethodPost, "/v1/scan"+query, bytes.NewBufferString(body)))
	return w
}

// cancelScanRequest sends DELETE /v1/scan?id=scanID through the handler.
func cancelScanRequest(handler *HTTPHandler, scanID string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	handler.CancelScan(w, httptest.NewRequest(http.MethodDelete, "/v1/scan?id="+scanID, nil))
	return w
}

// responseScanID returns the scan ID from a /v1/scan response.
func responseScanID(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp utilsmetav1.Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.ID)
	return resp.ID
}

// startBlocker occupies the worker with a scan that has no exceptions.
func startBlocker(t *testing.T, handler *HTTPHandler, h *coreScanHarness) string {
	t.Helper()
	w := postScan(handler, "", `{}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	select {
	case id := <-h.blockerStarted:
		return id
	case <-time.After(10 * time.Second):
		t.Fatal("blocker scan never started")
		return ""
	}
}

// shutdownHandler shuts handler down without a drain period, cancelling
// queued and running scans, and waits for its worker to exit.
func shutdownHandler(t *testing.T, handler *HTTPHandler) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, handler.Shutdown(ctx, 0))
}

// TestExceptionsTempFile_NotLeftWhenRequestIsRejectedAtParse rejects requests with an invalid query
// parameter or a callback while callbacks are disabled (400) before any
// exceptions file is written.
func TestExceptionsTempFile_NotLeftWhenRequestIsRejectedAtParse(t *testing.T) {
	t.Setenv(callbackEnabledEnv, "")
	t.Setenv(callbackAllowlistEnv, "")

	for name, query := range map[string]string{
		"invalid query parameter": "?wait=notabool",
		"rejected callback URL":   "?callback=http://example.com/done", // callbacks are disabled
	} {
		t.Run(name, func(t *testing.T) {
			tmp := isolateExceptionsTempDir(t)
			h := installCoreScanHarness(t)
			handler := newHTTPHandler(false, 1, defaultMaxScanRequestBodyBytes)
			t.Cleanup(func() { shutdownHandler(t, handler) })

			w := postScan(handler, query, exceptionsScanBody)

			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Empty(t, exceptionsTempFiles(t, tmp), "a rejected request must not leave its exceptions file behind")
			assert.Zero(t, h.executedCount(), "a rejected request must never reach the scanner")
		})
	}
}

// TestExceptionsTempFile_GetScanParamsCreatesNoFileOnError checks that the parser returns no params
// and writes no exceptions file for a request it rejects.
func TestExceptionsTempFile_GetScanParamsCreatesNoFileOnError(t *testing.T) {
	tmp := isolateExceptionsTempDir(t)
	request := httptest.NewRequest(http.MethodPost, "/v1/scan?wait=notabool", bytes.NewBufferString(exceptionsScanBody))

	params, err := getScanParamsFromRequest(request, "rejected")

	require.Error(t, err)
	assert.Nil(t, params, "a request that failed to parse must not be handed back to the caller")
	assert.Empty(t, exceptionsTempFiles(t, tmp))
}

// TestExceptionsTempFile_RemovedWhenQueueIsFull rejects a request with exceptions while the
// worker is busy and the queue is full (429).
func TestExceptionsTempFile_RemovedWhenQueueIsFull(t *testing.T) {
	tmp := isolateExceptionsTempDir(t)
	h := installCoreScanHarness(t)
	handler := newHTTPHandler(false, 1, defaultMaxScanRequestBodyBytes)
	t.Cleanup(func() { shutdownHandler(t, handler) })

	startBlocker(t, handler, h)
	filler := postScan(handler, "", `{}`) // takes the only queue slot
	require.Equal(t, http.StatusOK, filler.Code, filler.Body.String())

	w := postScan(handler, "", exceptionsScanBody)

	require.Equal(t, http.StatusTooManyRequests, w.Code, w.Body.String())
	assert.Equal(t, "1", w.Header().Get("Retry-After"))
	assert.Empty(t, exceptionsTempFiles(t, tmp), "a request rejected by a full queue must not leave its exceptions file behind")
	close(h.releaseBlocker)
}

// TestExceptionsTempFile_RemovedWhenServerIsShuttingDown rejects a request with exceptions once
// shutdown has begun (503).
func TestExceptionsTempFile_RemovedWhenServerIsShuttingDown(t *testing.T) {
	tmp := isolateExceptionsTempDir(t)
	h := installCoreScanHarness(t)
	handler := newHTTPHandler(false, 1, defaultMaxScanRequestBodyBytes)
	handler.BeginShutdown()

	w := postScan(handler, "", exceptionsScanBody)

	require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
	assert.Empty(t, exceptionsTempFiles(t, tmp), "a request rejected during shutdown must not leave its exceptions file behind")
	assert.Zero(t, h.executedCount())
	shutdownHandler(t, handler)
}

// TestExceptionsTempFile_RemovedWhenQueuedScanIsCancelled cancels a queued scan with DELETE
// /v1/scan, so the worker skips it without calling the scanner.
func TestExceptionsTempFile_RemovedWhenQueuedScanIsCancelled(t *testing.T) {
	tmp := isolateExceptionsTempDir(t)
	h := installCoreScanHarness(t)
	handler := newHTTPHandler(false, 1, defaultMaxScanRequestBodyBytes)

	startBlocker(t, handler, h)
	queued := postScan(handler, "", exceptionsScanBody)
	require.Equal(t, http.StatusOK, queued.Code, queued.Body.String())
	queuedID := responseScanID(t, queued)
	require.Len(t, exceptionsTempFiles(t, tmp), 1, "the queued request owns an exceptions file while it waits")

	cancelled := cancelScanRequest(handler, queuedID)
	require.Equal(t, http.StatusOK, cancelled.Code, cancelled.Body.String())
	close(h.releaseBlocker)

	require.Eventually(t, func() bool { return !handler.state.isBusy(queuedID) }, 10*time.Second, 10*time.Millisecond,
		"the worker must dequeue and skip the cancelled scan")
	assert.Zero(t, h.executedCount(), "a scan cancelled while queued must not reach the scanner")
	assert.Empty(t, exceptionsTempFiles(t, tmp), "a scan cancelled while queued must not leave its exceptions file behind")
	shutdownHandler(t, handler)
}

// TestExceptionsTempFile_RemovedWhenShutdownCancelsQueuedScan lets Shutdown cancel a queued scan
// via cancelAll, so the worker skips it without calling the scanner.
func TestExceptionsTempFile_RemovedWhenShutdownCancelsQueuedScan(t *testing.T) {
	tmp := isolateExceptionsTempDir(t)
	h := installCoreScanHarness(t)
	handler := newHTTPHandler(false, 1, defaultMaxScanRequestBodyBytes)

	startBlocker(t, handler, h)
	queued := postScan(handler, "", exceptionsScanBody)
	require.Equal(t, http.StatusOK, queued.Code, queued.Body.String())

	// A zero drain period cancels the running and the queued scan at once.
	shutdownHandler(t, handler)

	assert.Zero(t, h.executedCount(), "a queued scan cancelled by shutdown must not reach the scanner")
	assert.Empty(t, exceptionsTempFiles(t, tmp), "a queued scan cancelled by shutdown must not leave its exceptions file behind")
}

// TestExceptionsTempFile_RemovedWhenExecutedScanFailsInitialization is a control: an executed
// scan that fails during core initialization is still cleaned up by core.
func TestExceptionsTempFile_RemovedWhenExecutedScanFailsInitialization(t *testing.T) {
	tmp := isolateExceptionsTempDir(t)
	h := installCoreScanHarness(t)
	handler := newHTTPHandler(false, 1, defaultMaxScanRequestBodyBytes)
	t.Cleanup(func() { shutdownHandler(t, handler) })

	w := postScan(handler, "?wait=true", exceptionsScanBody)

	require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"type":"error"`, "the scan is expected to fail during scanner initialization")
	require.Equal(t, 1, h.executedCount(), "the request must have reached the real scanner")
	assert.Empty(t, exceptionsTempFiles(t, tmp), "core.ScanContext must still remove the exceptions file of an executed scan")
}

// TestExceptionsTempFile_SuccessfulScanUsesThenRemovesFile runs a complete,
// offline scan of a local manifest through the real core scanner, so the
// exceptions file is read by the scan and removed only after it has finished.
func TestExceptionsTempFile_SuccessfulScanUsesThenRemovesFile(t *testing.T) {
	tmp := isolateExceptionsTempDir(t)
	withTempOutputDirs(t)
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing-kubeconfig"))
	t.Setenv("KS_CLOUD_API_URL", "https://api.example.invalid")
	t.Setenv("KS_CLOUD_REPORT_URL", "https://report.example.invalid")
	previousConnector := getter.GetKSCloudAPIConnector()
	getter.SetKSCloudAPIConnector(nil)
	t.Cleanup(func() { getter.SetKSCloudAPIConnector(previousConnector) })

	fixtures := t.TempDir()
	manifests := filepath.Join(fixtures, "manifests")
	require.NoError(t, os.MkdirAll(manifests, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(manifests, "pod.yaml"), []byte(`apiVersion: v1
kind: Pod
metadata:
  name: web
  namespace: default
spec:
  containers:
  - name: app
    image: nginx:1.27
    securityContext:
      privileged: true
`), 0o600))
	rule := reporthandling.PolicyRule{
		Rule: `package armo_builtins
import rego.v1
deny contains {"alertMessage": "privileged container", "alertObject": {"k8sApiObjects": [pod]}} if {
    pod := input[_]
    pod.spec.containers[_].securityContext.privileged == true
}`,
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"Pod"},
		}},
	}
	rule.Name = "privileged-container"
	control := reporthandling.Control{ControlID: "C-TEST", BaseScore: 5, Rules: []reporthandling.PolicyRule{rule}}
	control.Name = "Privileged container"
	policy, err := json.Marshal(control)
	require.NoError(t, err)
	policyPath := filepath.Join(fixtures, "control.json")
	require.NoError(t, os.WriteFile(policyPath, policy, 0o600))
	inputsPath := filepath.Join(fixtures, "inputs.json")
	require.NoError(t, os.WriteFile(inputsPath, []byte(`{"probe":["value"]}`), 0o600))

	originalScan, originalRun := scanImpl, runKubescapeScan
	t.Cleanup(func() { scanImpl, runKubescapeScan = originalScan, originalRun })
	scanImpl = scan
	var exceptionsPresentDuringScan bool
	runKubescapeScan = func(ctx context.Context, scanInfo *cautils.ScanInfo, policyIdentifiers []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
		_, statErr := os.Stat(scanInfo.UseExceptions)
		exceptionsPresentDuringScan = statErr == nil
		// Scan the local manifest with the local control, fully offline.
		scanInfo.InputPatterns = []string{manifests}
		scanInfo.UseFrom = []string{policyPath}
		scanInfo.ControlsInputs = inputsPath
		scanInfo.UseArtifactsFrom = ""
		scanInfo.Local = true
		return core.NewKubescape(ctx).Scan(scanInfo, policyIdentifiers)
	}

	handler := newHTTPHandler(false, 1, defaultMaxScanRequestBodyBytes)
	t.Cleanup(func() { shutdownHandler(t, handler) })
	// A disable exception covers the privileged Pod for C-TEST, so the finding
	// is only absent if the scan actually read the exceptions file.
	body := `{"targetType":"control","targetNames":["C-TEST"],"exceptions":[{"name":"accept-web","policyType":"postureExceptionPolicy","actions":["disable"],` +
		`"resources":[{"designatorType":"Attributes","attributes":{"namespace":"default","kind":"Pod","name":"web"}}],"posturePolicies":[{"controlID":"C-TEST"}]}]}`

	w := postScan(handler, "?wait=true&keep=true", body)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Type     string `json:"type"`
		Response struct {
			SummaryDetails struct {
				Controls map[string]struct {
					ResourceCounters struct {
						Failed   int `json:"failedResources"`
						Passed   int `json:"passedResources"`
						Excluded int `json:"excludedResources"`
					} `json:"ResourceCounters"`
				} `json:"controls"`
			} `json:"summaryDetails"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp), w.Body.String())
	require.Equal(t, "v1results", resp.Type, w.Body.String())
	counters := resp.Response.SummaryDetails.Controls["C-TEST"].ResourceCounters
	assert.Zero(t, counters.Failed, "the disable exception from the request must apply: %+v", counters)
	assert.Equal(t, 1, counters.Passed+counters.Excluded, "the privileged Pod must still be evaluated: %+v", counters)
	assert.True(t, exceptionsPresentDuringScan, "the exceptions file must exist while the scan runs")
	assert.Empty(t, exceptionsTempFiles(t, tmp), "a completed scan must not leave its exceptions file behind")
}

// TestExceptionsTempFile_ConcurrentAdmissionAndCancellation mixes accepted,
// rejected and cancelled requests from many goroutines. Run with -race.
func TestExceptionsTempFile_ConcurrentAdmissionAndCancellation(t *testing.T) {
	tmp := isolateExceptionsTempDir(t)
	h := installCoreScanHarness(t)
	handler := newHTTPHandler(false, 2, defaultMaxScanRequestBodyBytes)
	startBlocker(t, handler, h)

	const requests = 24
	var wg sync.WaitGroup
	var mu sync.Mutex
	statuses := map[int]int{}
	var admitted []string
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := postScan(handler, "", exceptionsScanBody)
			var resp utilsmetav1.Response
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			mu.Lock()
			defer mu.Unlock()
			statuses[w.Code]++
			if w.Code == http.StatusOK {
				admitted = append(admitted, resp.ID)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, requests, statuses[http.StatusOK]+statuses[http.StatusTooManyRequests], "unexpected statuses: %v", statuses)
	require.Positive(t, statuses[http.StatusTooManyRequests], "the queue must have rejected some requests: %v", statuses)
	require.NotEmpty(t, admitted, "the queue must have admitted some requests: %v", statuses)

	// Cancel one admitted scan while it is still queued; shutdown cancels the rest.
	cancelled := cancelScanRequest(handler, admitted[0])
	require.Equal(t, http.StatusOK, cancelled.Code, cancelled.Body.String())

	close(h.releaseBlocker)
	shutdownHandler(t, handler)

	assert.Empty(t, exceptionsTempFiles(t, tmp), "no exceptions file may survive admission, rejection, cancellation or execution")
}
