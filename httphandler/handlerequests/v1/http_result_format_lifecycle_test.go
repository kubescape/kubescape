package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	resultprinter "github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type artifactPrinter struct {
	path    string
	content []byte
}

func (p *artifactPrinter) SetWriter(context.Context, string) error { return nil }
func (p *artifactPrinter) PrintNextSteps()                         {}
func (p *artifactPrinter) Score(float32)                           {}
func (p *artifactPrinter) ActionPrint(context.Context, *cautils.OPASessionObj, []cautils.ImageScanData) error {
	return os.WriteFile(p.path, p.content, 0o600)
}

type noOpPrinter struct{}

func (*noOpPrinter) SetWriter(context.Context, string) error { return nil }
func (*noOpPrinter) PrintNextSteps()                         {}
func (*noOpPrinter) Score(float32)                           {}
func (*noOpPrinter) ActionPrint(context.Context, *cautils.OPASessionObj, []cautils.ImageScanData) error {
	return nil
}

func newFormatLifecycleResultsHandler(outputPath, suffix string, content []byte) *resultshandling.ResultsHandler {
	results := resultshandling.NewResultsHandler(
		nil,
		[]resultprinter.IPrinter{&artifactPrinter{path: outputPath + suffix, content: content}},
		&noOpPrinter{},
	)
	data := cautils.NewOPASessionObjMock()
	data.Report.ClusterName = "canonical-cluster"
	results.SetData(data)
	return results
}

func TestScanSyncNonJSONFormatPersistsRetrievableCanonicalResult(t *testing.T) {
	out := withTempOutputDirs(t)

	originalScanImpl := scanImpl
	originalRunKubescapeScan := runKubescapeScan
	t.Cleanup(func() {
		scanImpl = originalScanImpl
		runKubescapeScan = originalRunKubescapeScan
	})

	const sidecar = "requested yaml output\n"
	var scanID string
	scanImpl = scan
	runKubescapeScan = func(_ context.Context, scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
		scanID = scanInfo.ScanID
		return newFormatLifecycleResultsHandler(scanInfo.Output, ".yaml", []byte(sidecar)), nil
	}

	body, err := json.Marshal(utilsmetav1.PostScanRequest{Format: "yaml"})
	require.NoError(t, err)
	h := NewHTTPHandler(false)
	w := httptest.NewRecorder()
	h.Scan(w, httptest.NewRequest(http.MethodPost, "/scan?wait=true&keep=true", bytes.NewReader(body)))

	require.Equal(t, http.StatusOK, w.Code, "body=%s", w.Body.String())
	response := decodeResultsResponse(t, w)
	require.Equal(t, utilsapisv1.ResultsV1ScanResponseType, response.Type)
	payload, ok := response.Response.(map[string]any)
	require.Truef(t, ok, "response payload type = %T; want JSON object", response.Response)
	assert.Equal(t, "canonical-cluster", payload["clusterName"])

	require.NotEmpty(t, scanID)
	canonicalPath := filepath.Join(out, scanID)
	canonical, err := os.ReadFile(canonicalPath)
	require.NoError(t, err, "non-JSON scans must persist extensionless canonical JSON")
	assert.True(t, json.Valid(canonical), "canonical result must be valid JSON: %q", canonical)
	assert.NotEqual(t, sidecar, string(canonical), "canonical JSON must not reuse the requested sidecar bytes")

	requestedPath := filepath.Join(out, scanID+".yaml")
	gotSidecar, err := os.ReadFile(requestedPath)
	require.NoError(t, err, "requested output sidecar must remain available when keep=true")
	assert.Equal(t, sidecar, string(gotSidecar))
	_, err = os.Stat(filepath.Join(out, scanID+".json"))
	assert.True(t, os.IsNotExist(err), "internal canonical persistence must not create an unrequested .json sidecar")
}

func TestScanSyncNonJSONFormatDefaultCleanupRemovesCanonicalAndSidecar(t *testing.T) {
	out := withTempOutputDirs(t)

	originalScanImpl := scanImpl
	originalRunKubescapeScan := runKubescapeScan
	t.Cleanup(func() {
		scanImpl = originalScanImpl
		runKubescapeScan = originalRunKubescapeScan
	})

	var scanID string
	scanImpl = scan
	runKubescapeScan = func(_ context.Context, scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
		scanID = scanInfo.ScanID
		return newFormatLifecycleResultsHandler(scanInfo.Output, ".pdf", []byte("requested pdf output")), nil
	}

	body, err := json.Marshal(utilsmetav1.PostScanRequest{Format: "pdf"})
	require.NoError(t, err)
	h := NewHTTPHandler(false)
	w := httptest.NewRecorder()
	h.Scan(w, httptest.NewRequest(http.MethodPost, "/scan?wait=true", bytes.NewReader(body)))

	require.Equal(t, http.StatusOK, w.Code, "body=%s", w.Body.String())
	response := decodeResultsResponse(t, w)
	require.Equal(t, utilsapisv1.ResultsV1ScanResponseType, response.Type)
	payload, ok := response.Response.(map[string]any)
	require.Truef(t, ok, "response payload type = %T; want JSON object", response.Response)
	assert.Equal(t, "canonical-cluster", payload["clusterName"], "cleanup must happen only after the synchronous response reads the canonical result")

	require.NotEmpty(t, scanID)
	for _, path := range []string{
		filepath.Join(out, scanID),
		filepath.Join(out, scanID+".pdf"),
	} {
		_, err := os.Stat(path)
		assert.Truef(t, os.IsNotExist(err), "keep=false left result artifact %q: %v", path, err)
	}
}

func TestScanAsyncNonJSONFormatCanBeFetched(t *testing.T) {
	out := withTempOutputDirs(t)

	originalScanImpl := scanImpl
	originalRunKubescapeScan := runKubescapeScan
	t.Cleanup(func() {
		scanImpl = originalScanImpl
		runKubescapeScan = originalRunKubescapeScan
	})

	const sidecar = "requested yaml output\n"
	scanImpl = scan
	runKubescapeScan = func(_ context.Context, scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
		return newFormatLifecycleResultsHandler(scanInfo.Output, ".yaml", []byte(sidecar)), nil
	}

	body, err := json.Marshal(utilsmetav1.PostScanRequest{Format: "yaml"})
	require.NoError(t, err)
	h := NewHTTPHandler(false)
	scanRecorder := httptest.NewRecorder()
	h.Scan(scanRecorder, httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body)))

	require.Equal(t, http.StatusOK, scanRecorder.Code, "body=%s", scanRecorder.Body.String())
	scanResponse := decodeResultsResponse(t, scanRecorder)
	require.Equal(t, utilsapisv1.BusyScanResponseType, scanResponse.Type)
	require.NotEmpty(t, scanResponse.ID)
	require.Eventually(t, func() bool {
		return !h.state.isBusy(scanResponse.ID)
	}, time.Second, 5*time.Millisecond, "asynchronous scan did not finish")

	resultsRecorder := httptest.NewRecorder()
	h.GetResults(resultsRecorder, httptest.NewRequest(http.MethodGet, "/results?id="+scanResponse.ID+"&keep=true", nil))

	require.Equal(t, http.StatusOK, resultsRecorder.Code, "body=%s", resultsRecorder.Body.String())
	resultsResponse := decodeResultsResponse(t, resultsRecorder)
	require.Equal(t, utilsapisv1.ResultsV1ScanResponseType, resultsResponse.Type)
	payload, ok := resultsResponse.Response.(map[string]any)
	require.Truef(t, ok, "response payload type = %T; want JSON object", resultsResponse.Response)
	assert.Equal(t, "canonical-cluster", payload["clusterName"])

	canonical, err := os.ReadFile(filepath.Join(out, scanResponse.ID))
	require.NoError(t, err)
	assert.True(t, json.Valid(canonical))
	gotSidecar, err := os.ReadFile(filepath.Join(out, scanResponse.ID+".yaml"))
	require.NoError(t, err)
	assert.Equal(t, sidecar, string(gotSidecar))
}

func TestScanSkipPersistenceNonJSONFormatKeepsCanonicalHTTPArtifact(t *testing.T) {
	out := withTempOutputDirs(t)

	originalScanImpl := scanImpl
	originalRunKubescapeScan := runKubescapeScan
	t.Cleanup(func() {
		scanImpl = originalScanImpl
		runKubescapeScan = originalRunKubescapeScan
	})

	skipPersistenceSeen := make(chan bool, 1)
	var scanID string
	scanImpl = func(ctx context.Context, scanInfo *cautils.ScanInfo, policyIdentifiers []cautils.PolicyIdentifier, id string, skipPersistence bool) (*reporthandlingv2.PostureReport, error) {
		skipPersistenceSeen <- skipPersistence
		return scan(ctx, scanInfo, policyIdentifiers, id, skipPersistence)
	}
	runKubescapeScan = func(_ context.Context, scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
		scanID = scanInfo.ScanID
		return newFormatLifecycleResultsHandler(scanInfo.Output, ".yaml", []byte("requested yaml output\n")), nil
	}

	body, err := json.Marshal(utilsmetav1.PostScanRequest{Format: "yaml"})
	require.NoError(t, err)
	h := NewHTTPHandler(false)
	w := httptest.NewRecorder()
	h.Scan(w, httptest.NewRequest(http.MethodPost, "/scan?wait=true&keep=true&skipPersistence=true", bytes.NewReader(body)))

	require.Equal(t, http.StatusOK, w.Code, "body=%s", w.Body.String())
	response := decodeResultsResponse(t, w)
	require.Equal(t, utilsapisv1.ResultsV1ScanResponseType, response.Type)
	payload, ok := response.Response.(map[string]any)
	require.Truef(t, ok, "response payload type = %T; want JSON object", response.Response)
	assert.Equal(t, "canonical-cluster", payload["clusterName"])
	require.True(t, <-skipPersistenceSeen, "query parameter must reach scan persistence control")
	require.NotEmpty(t, scanID)

	canonical, err := os.ReadFile(filepath.Join(out, scanID))
	require.NoError(t, err, "skipPersistence must not suppress the HTTP results artifact")
	assert.True(t, json.Valid(canonical))
}

func TestScanLiteralJSONFormatDoesNotCreateCanonicalDuplicate(t *testing.T) {
	out := withTempOutputDirs(t)

	originalRunKubescapeScan := runKubescapeScan
	t.Cleanup(func() { runKubescapeScan = originalRunKubescapeScan })

	const id = "123e4567-e89b-12d3-a456-426614174010"
	outputPath := filepath.Join(out, id)
	runKubescapeScan = func(_ context.Context, scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
		return newFormatLifecycleResultsHandler(scanInfo.Output, ".json", []byte(`{"reportGUID":"requested-json"}`)), nil
	}

	_, err := scan(withCanonicalResultPersistence(context.Background()), &cautils.ScanInfo{
		ScanID: id,
		Format: "yaml, json",
		Output: outputPath,
	}, nil, id, true)
	require.NoError(t, err)

	requested, err := os.ReadFile(outputPath + ".json")
	require.NoError(t, err)
	assert.JSONEq(t, `{"reportGUID":"requested-json"}`, string(requested))
	_, err = os.Stat(outputPath)
	assert.True(t, os.IsNotExist(err), "literal json requests already have a retrievable .json result; no duplicate canonical file should be created")
}

func TestResultsGetCanonicalResultWinsOverGitLabSASTJSONSidecar(t *testing.T) {
	const id = "123e4567-e89b-12d3-a456-426614174011"
	out := withTempOutputDirs(t)
	require.NoError(t, os.WriteFile(filepath.Join(out, id), []byte(`{"reportGUID":"canonical"}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(out, id+".json"), []byte(`{"version":"15.0.6","vulnerabilities":[]}`), 0o600))

	h := newResultsHandler(false)
	w := httptest.NewRecorder()
	h.GetResults(w, httptest.NewRequest(http.MethodGet, "/results?id="+id+"&keep=true", nil))

	require.Equal(t, http.StatusOK, w.Code, "body=%s", w.Body.String())
	response := decodeResultsResponse(t, w)
	payload, ok := response.Response.(map[string]any)
	require.Truef(t, ok, "response payload type = %T; want JSON object", response.Response)
	assert.Equal(t, "canonical", payload["reportGUID"], "extensionless canonical JSON must win over gitlab-sast's .json sidecar")
	assert.NotContains(t, payload, "version")

	_, err := os.Stat(filepath.Join(out, id))
	assert.NoError(t, err)
	_, err = os.Stat(filepath.Join(out, id+".json"))
	assert.NoError(t, err, "keep=true must retain requested sidecars")
}

func TestResultsDeleteRemovesOnlyKnownResultArtifacts(t *testing.T) {
	const id = "123e4567-e89b-12d3-a456-426614174012"
	const otherID = "123e4567-e89b-12d3-a456-426614174013"
	withTempOutputDirs(t)

	knownSuffixes := []string{
		"",
		".json",
		".xml",
		".sarif",
		".html",
		".pdf",
		".txt",
		".yaml",
		".csv",
		".cdx.json",
		".spdx.json",
	}
	for _, dir := range []string{OutputDir, FailedOutputDir} {
		for _, suffix := range knownSuffixes {
			require.NoError(t, os.WriteFile(filepath.Join(dir, id+suffix), []byte("result"), 0o600))
		}
	}

	preserved := []string{
		filepath.Join(OutputDir, id+".notes"),
		filepath.Join(OutputDir, id+".json.bak"),
		filepath.Join(OutputDir, otherID+".yaml"),
		filepath.Join(FailedOutputDir, id+".custom"),
	}
	for _, path := range preserved {
		require.NoError(t, os.WriteFile(path, []byte("preserve"), 0o600))
	}

	h := newResultsHandler(false)
	w := httptest.NewRecorder()
	h.DeleteResults(w, httptest.NewRequest(http.MethodDelete, "/results?id="+id, nil))
	require.Equal(t, http.StatusOK, w.Code, "body=%s", w.Body.String())

	for _, dir := range []string{OutputDir, FailedOutputDir} {
		for _, suffix := range knownSuffixes {
			path := filepath.Join(dir, id+suffix)
			_, err := os.Stat(path)
			assert.Truef(t, os.IsNotExist(err), "known result artifact %q survived DELETE: %v", path, err)
		}
	}
	for _, path := range preserved {
		got, err := os.ReadFile(path)
		require.NoErrorf(t, err, "unrelated UUID-adjacent file %q must survive exact cleanup", path)
		assert.Equal(t, "preserve", string(got))
	}
}
