package v1

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/schema"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"go.opentelemetry.io/otel/trace"
)

// MetricsQueryParams query params for metrics endpoint
type MetricsQueryParams struct {
	// Frameworks is a comma-separated list of frameworks to scan
	// Example: "nsa,mitre,cis-v1.10.0"
	// If not provided, all available frameworks will be scanned
	Frameworks string `schema:"frameworks" json:"frameworks"`

	// Do not persist data after scanning
	// default: false
	SkipPersistence bool `schema:"skipPersistence" json:"skipPersistence"`
}

// Metrics http listener for prometheus support
func (handler *HTTPHandler) Metrics(w http.ResponseWriter, r *http.Request) {

	scanID := uuid.NewString()
	handler.state.setBusy(scanID)
	defer handler.state.setNotBusy(scanID)

	metricsQueryParams := &MetricsQueryParams{}
	if err := schema.NewDecoder().Decode(metricsQueryParams, r.URL.Query()); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		handler.writeError(w, fmt.Errorf("failed to parse query params, reason: %s", err.Error()), scanID)
		return
	}
	skipPersistence := r.URL.Query().Get("skipPersistence") == "true"

	resultsFile := filepath.Join(OutputDir, scanID)
	scanInfo := getPrometheusDefaultScanCommand(scanID, resultsFile, metricsQueryParams.Frameworks)

	scanParams := &scanRequestParams{
		scanQueryParams: &ScanQueryParams{
			ReturnResults:   true,
			KeepResults:     false,
			SkipPersistence: skipPersistence,
		},
		scanInfo: scanInfo,
		scanID:   scanID,
		ctx:      trace.ContextWithSpanContext(context.Background(), trace.SpanContextFromContext(r.Context())),
		resp:     make(chan *utilsmetav1.Response, 1),
	}

	// send to scan queue
	logger.L().Info("requesting scan", helpers.String("scanID", scanID), helpers.String("api", "v1/metrics"))
	handler.scanRequestChan <- scanParams

	// wait for scan to complete
	results := <-scanParams.resp
	defer removeResultsFile(scanID) // remove json format results file
	defer os.Remove(resultsFile)    // remove prometheus format results file

	// handle response
	if results.Type == utilsapisv1.ErrorScanResponseType {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(responseToBytes(results))
		return
	}

	// read prometheus format results file
	f, err := os.ReadFile(resultsFile)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		results.Type = utilsapisv1.ErrorScanResponseType
		results.Response = fmt.Sprintf("failed read results from file. reason: %s", err.Error())
		w.Write(responseToBytes(results))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(f)
}

func getPrometheusDefaultScanCommand(scanID, resultsFile, frameworksParam string) *cautils.ScanInfo {
	scanInfo := defaultScanInfo()
	scanInfo.UseArtifactsFrom = getter.DefaultLocalStore // Load files from cache (this will prevent kubescape from downloading the artifacts every time)
	scanInfo.Submit = false                              // do not submit results every scan
	scanInfo.Local = true                                // do not submit results every scan
	scanInfo.FrameworkScan = true
	scanInfo.HostSensorEnabled.SetBool(false)                // disable host scanner
	scanInfo.ScanID = scanID                                 // scan ID
	scanInfo.FailThreshold = 100                             // Do not fail scanning
	scanInfo.ComplianceThreshold = 0                         // Do not fail scanning
	scanInfo.Output = resultsFile                            // results output
	scanInfo.Format = envToString("KS_FORMAT", "prometheus") // default output format is prometheus

	// Check if specific frameworks are requested via query parameter
	if frameworksParam != "" {
		// Scan specific frameworks (comma-separated list)
		frameworks := splitAndTrim(frameworksParam, ",")
		scanInfo.SetPolicyIdentifiers(frameworks, utilsapisv1.KindFramework)
	} else {
		// Default: scan all available frameworks (including CIS)
		scanInfo.ScanAll = true
		// Framework identifiers will be set dynamically by the scan process when ScanAll is true
	}

	return scanInfo
}

// splitAndTrim splits a string by delimiter and trims whitespace from each element
func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
