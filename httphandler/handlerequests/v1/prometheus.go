package v1

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"

	"github.com/google/uuid"
)

// Metrics http listener for prometheus support
func (handler *HTTPHandler) Metrics(w http.ResponseWriter, r *http.Request) {

	scanID := uuid.NewString()
	handler.state.setBusy(scanID)
	defer handler.state.setNotBusy(scanID)

	resultsFile := filepath.Join(OutputDir, scanID)
	scanInfo := getPrometheusDefaultScanCommand(scanID, resultsFile)

	scanParams := &scanRequestParams{
		scanQueryParams: &ScanQueryParams{
			ReturnResults: true,
			KeepResults:   false,
		},
		scanInfo: scanInfo,
		scanID:   scanID,
	}

	handler.scanResponseChan.set(scanID) // add scan to channel
	defer handler.scanResponseChan.delete(scanID)

	// send to scan queue
	logger.L().Info("requesting scan", helpers.String("scanID", scanID), helpers.String("api", "v1/metrics"))
	handler.scanRequestChan <- scanParams

	// wait for scan to complete
	results := <-handler.scanResponseChan.get(scanID)
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

func getPrometheusDefaultScanCommand(scanID, resultsFile string) *cautils.ScanInfo {
	scanInfo := defaultScanInfo()
	scanInfo.Submit = false // do not submit results every scan
	scanInfo.Local = true   // do not submit results every scan
	scanInfo.FrameworkScan = true
	scanInfo.ScanAll = true                                                        // scan all frameworks
	scanInfo.ScanID = scanID                                                       // scan ID
	scanInfo.FailThreshold = 100                                                   // Do not fail scanning
	scanInfo.Output = resultsFile                                                  // results output
	scanInfo.Format = envToString("KS_FORMAT", "prometheus")                       // default output should be json
	scanInfo.HostSensorEnabled.SetBool(envToBool("KS_ENABLE_HOST_SCANNER", false)) // enable host scanner
	return scanInfo
}
