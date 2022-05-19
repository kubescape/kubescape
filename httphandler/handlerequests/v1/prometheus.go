package v1

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/armosec/kubescape/v2/core/cautils"
	"github.com/armosec/kubescape/v2/core/cautils/logger"
	"github.com/armosec/kubescape/v2/core/cautils/logger/helpers"
	"github.com/armosec/kubescape/v2/core/core"
	"github.com/google/uuid"
)

// Metrics http listener for prometheus support
func (handler *HTTPHandler) Metrics(w http.ResponseWriter, r *http.Request) {
	if handler.state.len() > 0 { // if already scanning the cluster
		message := fmt.Sprintf("scan '%s' in action", handler.state.getLatestID())
		logger.L().Info("server is busy", helpers.String("message", message), helpers.Time())
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(message))
		return
	}

	scanID := uuid.NewString()
	handler.state.setBusy(scanID)
	defer handler.state.setNotBusy(scanID)

	resultsFile := filepath.Join(OutputDir, scanID)

	// trigger scanning
	logger.L().Info(scanID, helpers.String("action", "triggering scan"), helpers.Time())

	ks := core.NewKubescape()
	results, err := ks.Scan(getPrometheusDefaultScanCommand(scanID, resultsFile))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("failed to complete scan. reason: %s", err.Error())))
		return
	}
	results.HandleResults()
	logger.L().Info(scanID, helpers.String("action", "done scanning"), helpers.Time())

	f, err := os.ReadFile(resultsFile)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("failed read results from file. reason: %s", err.Error())))
		return
	}
	os.Remove(resultsFile)

	w.WriteHeader(http.StatusOK)
	w.Write(f)
}

func getPrometheusDefaultScanCommand(scanID, resultsFile string) *cautils.ScanInfo {
	scanInfo := defaultScanInfo()
	scanInfo.FrameworkScan = true
	scanInfo.ScanAll = true                                                        // scan all frameworks
	scanInfo.ScanID = scanID                                                       // scan ID
	scanInfo.FailThreshold = 100                                                   // Do not fail scanning
	scanInfo.Output = resultsFile                                                  // results output
	scanInfo.Format = envToString("KS_FORMAT", "prometheus")                       // default output should be json
	scanInfo.HostSensorEnabled.SetBool(envToBool("KS_ENABLE_HOST_SCANNER", false)) // enable host scanner
	return scanInfo
}
