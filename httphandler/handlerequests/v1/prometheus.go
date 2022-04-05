package v1

import (
	"fmt"
	"net/http"
	"os"

	"github.com/armosec/kubescape/core/cautils"
	"github.com/armosec/kubescape/core/cautils/logger"
	"github.com/armosec/kubescape/core/cautils/logger/helpers"
	"github.com/armosec/kubescape/core/core"
	"github.com/google/uuid"
)

// Metrics http listener for prometheus support
func (handler *HTTPHandler) Metrics(w http.ResponseWriter, r *http.Request) {
	if handler.state.isBusy() { // if already scanning the cluster
		message := fmt.Sprintf("scan '%s' in action", handler.state.getID())
		logger.L().Info("server is busy", helpers.String("message", message), helpers.Time())
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(message))
		return
	}

	handler.state.setBusy()
	defer handler.state.setNotBusy()

	scanID := uuid.NewString()
	handler.state.setID(scanID)

	// trigger scanning
	logger.L().Info(handler.state.getID(), helpers.String("action", "triggering scan"), helpers.Time())
	ks := core.NewKubescape()
	results, err := ks.Scan(getPrometheusDefaultScanCommand(scanID))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("failed to complete scan. reason: %s", err.Error())))
		return
	}
	results.HandleResults()
	logger.L().Info(handler.state.getID(), helpers.String("action", "done scanning"), helpers.Time())

	f, err := os.ReadFile(scanID)
	// res, err := results.ToJson()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("failed read results from file. reason: %s", err.Error())))
		return
	}
	os.Remove(scanID)

	w.WriteHeader(http.StatusOK)
	w.Write(f)
}

func getPrometheusDefaultScanCommand(scanID string) *cautils.ScanInfo {
	scanInfo := defaultScanInfo()
	scanInfo.FrameworkScan = true
	scanInfo.ScanAll = true                                                        // scan all frameworks
	scanInfo.ScanID = scanID                                                       // scan ID
	scanInfo.FailThreshold = 100                                                   // Do not fail scanning
	scanInfo.Output = scanID                                                       // results output
	scanInfo.Format = envToString("KS_FORMAT", "prometheus")                       // default output should be json
	scanInfo.HostSensorEnabled.SetBool(envToBool("KS_ENABLE_HOST_SCANNER", false)) // enable host scanner
	return scanInfo
}
