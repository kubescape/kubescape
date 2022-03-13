package v1

import (
	"fmt"
	"net/http"
	"os"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/cautils/logger/helpers"
	"github.com/armosec/kubescape/core/core"
	"github.com/google/uuid"
)

// Metrics http listener for prometheus support
func (handler *HTTPHandler) Metrics(w http.ResponseWriter, r *http.Request) {
	if handler.state.isBusy() { // if already scanning the cluster
		w.Write([]byte(fmt.Sprintf("scan '%s' in action", handler.state.getID())))
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	handler.state.setBusy()
	defer handler.state.setNotBusy()

	handler.state.setID(uuid.NewString())

	// trigger scanning
	logger.L().Info(handler.state.getID(), helpers.String("action", "triggering scan"), helpers.Time())
	results, err := core.Scan(getPrometheusDefaultScanCommand(handler.state.getID()))
	logger.L().Info(handler.state.getID(), helpers.String("action", "done scanning"), helpers.Time())

	if err != nil {
		w.Write([]byte(fmt.Sprintf("failed to complete scan. reason: %s", err.Error())))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	res, err := results.ToJson()
	if err != nil {
		w.Write([]byte(fmt.Sprintf("failed to convert scan scan results to json. reason: %s", err.Error())))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(res)
	w.WriteHeader(http.StatusOK)
}

func getPrometheusDefaultScanCommand(scanID string) *cautils.ScanInfo {
	scanInfo := cautils.ScanInfo{}
	scanInfo.FrameworkScan = true
	scanInfo.ScanAll = true                                            // scan all frameworks
	scanInfo.ReportID = scanID                                         // scan ID
	scanInfo.HostSensorEnabled.Set(os.Getenv("KS_ENABLE_HOST_SENSOR")) // enable host scanner
	scanInfo.FailThreshold = 100                                       // Do not fail scanning
	// scanInfo.Format = "prometheus" 								   // results format
	return &scanInfo
}
