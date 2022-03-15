package v1

import (
	"fmt"
	"net/http"
	"os"

	"github.com/armosec/kubescape/core/cautils"
	"github.com/armosec/kubescape/core/cautils/getter"
	"github.com/armosec/kubescape/core/cautils/logger"
	"github.com/armosec/kubescape/core/cautils/logger/helpers"
	"github.com/armosec/kubescape/core/core"
	pkgcautils "github.com/armosec/utils-go/utils"
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

	handler.state.setID(uuid.NewString())
	resultsFile := handler.state.getID() + ".junit"
	// trigger scanning
	logger.L().Info(handler.state.getID(), helpers.String("action", "triggering scan"), helpers.Time())
	ks := core.NewKubescape()
	results, err := ks.Scan(getPrometheusDefaultScanCommand(handler.state.getID(), resultsFile))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("failed to complete scan. reason: %s", err.Error())))
		return
	}
	results.HandleResults()
	logger.L().Info(handler.state.getID(), helpers.String("action", "done scanning"), helpers.Time())

	f, err := os.ReadFile(resultsFile)
	// res, err := results.ToJson()
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
	scanInfo := cautils.ScanInfo{}
	scanInfo.FrameworkScan = true
	scanInfo.ScanAll = true                                             // scan all frameworks
	scanInfo.ReportID = scanID                                          // scan ID
	scanInfo.HostSensorEnabled.Set(os.Getenv("KS_ENABLE_HOST_SCANNER")) // enable host scanner
	scanInfo.FailThreshold = 100                                        // Do not fail scanning
	scanInfo.Format = "prometheus"                                      // results format
	scanInfo.Output = resultsFile                                       // results output
	scanInfo.Local = true                                               // Do not publish results to Kubescape SaaS
	if !downloadArtifactsEveryScan() {
		scanInfo.UseArtifactsFrom = getter.DefaultLocalStore // Load files from cache (this will prevent kubescape fom downloading the artifacts every time)
	}
	scanInfo.Init()
	return &scanInfo
}
func downloadArtifactsEveryScan() bool {
	if d, ok := os.LookupEnv("KS_DOWNLOAD_ARTIFACTS"); ok {
		return pkgcautils.StringToBool(d)
	}
	return false
}
