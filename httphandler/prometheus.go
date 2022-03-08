package httphandler

import (
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/cautils/logger/helpers"
	"github.com/armosec/kubescape/clihandler"
	"github.com/armosec/opa-utils/reporthandling"
)

type serverState struct {
	valid    bool
	response string
	mtx      sync.RWMutex
}

var state serverState

const (
	meticsPath = "/metrics"
	livePath   = "/livez"
	readyPath  = "/readyz"
)

func PrometheusListener() {
	// init
	state = serverState{
		valid: false,
		mtx:   sync.RWMutex{},
	}

	// listen
	http.HandleFunc(meticsPath, metrics)
	http.HandleFunc(livePath, livez)
	http.HandleFunc(readyPath, readyz)

	port := getServerPort()
	logger.L().Info("Started Kubescape server for Prometheus", helpers.String("port", port), helpers.String("metrics path", meticsPath))

	logger.L().Fatal(http.ListenAndServe(fmt.Sprintf(":%s", getServerPort()), nil).Error())
}

func metrics(w http.ResponseWriter, r *http.Request) {
	state.mtx.Lock()
	logger.L().Info("triggering a scan", helpers.Time())
	truggerScan()
	logger.L().Info("done scanning", helpers.Time())
	state.mtx.Unlock()

	state.mtx.RLock()
	if !state.valid {
		logger.L().Info("no scan results to return", helpers.String("path", meticsPath), helpers.Int("code", http.StatusServiceUnavailable))
		w.WriteHeader(http.StatusServiceUnavailable)

	} else {
		logger.L().Info("returning scan results", helpers.String("path", meticsPath), helpers.Int("code", http.StatusOK))
		w.WriteHeader(http.StatusOK)

		fmt.Fprintf(w, state.response)
		// load from file and return
	}
	state.mtx.RUnlock()
}

func livez(w http.ResponseWriter, r *http.Request) {
	logger.L().Debug("liveliness", helpers.String("method", r.Method), helpers.String("host", r.Host), helpers.String("path", livePath), helpers.Int("code", http.StatusNoContent))
	w.WriteHeader(http.StatusNoContent)
}

func readyz(w http.ResponseWriter, r *http.Request) {
	state.mtx.RLock()
	if !state.valid {
		logger.L().Debug("no ready results", helpers.String("method", r.Method), helpers.String("host", r.Host), helpers.String("path", readyPath), helpers.Int("code", http.StatusServiceUnavailable))
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		logger.L().Debug("result are ready", helpers.String("method", r.Method), helpers.String("host", r.Host), helpers.String("path", readyPath), helpers.Int("code", http.StatusNoContent))
		w.WriteHeader(http.StatusNoContent)
	}
	state.mtx.RUnlock()
}

func truggerScan() {
	state.valid = false

	defer func() {
		if err := recover(); err != nil {
			state.valid = false
			logger.L().Error("in truggerScan - recover", helpers.Error(fmt.Errorf("%v", err)))
		}
	}()

	scanInfo := setScanInfo()
	if err := clihandler.ScanCliSetup(scanInfo); err != nil {
		logger.L().Error("scan failed", helpers.Error(err))
	} else {
		logger.L().Success("scan")
		f, err := os.ReadFile(scanInfo.Output)
		if err != nil {
			logger.L().Error("failed to load results from file", helpers.String("path", scanInfo.Output), helpers.Error(err))
			return
		}
		state.response = string(f)
		state.valid = true

	}
}

func setScanInfo() *cautils.ScanInfo {
	scanInfo := cautils.ScanInfo{}
	scanInfo.Format = "prometheus"
	scanInfo.ScanAll = true
	scanInfo.FrameworkScan = true
	scanInfo.HostSensorEnabled.Set(os.Getenv("KS_ENABLE_HOST_SENSOR"))
	scanInfo.Output = "results"
	scanInfo.FailThreshold = 100
	scanInfo.SetPolicyIdentifiers(getter.NativeFrameworks, reporthandling.KindFramework)
	scanInfo.Init()
	return &scanInfo
}

func getServerPort() string {
	if p := os.Getenv("KS_PROMETHEUS_SERVER_PORT"); p != "" {
		return p
	}
	return "8080"
}
