package v1

import (
	"context"
	"fmt"
	"net/http"
	_ "net/http/pprof"

	"github.com/kubescape/go-logger/helpers"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"go.opentelemetry.io/otel/trace"

	"github.com/gorilla/schema"

	logger "github.com/kubescape/go-logger"

	"github.com/google/uuid"
)

var OutputDir = "./results/"
var FailedOutputDir = "./failed/"

// A Scan Response object
//
// swagger:response scanResponse
type ScanResponse struct {
	// in:body
	Body utilsmetav1.Response
}

type HTTPHandler struct {
	state            *serverState
	scanResponseChan *scanResponseChan
	scanRequestChan  chan *scanRequestParams
}

func NewHTTPHandler() *HTTPHandler {
	handler := &HTTPHandler{
		state:            newServerState(),
		scanRequestChan:  make(chan *scanRequestParams),
		scanResponseChan: newScanResponseChan(),
	}
	go handler.watchForScan()

	return handler
}

// ============================================== STATUS ========================================================
// Status API
func (handler *HTTPHandler) Status(w http.ResponseWriter, r *http.Request) {
	defer handler.recover(r.Context(), w, "")

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	response := utilsmetav1.Response{}
	w.Header().Set("Content-Type", "application/json")

	statusQueryParams := &StatusQueryParams{}
	if err := schema.NewDecoder().Decode(statusQueryParams, r.URL.Query()); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		handler.writeError(w, fmt.Errorf("failed to parse query params, reason: %s", err.Error()), "")
		return
	}
	logger.L().Info("requesting status", helpers.String("scanID", statusQueryParams.ScanID), helpers.String("api", "v1/status"))

	w.WriteHeader(http.StatusOK)
	if !handler.state.isBusy(statusQueryParams.ScanID) {
		response.Type = utilsapisv1.NotBusyScanResponseType
		logger.L().Debug("status: not busy", helpers.String("ID", statusQueryParams.ScanID))
		w.Write(responseToBytes(&response))
		return
	}

	if statusQueryParams.ScanID == "" {
		statusQueryParams.ScanID = handler.state.getLatestID()
	}

	response.Response = statusQueryParams.ScanID
	response.ID = statusQueryParams.ScanID
	response.Type = utilsapisv1.BusyScanResponseType

	logger.L().Debug("status: busy", helpers.String("ID", statusQueryParams.ScanID))
	w.Write(responseToBytes(&response))
}

// ============================================== SCAN ========================================================
// Scan API
func (handler *HTTPHandler) Scan(w http.ResponseWriter, r *http.Request) {

	// generate id
	scanID := uuid.NewString()

	defer handler.recover(r.Context(), w, scanID)

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	scanRequestParams, err := getScanParamsFromRequest(r, scanID)
	if err != nil {
		handler.writeError(w, err, "")
		return
	}
	scanRequestParams.ctx = trace.ContextWithSpanContext(context.Background(), trace.SpanContextFromContext(r.Context()))

	handler.state.setBusy(scanID)

	response := &utilsmetav1.Response{}
	response.ID = scanID
	response.Type = utilsapisv1.BusyScanResponseType
	response.Response = fmt.Sprintf("scanning '%s' is in progress", scanID)

	handler.scanResponseChan.set(scanID) // add channel
	defer handler.scanResponseChan.delete(scanID)

	// you must use a goroutine since the executeScan function is not always listening to the channel
	go func() {
		// send to scanning handler
		logger.L().Info("requesting scan", helpers.String("scanID", scanID), helpers.String("api", "v1/scan"))
		handler.scanRequestChan <- scanRequestParams
	}()

	if scanRequestParams.scanQueryParams.ReturnResults {
		// wait for scan to complete
		response = <-handler.scanResponseChan.get(scanID)

		if scanRequestParams.scanQueryParams.KeepResults {
			// delete results after returning
			logger.L().Debug("deleting results", helpers.String("ID", scanID))
			removeResultsFile(scanID)
		}
	}

	statusCode := http.StatusOK
	if response.Type == utilsapisv1.ErrorScanResponseType {
		statusCode = http.StatusInternalServerError
	}

	w.WriteHeader(statusCode)
	w.Write(responseToBytes(response))
}

// ============================================== RESULTS ========================================================

// Results API - TODO: break down to functions
func (handler *HTTPHandler) Results(w http.ResponseWriter, r *http.Request) {
	response := utilsmetav1.Response{}
	w.Header().Set("Content-Type", "application/json")

	defer handler.recover(r.Context(), w, "")

	defer r.Body.Close()

	resultsQueryParams := &ResultsQueryParams{}
	if err := schema.NewDecoder().Decode(resultsQueryParams, r.URL.Query()); err != nil {
		handler.writeError(w, fmt.Errorf("failed to parse query params, reason: %s", err.Error()), "")
		return
	}
	logger.L().Info("requesting results", helpers.String("scanID", resultsQueryParams.ScanID), helpers.String("api", "v1/results"), helpers.String("method", r.Method))

	if resultsQueryParams.ScanID == "" {
		resultsQueryParams.ScanID = handler.state.getLatestID()
	}

	if resultsQueryParams.ScanID == "" { // if no scan found
		logger.L().Info("empty scan ID")
		w.WriteHeader(http.StatusBadRequest)
		response.Response = "latest scan not found"
		response.Type = utilsapisv1.ErrorScanResponseType
		w.Write(responseToBytes(&response))
		return
	}
	response.ID = resultsQueryParams.ScanID

	if handler.state.isBusy(resultsQueryParams.ScanID) { // if requested ID is still scanning
		logger.L().Info("scan in process", helpers.String("ID", resultsQueryParams.ScanID))
		w.WriteHeader(http.StatusOK)
		response.Type = utilsapisv1.BusyScanResponseType
		response.Response = fmt.Sprintf("scanning '%s' in progress", resultsQueryParams.ScanID)
		w.Write(responseToBytes(&response))
		return

	}

	switch r.Method {
	case http.MethodGet:
		logger.L().Info("requesting results", helpers.String("ID", resultsQueryParams.ScanID))

		if res, err := readResultsFile(resultsQueryParams.ScanID); err != nil {
			logger.L().Info("scan result not found", helpers.String("ID", resultsQueryParams.ScanID))
			w.WriteHeader(http.StatusNoContent)
			response.Response = err.Error()
		} else {
			logger.L().Info("scan result found", helpers.String("ID", resultsQueryParams.ScanID))
			w.WriteHeader(http.StatusOK)
			response.Response = res

			if !resultsQueryParams.KeepResults {
				logger.L().Info("deleting results", helpers.String("ID", resultsQueryParams.ScanID))
				defer removeResultsFile(resultsQueryParams.ScanID)
			}

		}
		w.Write(responseToBytes(&response))
	case http.MethodDelete:
		logger.L().Info("deleting results", helpers.String("ID", resultsQueryParams.ScanID))

		if resultsQueryParams.AllResults {
			removeResultDirs()
		} else {
			removeResultsFile(resultsQueryParams.ScanID)
		}
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

}

func (handler *HTTPHandler) Live(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (handler *HTTPHandler) Ready(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (handler *HTTPHandler) recover(ctx context.Context, w http.ResponseWriter, scanID string) {
	response := utilsmetav1.Response{}
	if err := recover(); err != nil {
		handler.state.setNotBusy(scanID)
		logger.L().Ctx(ctx).Error("recover", helpers.Error(fmt.Errorf("%v", err)))
		w.WriteHeader(http.StatusInternalServerError)
		response.Response = fmt.Sprintf("%v", err)
		response.Type = utilsapisv1.ErrorScanResponseType
		w.Write(responseToBytes(&response))
	}
}

func (handler *HTTPHandler) writeError(w http.ResponseWriter, err error, scanID string) {
	response := utilsmetav1.Response{}
	w.WriteHeader(http.StatusBadRequest)
	response.Response = err.Error()
	response.Type = utilsapisv1.ErrorScanResponseType
	w.Write(responseToBytes(&response))
	handler.state.setNotBusy(scanID)
}
