package v1

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof"

	"github.com/google/uuid"
	"github.com/gorilla/schema"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
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
	offline         bool
	state           *serverState
	scanRequestChan chan *scanRequestParams
}

func NewHTTPHandler(offline bool) *HTTPHandler {
	handler := &HTTPHandler{
		offline:         offline,
		state:           newServerState(),
		scanRequestChan: make(chan *scanRequestParams),
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
	scanRequestParams.ctx = context.WithoutCancel(r.Context())

	if handler.offline {
		scanRequestParams.scanInfo.UseDefault = true
		scanRequestParams.scanInfo.UseArtifactsFrom = getter.DefaultLocalStore
	}

	handler.state.setBusy(scanID)

	// you must use a goroutine since the executeScan function is not always listening to the channel
	go func() {
		// send to scanning handler
		logger.L().Info("requesting scan", helpers.String("scanID", scanID), helpers.String("api", "v1/scan"))
		handler.scanRequestChan <- scanRequestParams
	}()

	response := &utilsmetav1.Response{
		ID:       scanID,
		Type:     utilsapisv1.BusyScanResponseType,
		Response: fmt.Sprintf("scanning '%s' is in progress", scanID),
	}
	if scanRequestParams.resp != nil {
		// wait for scan to complete
		response = <-scanRequestParams.resp

		if !scanRequestParams.scanQueryParams.KeepResults {
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

// parseResultsQueryParams extracts query parameters and validates them
func (handler *HTTPHandler) parseResultsQueryParams(w http.ResponseWriter, r *http.Request) (*ResultsQueryParams, bool) {
	resultsQueryParams := &ResultsQueryParams{}
	if err := schema.NewDecoder().Decode(resultsQueryParams, r.URL.Query()); err != nil {
		handler.writeError(w, fmt.Errorf("failed to parse query params, reason: %s", err.Error()), "")
		return nil, false
	}
	logger.L().Info("requesting results", helpers.String("scanID", resultsQueryParams.ScanID), helpers.String("api", "v1/results"), helpers.String("method", r.Method))
	return resultsQueryParams, true
}

func (handler *HTTPHandler) validateScanID(w http.ResponseWriter, resultsQueryParams *ResultsQueryParams) (bool, bool) {
	isLatestFallback := false
	if resultsQueryParams.ScanID == "" {
		if handler.offline {
			resultsQueryParams.ScanID = handler.state.getLatestID()
			isLatestFallback = true
		} else {
			logger.L().Info("empty scan ID")
			w.WriteHeader(http.StatusBadRequest)
			response := utilsmetav1.Response{
				Response: "scan ID is required",
				Type:     utilsapisv1.ErrorScanResponseType,
			}
			w.Write(responseToBytes(&response))
			return false, false
		}
	}

	if resultsQueryParams.ScanID == "" { // if no scan found
		logger.L().Info("empty scan ID")
		w.WriteHeader(http.StatusBadRequest)
		response := utilsmetav1.Response{
			Response: "latest scan not found",
			Type:     utilsapisv1.ErrorScanResponseType,
		}
		w.Write(responseToBytes(&response))
		return false, false
	}

	if handler.state.isBusy(resultsQueryParams.ScanID) { // if requested ID is still scanning
		logger.L().Info("scan in process", helpers.String("ID", resultsQueryParams.ScanID))
		w.WriteHeader(http.StatusOK)
		response := utilsmetav1.Response{
			Type:     utilsapisv1.BusyScanResponseType,
			Response: fmt.Sprintf("scanning '%s' in progress", resultsQueryParams.ScanID),
			ID:       resultsQueryParams.ScanID,
		}
		w.Write(responseToBytes(&response))
		return false, false
	}

	return isLatestFallback, true
}

// GetResults handles GET /v1/results
func (handler *HTTPHandler) GetResults(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	defer handler.recover(r.Context(), w, "")
	defer r.Body.Close()

	resultsQueryParams, ok := handler.parseResultsQueryParams(w, r)
	if !ok {
		return
	}

	isLatestFallback, ok := handler.validateScanID(w, resultsQueryParams)
	if !ok {
		return
	}

	response := utilsmetav1.Response{ID: resultsQueryParams.ScanID}
	logger.L().Info("requesting results", helpers.String("ID", resultsQueryParams.ScanID))

	if res, err := readResultsFile(resultsQueryParams.ScanID); err != nil {
		if scanFailed, isScanFailed := errors.AsType[*ScanFailedError](err); isScanFailed {
			logger.L().Info("scan failed", helpers.String("ID", resultsQueryParams.ScanID), helpers.String("reason", scanFailed.Message))
			w.WriteHeader(http.StatusInternalServerError)
			response.Type = utilsapisv1.ErrorScanResponseType
			response.Response = scanFailed.Message
			if !resultsQueryParams.KeepResults && !isLatestFallback {
				defer removeResultsFile(resultsQueryParams.ScanID)
			}
		} else {
			logger.L().Info("scan result not found", helpers.String("ID", resultsQueryParams.ScanID))
			w.WriteHeader(http.StatusNoContent)
			response.Response = err.Error()
		}
	} else {
		logger.L().Info("scan result found", helpers.String("ID", resultsQueryParams.ScanID))
		w.WriteHeader(http.StatusOK)
		response.Type = utilsapisv1.ResultsV1ScanResponseType
		response.Response = res

		if !resultsQueryParams.KeepResults {
			if isLatestFallback {
				logger.L().Info("keeping results for latest scan fallback to prevent unintended deletion", helpers.String("ID", resultsQueryParams.ScanID))
			} else {
				logger.L().Info("deleting results", helpers.String("ID", resultsQueryParams.ScanID))
				defer removeResultsFile(resultsQueryParams.ScanID)
			}
		}
	}
	w.Write(responseToBytes(&response))
}

// DeleteResults handles DELETE /v1/results
func (handler *HTTPHandler) DeleteResults(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	defer handler.recover(r.Context(), w, "")
	defer r.Body.Close()

	resultsQueryParams, ok := handler.parseResultsQueryParams(w, r)
	if !ok {
		return
	}

	if resultsQueryParams.AllResults {
		logger.L().Info("deleting all results")
		if err := handler.state.removeAllIfIdle(removeResultDirs); err != nil {
			handler.writeError(w, err, "")
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	isLatestFallback, ok := handler.validateScanID(w, resultsQueryParams)
	if !ok {
		return
	}

	logger.L().Info("deleting results", helpers.String("ID", resultsQueryParams.ScanID))

	if isLatestFallback {
		handler.writeError(w, fmt.Errorf("scan ID must be provided for deletion"), resultsQueryParams.ScanID)
		return
	}
	removeResultsFile(resultsQueryParams.ScanID)
	w.WriteHeader(http.StatusOK)
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
