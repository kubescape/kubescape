package v1

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	utilsapisv1 "github.com/armosec/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/armosec/opa-utils/httpserver/meta/v1"
	"github.com/gorilla/schema"

	"github.com/armosec/kubescape/v2/core/cautils/logger"
	"github.com/armosec/kubescape/v2/core/cautils/logger/helpers"
	"github.com/google/uuid"
)

var OutputDir = "./results"
var FailedOutputDir = "./failed"

type ScanQueryParams struct {
	ReturnResults bool `schema:"wait"` // wait for scanning to complete (synchronized request)
	KeepResults   bool `schema:"keep"` // do not delete results after returning (relevant only for synchronized requests)
}

type ResultsQueryParams struct {
	ScanID      string `schema:"id"`
	KeepResults bool   `schema:"keep"` // do not delete results after returning (default will delete results)
	AllResults  bool   `schema:"all"`  // delete all results
}

type StatusQueryParams struct {
	ScanID string `schema:"id"`
}

type HTTPHandler struct {
	state *serverState
}

func NewHTTPHandler() *HTTPHandler {
	return &HTTPHandler{
		state: newServerState(),
	}
}

// ============================================== STATUS ========================================================
// Status API
func (handler *HTTPHandler) Status(w http.ResponseWriter, r *http.Request) {
	defer handler.recover(w, "")

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	response := utilsmetav1.Response{}
	w.Header().Set("Content-Type", "application/json")

	statusQueryParams := &StatusQueryParams{}
	if err := schema.NewDecoder().Decode(statusQueryParams, r.URL.Query()); err != nil {
		handler.writeError(w, fmt.Errorf("failed to parse query params, reason: %s", err.Error()), "")
		return
	}

	if !handler.state.isBusy(statusQueryParams.ScanID) {
		response.Type = utilsapisv1.NotBusyScanResponseType
		w.Write(responseToBytes(&response))
		return
	}

	if statusQueryParams.ScanID == "" {
		statusQueryParams.ScanID = handler.state.getLatestID()
	}

	response.Response = statusQueryParams.ScanID
	response.ID = statusQueryParams.ScanID
	response.Type = utilsapisv1.BusyScanResponseType
	w.Write(responseToBytes(&response))
}

// ============================================== SCAN ========================================================
// Scan API - TODO: break down to functions
func (handler *HTTPHandler) Scan(w http.ResponseWriter, r *http.Request) {

	// generate id
	scanID := uuid.NewString()

	defer handler.recover(w, scanID)

	defer r.Body.Close()

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	response := utilsmetav1.Response{}
	w.Header().Set("Content-Type", "application/json")

	scanQueryParams := &ScanQueryParams{}
	if err := schema.NewDecoder().Decode(scanQueryParams, r.URL.Query()); err != nil {
		handler.writeError(w, fmt.Errorf("failed to parse query params, reason: %s", err.Error()), scanID)
		return
	}

	handler.state.setBusy(scanID)

	// Add to queue

	response.ID = scanID
	response.Type = utilsapisv1.IDScanResponseType

	readBuffer, err := ioutil.ReadAll(r.Body)
	if err != nil {
		handler.writeError(w, fmt.Errorf("failed to read request body, reason: %s", err.Error()), scanID)
		return
	}

	logger.L().Info("REST API received scan request", helpers.String("body", string(readBuffer)))

	scanRequest := utilsmetav1.PostScanRequest{}
	if err := json.Unmarshal(readBuffer, &scanRequest); err != nil {
		handler.writeError(w, fmt.Errorf("failed to parse request payload, reason: %s", err.Error()), scanID)
		return
	}

	var wg sync.WaitGroup
	if scanQueryParams.ReturnResults {
		wg.Add(1)
	} else {
		wg.Add(0)
	}
	statusCode := http.StatusOK
	go func() {
		// execute scan in the background

		logger.L().Info("scan triggered", helpers.String("ID", scanID))

		results, err := scan(&scanRequest, scanID)
		if err != nil {
			logger.L().Error("scanning failed", helpers.String("ID", scanID), helpers.Error(err))
			if scanQueryParams.ReturnResults {
				response.Type = utilsapisv1.ErrorScanResponseType
				response.Response = err.Error()
				statusCode = http.StatusInternalServerError
			}
		} else {
			logger.L().Success("done scanning", helpers.String("ID", scanID))
			if scanQueryParams.ReturnResults {
				response.Type = utilsapisv1.ResultsV1ScanResponseType
				response.Response = results
				wg.Done()
			}
		}
		if scanQueryParams.ReturnResults && !scanQueryParams.KeepResults {
			logger.L().Debug("deleting results", helpers.String("ID", scanID))
			removeResultsFile(scanID)
		}
		handler.state.setNotBusy(scanID)
	}()

	wg.Wait()

	w.WriteHeader(statusCode)
	w.Write(responseToBytes(&response))
}
func (handler *HTTPHandler) scan() {
	for {

	}
}

// ============================================== RESULTS ========================================================

// Results API - TODO: break down to functions
func (handler *HTTPHandler) Results(w http.ResponseWriter, r *http.Request) {
	response := utilsmetav1.Response{}
	w.Header().Set("Content-Type", "application/json")

	defer handler.recover(w, "")

	defer r.Body.Close()

	resultsQueryParams := &ResultsQueryParams{}
	if err := schema.NewDecoder().Decode(resultsQueryParams, r.URL.Query()); err != nil {
		handler.writeError(w, fmt.Errorf("failed to parse query params, reason: %s", err.Error()), "")
		return
	}

	if resultsQueryParams.ScanID == "" {
		resultsQueryParams.ScanID = handler.state.getLatestID()
	}

	if resultsQueryParams.ScanID == "" { // if no scan found
		logger.L().Info("empty scan ID")
		w.WriteHeader(http.StatusBadRequest) // Should we return ok?
		response.Response = "latest scan not found. trigger again"
		response.Type = utilsapisv1.ErrorScanResponseType
		w.Write(responseToBytes(&response))
		return
	}
	response.ID = resultsQueryParams.ScanID

	if handler.state.isBusy(resultsQueryParams.ScanID) { // if requested ID is still scanning
		logger.L().Info("scan in process", helpers.String("ID", resultsQueryParams.ScanID))
		w.WriteHeader(http.StatusOK)
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

func responseToBytes(res *utilsmetav1.Response) []byte {
	b, _ := json.Marshal(res)
	return b
}

func (handler *HTTPHandler) recover(w http.ResponseWriter, scanID string) {
	response := utilsmetav1.Response{}
	if err := recover(); err != nil {
		handler.state.setNotBusy(scanID)
		logger.L().Error("recover", helpers.Error(fmt.Errorf("%v", err)))
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
