package v1

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	utilsmetav1 "github.com/armosec/opa-utils/httpserver/meta/v1"

	"github.com/armosec/kubescape/v2/core/cautils/logger"
	"github.com/armosec/kubescape/v2/core/cautils/logger/helpers"
	"github.com/google/uuid"
)

var OutputDir = "./results"
var FailedOutputDir = "./failed"

type HTTPHandler struct {
	state *serverState
}

func NewHTTPHandler() *HTTPHandler {
	return &HTTPHandler{
		state: newServerState(),
	}
}
func (handler *HTTPHandler) Scan(w http.ResponseWriter, r *http.Request) {
	response := utilsmetav1.Response{}
	w.Header().Set("Content-Type", "application/json")

	defer func() {
		if err := recover(); err != nil {
			handler.state.setNotBusy()
			logger.L().Error("Scan recover", helpers.Error(fmt.Errorf("%v", err)))
			w.WriteHeader(http.StatusInternalServerError)
			response.Response = []byte(fmt.Sprintf("%v", err))
			response.Type = utilsmetav1.ErrorScanResponseType
			w.Write(responseToBytes(&response))
		}
	}()

	defer r.Body.Close()

	switch r.Method {
	case http.MethodGet: // return request template
		json.NewEncoder(w).Encode(utilsmetav1.PostScanRequest{})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		return
	case http.MethodPost:
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if handler.state.isBusy() {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(handler.state.getID()))
		return
	}

	handler.state.setBusy()

	// generate id
	scanID := uuid.NewString()
	handler.state.setID(scanID)
	response.ID = scanID
	response.Type = utilsmetav1.IDScanResponseType

	readBuffer, err := ioutil.ReadAll(r.Body)
	if err != nil {
		defer handler.state.setNotBusy()
		w.WriteHeader(http.StatusBadRequest)
		response.Response = []byte(fmt.Sprintf("failed to read request body, reason: %s", err.Error()))
		response.Type = utilsmetav1.ErrorScanResponseType
		w.Write(responseToBytes(&response))
		return
	}
	scanRequest := utilsmetav1.PostScanRequest{}
	if err := json.Unmarshal(readBuffer, &scanRequest); err != nil {
		defer handler.state.setNotBusy()
		w.WriteHeader(http.StatusBadRequest)
		response.Response = []byte(fmt.Sprintf("failed to parse request payload, reason: %s", err.Error()))
		response.Type = utilsmetav1.ErrorScanResponseType
		w.Write(responseToBytes(&response))
		return
	}

	returnResults := r.URL.Query().Has("wait")
	var wg sync.WaitGroup
	if returnResults {
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
			if returnResults {
				response.Type = utilsmetav1.ErrorScanResponseType
				response.Response = []byte(err.Error())
				statusCode = http.StatusInternalServerError
			}
		} else {
			logger.L().Success("done scanning", helpers.String("ID", scanID))
			if returnResults {
				response.Type = utilsmetav1.ResultsV1ScanResponseType
				response.Response = results
				wg.Done()
			}
		}
		handler.state.setNotBusy()
	}()

	wg.Wait()

	w.WriteHeader(statusCode)
	w.Write(responseToBytes(&response))
}
func (handler *HTTPHandler) Results(w http.ResponseWriter, r *http.Request) {
	response := utilsmetav1.Response{}
	w.Header().Set("Content-Type", "application/json")

	defer func() {
		if err := recover(); err != nil {
			handler.state.setNotBusy()
			logger.L().Error("Results recover", helpers.Error(fmt.Errorf("%v", err)))
			w.WriteHeader(http.StatusInternalServerError)
			response.Response = []byte(fmt.Sprintf("%v", err))
			response.Type = utilsmetav1.ErrorScanResponseType
			w.Write(responseToBytes(&response))
		}
	}()

	defer r.Body.Close()

	var scanID string
	if scanID = r.URL.Query().Get("id"); scanID == "" {
		scanID = handler.state.getLatestID()
	}
	if scanID == "" { // if no scan found
		logger.L().Info("empty scan ID")
		w.WriteHeader(http.StatusBadRequest) // Should we return ok?
		response.Response = []byte("latest scan not found. trigger again")
		response.Type = utilsmetav1.ErrorScanResponseType
		w.Write(responseToBytes(&response))
		return
	}
	response.ID = scanID

	if handler.state.isBusy() { // if requested ID is still scanning
		if scanID == handler.state.getID() {
			logger.L().Info("scan in process", helpers.String("ID", scanID))
			w.WriteHeader(http.StatusOK)
			response.Response = []byte("scanning in progress")
			w.Write(responseToBytes(&response))
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		logger.L().Info("requesting results", helpers.String("ID", scanID))

		if r.URL.Query().Has("remove") {
			logger.L().Info("deleting results", helpers.String("ID", scanID))
			defer removeResultsFile(scanID)
		}
		if res, err := readResultsFile(scanID); err != nil {
			logger.L().Info("scan result not found", helpers.String("ID", scanID))
			w.WriteHeader(http.StatusNoContent)
			response.Response = []byte(err.Error())
		} else {
			logger.L().Info("scan result found", helpers.String("ID", scanID))
			w.WriteHeader(http.StatusOK)
			response.Response = res
		}
		w.Write(responseToBytes(&response))
	case http.MethodDelete:
		logger.L().Info("deleting results", helpers.String("ID", scanID))

		if r.URL.Query().Has("all") {
			removeResultDirs()
		} else {
			removeResultsFile(scanID)
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
