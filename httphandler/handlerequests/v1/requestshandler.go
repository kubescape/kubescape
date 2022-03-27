package v1

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/armosec/kubescape/core/cautils/logger"
	"github.com/armosec/kubescape/core/cautils/logger/helpers"
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
	defer func() {
		if err := recover(); err != nil {
			handler.state.setNotBusy()
			logger.L().Error("Scan recover", helpers.Error(fmt.Errorf("%v", err)))
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("%v", err)))
		}
	}()

	defer r.Body.Close()

	switch r.Method {
	case http.MethodGet: // return request template
		json.NewEncoder(w).Encode(PostScanRequest{})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		return
	case http.MethodPost:
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if handler.state.isBusy() {
		w.Write([]byte(handler.state.getID()))
		w.WriteHeader(http.StatusOK)
		return
	}

	handler.state.setBusy()

	// generate id
	scanID := uuid.NewString()
	handler.state.setID(scanID)

	readBuffer, err := ioutil.ReadAll(r.Body)
	if err != nil {
		defer handler.state.setNotBusy()
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("failed to read request body, reason: %s", err.Error())))
		return
	}
	scanRequest := PostScanRequest{}
	if err := json.Unmarshal(readBuffer, &scanRequest); err != nil {
		defer handler.state.setNotBusy()
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("failed to parse request payload, reason: %s", err.Error())))
		return
	}

	response := []byte(scanID)

	returnResults := r.URL.Query().Has("wait")
	var wg sync.WaitGroup
	if returnResults {
		wg.Add(1)
	} else {
		wg.Add(0)
	}

	go func() {
		// execute scan in the background

		logger.L().Info("scan triggered", helpers.String("ID", scanID))

		results, err := scan(&scanRequest, scanID)
		if err != nil {
			logger.L().Error("scanning failed", helpers.String("ID", scanID), helpers.Error(err))
			if returnResults {
				response = []byte(err.Error())
				w.WriteHeader(http.StatusInternalServerError)
			}
		} else {
			logger.L().Success("done scanning", helpers.String("ID", scanID))
			if returnResults {
				w.Header().Set("Content-Type", "application/json")
				response = results
				wg.Done()
			}
		}
		handler.state.setNotBusy()
	}()

	wg.Wait()
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}
func (handler *HTTPHandler) Results(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			handler.state.setNotBusy()
			logger.L().Error("Results recover", helpers.Error(fmt.Errorf("%v", err)))
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("%v", err)))
		}
	}()

	defer r.Body.Close()

	var scanID string
	if scanID = r.URL.Query().Get("scanID"); scanID == "" {
		scanID = handler.state.getLatestID()
	}

	if handler.state.isBusy() { // if requested ID is still scanning
		if scanID == handler.state.getID() {
			logger.L().Info("scan in process", helpers.String("ID", scanID))
			w.WriteHeader(http.StatusOK) // Should we return ok?
			w.Write([]byte(handler.state.getID()))
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		logger.L().Info("requesting results", helpers.String("ID", scanID))

		if r.URL.Query().Has("remove") {
			defer removeResultsFile(scanID)
		}
		if res, err := readResultsFile(scanID); err != nil {
			w.WriteHeader(http.StatusNoContent)
			w.Write([]byte(err.Error()))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write(res)
		}
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
