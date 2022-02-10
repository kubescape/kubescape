package v1

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	uuid "github.com/satori/go.uuid"

	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/cautils/logger/helpers"
)

var OutputDir = "/results"

type serverState struct {
	// response string
	busy bool
	id   string
	mtx  sync.RWMutex
}

func (s *serverState) isBusy() bool {
	s.mtx.RLock()
	busy := s.busy
	s.mtx.RUnlock()
	return busy
}

func (s *serverState) setBusy() {
	s.mtx.Lock()
	s.busy = true
	s.mtx.Unlock()
}

func (s *serverState) setNotBusy() {
	s.mtx.Lock()
	s.busy = false
	s.id = ""
	s.mtx.Unlock()
}

func (s *serverState) getID() string {
	s.mtx.RLock()
	id := s.id
	s.mtx.RUnlock()
	return id
}

func (s *serverState) setID(id string) {
	s.mtx.Lock()
	s.id = id
	s.mtx.Unlock()
}

func newServerState() *serverState {
	return &serverState{
		busy: false,
		mtx:  sync.RWMutex{},
	}
}

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
			logger.L().Error("", helpers.Error(fmt.Errorf("%v", err)))
			w.WriteHeader(http.StatusInternalServerError)
			bErr, _ := json.Marshal(err)
			w.Write(bErr)
		}
	}()

	defer r.Body.Close()

	if handler.state.isBusy() {
		// server is busy, do not execute any scan
		w.Write([]byte(fmt.Sprintf("server is busy with ID: %s", handler.state.getID())))
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	handler.state.setBusy()

	// generate id
	scanID := uuid.NewV4().String()
	handler.state.setID(scanID)

	if r.Method != http.MethodPost {
		defer handler.state.setNotBusy()
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	readBuffer, err := ioutil.ReadAll(r.Body)
	if err != nil {
		defer handler.state.setNotBusy()
		err = fmt.Errorf("failed to read request body, reason: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	defer handler.state.setNotBusy()
	if err := handler.executeScanRequest(readBuffer, scanID); err != nil {
		// write error to file
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(scanID))
}

// func (handler *HTTPHandler) Results(w http.ResponseWriter, r *http.Request) {
// 	defer listener.RecoverFunc(w)

// 	defer r.Body.Close()

// 	if r.Method != http.MethodGet {
// 		w.WriteHeader(http.StatusMethodNotAllowed)
// 		return
// 	}

// 	if scanID := r.URL.Query().Get("scanID"); scanID == "" {
// 		scanID = "latest"
// 	}

// 	switch r.Method {
// 	case http.MethodGet:
// 	case http.MethodDelete:
// 		// TODO - support
// 	}

// 	httpStatus := http.StatusOK
// 	readBuffer, err := ioutil.ReadAll(r.Body)
// 	if err != nil {
// 		err = fmt.Errorf("failed to read request body, reason: %s", err.Error())
// 		w.WriteHeader(http.StatusBadRequest)
// 		w.Write([]byte(err.Error()))
// 		return
// 	}

// 	scanID, err := handler.getResults(scanID)
// 	if err != nil {
// 		w.WriteHeader(http.StatusInternalServerError)
// 		w.Write([]byte(err.Error()))
// 		return
// 	}

// 	w.WriteHeader(httpStatus)
// 	w.Write([]byte(scanID))
// }
