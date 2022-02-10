package listener

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/armosec/kubescape/cautils/logger"
	"github.com/gorilla/mux"
)

type HTTPListener struct {
	keyPair *tls.Certificate
	// Listeners
}

func NewListener() *HTTPListener {
	return &HTTPListener{
		keyPair: nil,
	}
}

// SetupHTTPListener set up listening http servers
func (resthandler *HTTPListener) SetupHTTPListener() error {
	err := resthandler.loadTLSKey("", "") // TODO - support key and crt files
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: fmt.Sprintf(":%s", "4000"), // TODO - support loading port from config/env
	}
	if resthandler.keyPair != nil {
		server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*resthandler.keyPair}}
	}

	rtr := mux.NewRouter()
	// rtr.HandleFunc(opapolicy.PostureRestAPIPathV1, resthandler.RestAPIReceiveNotification)

	server.Handler = rtr

	logger.L().Info("") // TODO - set log message

	// listen
	if resthandler.keyPair != nil {
		return server.ListenAndServeTLS("", "")
	} else {
		return server.ListenAndServe()
	}
}

// func (resthandler *HTTPHandler) Scan(w http.ResponseWriter, r *http.Request) {
// 	defer func() {
// 		if err := recover(); err != nil {
// 			glog.Error(err)
// 			w.WriteHeader(http.StatusInternalServerError)
// 			bErr, _ := json.Marshal(err)
// 			w.Write(bErr)
// 		}
// 	}()
// 	defer r.Body.Close()
// 	var err error
// 	returnValue := []byte("ok")

// 	httpStatus := http.StatusOK
// 	readBuffer, err := ioutil.ReadAll(r.Body)
// 	if err != nil {
// 		err = fmt.Errorf("Failed to read request body, reason: %s", err.Error())
// 		w.WriteHeader(http.StatusBadRequest)
// 		w.Write([]byte(err.Error()))
// 		return
// 	}
// 	switch r.Method {
// 	case http.MethodPost:
// 		// handle post
// 	case http.MethodGet:
// 		// handle get
// 	default:
// 		httpStatus = http.StatusMethodNotAllowed
// 		err = fmt.Errorf("Method %s no allowed", r.Method)
// 	}
// 	if err != nil {
// 		returnValue = []byte(err.Error())
// 		httpStatus = http.StatusBadRequest
// 	}

// 	w.WriteHeader(httpStatus)
// 	w.Write(returnValue)
// }

func (resthandler *HTTPListener) loadTLSKey(certFile, keyFile string) error {
	if keyFile == "" || certFile == "" {
		return nil
	}

	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("filed to load key pair: %v", err)
	}
	resthandler.keyPair = &pair
	return nil
}
