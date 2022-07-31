package listener

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	"github.com/armosec/kubescape/v2/core/cautils"
	handlerequestsv1 "github.com/armosec/kubescape/v2/httphandler/handlerequests/v1"
	logger "github.com/dwertent/go-logger"
	"github.com/dwertent/go-logger/helpers"

	"github.com/gorilla/mux"
)

const (
	scanPath              = "/v1/scan"
	statusPath            = "/v1/status"
	resultsPath           = "/v1/results"
	prometheusMmeticsPath = "/v1/metrics"
	livePath              = "/livez"
	readyPath             = "/readyz"
	heap                  = "/heap"
)

// SetupHTTPListener set up listening http servers
func SetupHTTPListener() error {
	initialize()

	keyPair, err := loadTLSKey("", "") // TODO - support key and crt files
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: fmt.Sprintf(":%s", getPort()), // TODO - support loading port from config/env
	}
	if keyPair != nil {
		server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*keyPair}}
	}

	rtr := mux.NewRouter()
	// rtr.HandleFunc(opapolicy.PostureRestAPIPathV1, resthandler.RestAPIReceiveNotification)

	// listen
	httpHandler := handlerequestsv1.NewHTTPHandler()

	rtr.HandleFunc(prometheusMmeticsPath, httpHandler.Metrics)
	rtr.HandleFunc(scanPath, httpHandler.Scan)
	rtr.HandleFunc(statusPath, httpHandler.Status)
	rtr.HandleFunc(resultsPath, httpHandler.Results)
	rtr.HandleFunc(livePath, httpHandler.Live)
	rtr.HandleFunc(readyPath, httpHandler.Ready)
	rtr.HandleFunc(heap, httpHandler.Heap)

	server.Handler = rtr

	logger.L().Info("Started Kubescape server", helpers.String("port", getPort()), helpers.String("version", cautils.BuildNumber))
	server.ListenAndServe()
	if keyPair != nil {
		return server.ListenAndServeTLS("", "")
	}
	return server.ListenAndServe()
}

func loadTLSKey(certFile, keyFile string) (*tls.Certificate, error) {
	if keyFile == "" || certFile == "" {
		return nil, nil
	}

	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("filed to load key pair: %v", err)
	}
	return &pair, nil
}

func getPort() string {
	if p := os.Getenv("KS_PORT"); p != "" {
		return p
	}
	return "8080"
}
