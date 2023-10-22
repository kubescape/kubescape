package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"

	"github.com/gorilla/schema"
)

type scanResponseChan struct {
	scanResponseChan map[string]chan *utilsmetav1.Response
	mtx              sync.RWMutex
}

// get response object chan
func (resChan *scanResponseChan) get(key string) chan *utilsmetav1.Response {
	resChan.mtx.RLock()
	defer resChan.mtx.RUnlock()
	return resChan.scanResponseChan[key]
}

// set chan for response object
func (resChan *scanResponseChan) set(key string) {
	resChan.mtx.Lock()
	defer resChan.mtx.Unlock()
	resChan.scanResponseChan[key] = make(chan *utilsmetav1.Response)
}

// push response object to chan
func (resChan *scanResponseChan) push(key string, resp *utilsmetav1.Response) {
	resChan.mtx.Lock()
	defer resChan.mtx.Unlock()
	if _, ok := resChan.scanResponseChan[key]; ok {
		resChan.scanResponseChan[key] <- resp
	}
}

// delete channel
func (resChan *scanResponseChan) delete(key string) {
	resChan.mtx.Lock()
	defer resChan.mtx.Unlock()
	delete(resChan.scanResponseChan, key)
}
func newScanResponseChan() *scanResponseChan {
	return &scanResponseChan{
		scanResponseChan: make(map[string]chan *utilsmetav1.Response),
		mtx:              sync.RWMutex{},
	}
}

type ScanQueryParams struct {
	// Wait for scanning to complete (synchronous request)
	// default: false
	ReturnResults bool `schema:"wait" json:"wait"`
	// Do not delete results after returning (relevant only for synchronous requests)
	// default: false
	KeepResults bool `schema:"keep" json:"keep"`
}

// swagger:parameters getScanResults
type GetResultsQueryParams struct {
	// ID of the requested scan. If empty or not provided, defaults to the latest scan.
	//
	// in: query
	ScanID string `schema:"id" json:"id"`
	// Keep the results in local storage after returning them.
	//
	// By default, the Kubescape Microservice will delete scan results.
	//
	// in: query
	// default: false
	KeepResults bool `schema:"keep" json:"keep"`
}

// swagger:parameters deleteScanResults
type ResultsQueryParams struct {
	GetResultsQueryParams
	// Whether to delete all results
	//
	// in: query
	// default: false
	AllResults bool `schema:"all" json:"all"`
}

// swagger:parameters getStatus
type StatusQueryParams struct {
	// ID of the scan to check
	//
	// in:query
	// swagger:strfmt uuid4
	ScanID string `schema:"id" json:"id"`
}

// scanRequestParams params passed to channel
type scanRequestParams struct {
	scanInfo        *cautils.ScanInfo // request as received from api
	scanQueryParams *ScanQueryParams  // request as received from api
	scanID          string            // generated scan ID
	ctx             context.Context
}

// swagger:parameters triggerScan
type ScanRequest struct {
	ScanQueryParams
	// Scan parameters
	// in:body
	Body utilsmetav1.PostScanRequest
}

func getScanParamsFromRequest(r *http.Request, scanID string) (*scanRequestParams, error) {
	defer r.Body.Close()

	scanRequestParams := &scanRequestParams{}

	scanQueryParams := &ScanQueryParams{}
	if err := schema.NewDecoder().Decode(scanQueryParams, r.URL.Query()); err != nil {
		return scanRequestParams, fmt.Errorf("failed to parse query params, reason: %s", err.Error())
	}

	readBuffer, err := io.ReadAll(r.Body)
	if err != nil {
		// handler.writeError(w, fmt.Errorf("failed to read request body, reason: %s", err.Error()), scanID)
		return scanRequestParams, fmt.Errorf("failed to read request body, reason: %s", err.Error())
	}

	logger.L().Info("REST API received scan request", helpers.String("body", string(readBuffer)))

	scanRequest := &utilsmetav1.PostScanRequest{}
	if err := json.Unmarshal(readBuffer, &scanRequest); err != nil {
		return scanRequestParams, fmt.Errorf("failed to parse request payload, reason: %s", err.Error())
	}

	scanInfo := getScanCommand(scanRequest, scanID)

	scanRequestParams.scanID = scanID
	scanRequestParams.scanQueryParams = scanQueryParams
	scanRequestParams.scanInfo = scanInfo

	return scanRequestParams, nil
}
