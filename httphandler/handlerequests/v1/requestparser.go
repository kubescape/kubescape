package v1

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/armosec/kubescape/v2/core/cautils"
	utilsmetav1 "github.com/armosec/opa-utils/httpserver/meta/v1"
	logger "github.com/dwertent/go-logger"
	"github.com/dwertent/go-logger/helpers"

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

// scanRequestParams params passed to channel
type scanRequestParams struct {
	scanInfo        *cautils.ScanInfo // request as received from api
	scanQueryParams *ScanQueryParams  // request as received from api
	scanID          string            // generated scan ID
}

func getScanParamsFromRequest(r *http.Request, scanID string) (*scanRequestParams, error) {
	defer r.Body.Close()

	scanRequestParams := &scanRequestParams{}

	scanQueryParams := &ScanQueryParams{}
	if err := schema.NewDecoder().Decode(scanQueryParams, r.URL.Query()); err != nil {
		return scanRequestParams, fmt.Errorf("failed to parse query params, reason: %s", err.Error())
	}

	readBuffer, err := ioutil.ReadAll(r.Body)
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
