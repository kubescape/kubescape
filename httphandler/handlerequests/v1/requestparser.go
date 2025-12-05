package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gorilla/schema"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
)

type ScanQueryParams struct {
	// Wait for scanning to complete (synchronous request)
	// default: false
	ReturnResults bool `schema:"wait" json:"wait"`
	// Do not delete results after returning (relevant only for synchronous requests)
	// default: false
	KeepResults bool `schema:"keep" json:"keep"`
	// Donot persist data after scanning
	//default: false
	SkipPersistence bool `schema:"skipPersistence" json:"skipPersistence"`
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
	resp            chan *utilsmetav1.Response // Respose chan; nil if not interested.
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

	scanRequest := &utilsmetav1.PostScanRequest{}
	{
		readBuffer, err := io.ReadAll(r.Body)
		if err != nil {
			// handler.writeError(w, fmt.Errorf("failed to read request body, reason: %s", err.Error()), scanID)
			return nil, fmt.Errorf("failed to read request body, reason: %s", err.Error())
		}
		logger.L().Info("REST API received scan request", helpers.String("body", string(readBuffer)))
		if err := json.Unmarshal(readBuffer, &scanRequest); err != nil {
			return nil, fmt.Errorf("failed to parse request payload, reason: %s", err.Error())
		}
	}

	p := &scanRequestParams{
		scanID:          scanID,
		scanQueryParams: &ScanQueryParams{},
		scanInfo:        getScanCommand(scanRequest, scanID),
	}
	if err := schema.NewDecoder().Decode(p.scanQueryParams, r.URL.Query()); err != nil {
		return p, fmt.Errorf("failed to parse query params, reason: %s", err.Error())
	}
	if p.scanQueryParams.ReturnResults {
		p.resp = make(chan *utilsmetav1.Response, 1)
	}

	return p, nil
}
