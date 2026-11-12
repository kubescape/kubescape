package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/schema"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
)

type ScanQueryParams struct {
	// Wait for scanning to complete (synchronous request)
	// default: false
	ReturnResults bool `schema:"wait" json:"wait"`
	// Do not delete results after returning (relevant only for synchronous requests)
	// default: false
	KeepResults bool `schema:"keep" json:"keep"`
	// Do not persist data after scanning
	//default: false
	SkipPersistence bool `schema:"skipPersistence" json:"skipPersistence"`
	// URL to POST a scan-completion signal to when the scan finishes.
	// The callback carries the scan ID only; results must be fetched via GET /v1/results.
	CallbackURL string `schema:"callback" json:"callback"`
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
	// A GET that deletes them needs both the get and delete verbs on scanresults; read-only callers must pass keep=true.
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

// swagger:parameters cancelScan
type CancelScanQueryParams struct {
	// ID of the scan to cancel. If empty, the latest scan is cancelled.
	//
	// in:query
	// swagger:strfmt uuid4
	ScanID string `schema:"id" json:"id"`
}

// scanRequestParams params passed to channel
type scanRequestParams struct {
	scanInfo          *cautils.ScanInfo          // request as received from api
	policyIdentifiers []cautils.PolicyIdentifier // policies to scan
	scanQueryParams   *ScanQueryParams           // request as received from api
	scanID            string                     // generated scan ID
	ctx               context.Context
	resp              chan *utilsmetav1.Response // Response chan; nil if not interested.
	callbackURL       string                     // validated scan-completion callback URL; empty if not requested.
	isUserScan        bool                       // true when submitted via the Scan handler, not Metrics
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
			// handler.writeError(w, fmt.Errorf("failed to read request body, reason: %w", err), scanID)
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		if err := json.Unmarshal(readBuffer, &scanRequest); err != nil {
			return nil, fmt.Errorf("failed to parse request payload, reason: %w", err)
		}
		for _, control := range scanRequest.ExcludeControls {
			if strings.TrimSpace(control) == "" {
				return nil, fmt.Errorf("excludeControls contains an empty control identifier")
			}
		}
		logger.L().Info("REST API received scan request", helpers.String("scanID", scanID), helpers.String("format", scanRequest.Format))
	}

	// Validate the whole request before converting it: getScanCommand writes
	// the request's exceptions to a temp file, so a request rejected here must
	// not reach it.
	scanQueryParams := &ScanQueryParams{}
	if err := schema.NewDecoder().Decode(scanQueryParams, r.URL.Query()); err != nil {
		return nil, fmt.Errorf("failed to parse query params, reason: %w", err)
	}
	if scanQueryParams.CallbackURL != "" {
		if _, err := validateCallbackURL(scanQueryParams.CallbackURL); err != nil {
			return nil, err
		}
	}

	scanInfo, policyIdentifiers := getScanCommand(scanRequest, scanID)
	p := &scanRequestParams{
		scanID:            scanID,
		scanQueryParams:   scanQueryParams,
		scanInfo:          scanInfo,
		policyIdentifiers: policyIdentifiers,
		callbackURL:       scanQueryParams.CallbackURL,
		isUserScan:        true,
	}
	if scanQueryParams.ReturnResults {
		p.resp = make(chan *utilsmetav1.Response, 1)
	}

	return p, nil
}

// releaseScanInfo runs the cleanups ToScanInfo registered, such as removing
// the request's exceptions temp file, for a request that will never reach
// core.Scan, which otherwise runs them. ScanInfo.Cleanup is not safe for
// concurrent use, so only the request's current owner may call this: the
// handler until the request is queued, the worker once it has dequeued it.
func (p *scanRequestParams) releaseScanInfo() {
	if p != nil && p.scanInfo != nil {
		p.scanInfo.Cleanup()
	}
}
