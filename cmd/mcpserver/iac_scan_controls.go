package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler"
	printerv2 "github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

// iacControlPolicyIdentifiers validates the tool arguments and builds the
// policy identifiers shared by the IaC control scan and the remediation tool.
func iacControlPolicyIdentifiers(path string, controlIDs []string) ([]cautils.PolicyIdentifier, error) {
	filtered := make([]string, 0, len(controlIDs))
	for _, id := range controlIDs {
		if id = strings.TrimSpace(id); id != "" {
			filtered = append(filtered, id)
		}
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("at least one control ID is required")
	}
	if path == "" {
		return nil, fmt.Errorf("path is required")
	}
	policyIdentifiers := make([]cautils.PolicyIdentifier, len(filtered))
	for i, id := range filtered {
		policyIdentifiers[i] = cautils.PolicyIdentifier{Kind: apisv1.KindControl, Identifier: id}
	}
	return policyIdentifiers, nil
}

// runIaCScanControls scans local IaC at path against the given control IDs and
// returns the summarized scanResponse JSON used by the MCP scan tools.
func (ksServer *KubescapeMcpserver) runIaCScanControls(ctx context.Context, path string, controlIDs []string) ([]byte, error) {
	policyIdentifiers, err := iacControlPolicyIdentifiers(path, controlIDs)
	if err != nil {
		return nil, err
	}
	fileHandler := resourcehandler.NewFileResourceHandler()
	return runScan(ctx, ksServer, scanRequest{
		policyIdentifiers: policyIdentifiers,
		label:             "Local IaC Control",
		rsrcHandler:       fileHandler,
		inputPatterns:     []string{path},
	})
}

// iacScanOutcome carries the PostureReport together with the scan's coverage
// signal. printerv2.FinalizeResults does not copy ScanCoverage into the report,
// so a caller holding only the report JSON cannot tell a control that genuinely
// passed from one the scan never evaluated. The summarized scanResponse exposes
// this as its `degraded` flag; the report path has to carry it explicitly.
type iacScanOutcome struct {
	ReportJSON []byte
	// Degraded mirrors runScan's signal: the scan did not fully complete,
	// either because coverage was incomplete or because rule processing
	// partially failed.
	Degraded bool
	// NotEvaluatedControls lists controls the scan could not evaluate, with the
	// reason, so callers can surface them instead of reporting "nothing to fix".
	NotEvaluatedControls []cautils.NotEvaluatedControl
}

// runIaCScanControlsReport runs the same scan as runIaCScanControls but returns
// the full v2 PostureReport JSON — the document `kubescape scan --format json`
// writes, and the only format fixhandler.NewFixHandler accepts. The scan tools
// return a summarized scanResponse instead, which the fixhandler rejects.
//
// A non-fatal rule-processing error does not fail the scan (controls that did
// evaluate still yield valid fixes) but it is reported through the outcome's
// Degraded flag rather than discarded: a partially-failed run can drop a
// requested control before it is ever evaluated, and the caller has to be able
// to see that.
func (ksServer *KubescapeMcpserver) runIaCScanControlsReport(ctx context.Context, path string, controlIDs []string) (*iacScanOutcome, error) {
	policyIdentifiers, err := iacControlPolicyIdentifiers(path, controlIDs)
	if err != nil {
		return nil, err
	}
	fileHandler := resourcehandler.NewFileResourceHandler()
	scanData, processErr, err := executeScan(ctx, ksServer, scanRequest{
		policyIdentifiers: policyIdentifiers,
		label:             "Local IaC Remediation",
		rsrcHandler:       fileHandler,
		inputPatterns:     []string{path},
	})
	if err != nil {
		return nil, err
	}
	report := printerv2.FinalizeResults(scanData)

	// FinalizeResults does not copy ScanCoverage, but the document
	// `kubescape scan --format json` writes does carry it: ResultsHandler.ToJson
	// embeds the PostureReport and adds a top-level scanCoverage key. Mirror that
	// shape so the coverage gaps travel with the report rather than being
	// dropped. NewFixHandler unmarshals into reporthandlingv2.PostureReport,
	// which ignores the extra key.
	output := struct {
		*reporthandlingv2.PostureReport
		ScanCoverage *cautils.ScanCoverage `json:"scanCoverage,omitempty"`
	}{
		PostureReport: report,
		ScanCoverage:  &scanData.ScanCoverage,
	}
	reportJSON, err := json.Marshal(&output)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal posture report: %w", err)
	}
	return &iacScanOutcome{
		ReportJSON:           reportJSON,
		Degraded:             scanData.ScanCoverage.Degraded || processErr != nil,
		NotEvaluatedControls: scanData.ScanCoverage.NotEvaluatedControls,
	}, nil
}
