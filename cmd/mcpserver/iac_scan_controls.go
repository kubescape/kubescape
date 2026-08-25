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
	return runScan(ctx, ksServer, "", policyIdentifiers, "Local IaC Control", false, fileHandler, []string{path}, nil)
}

// runIaCScanControlsReport runs the same scan as runIaCScanControls but returns
// the full v2 PostureReport JSON — the document `kubescape scan --format json`
// writes, and the only format fixhandler.NewFixHandler accepts. The scan tools
// return a summarized scanResponse instead, which the fixhandler rejects.
//
// A non-fatal rule-processing error is tolerated, matching runScan: controls
// that did evaluate still yield valid fixes.
func (ksServer *KubescapeMcpserver) runIaCScanControlsReport(ctx context.Context, path string, controlIDs []string) ([]byte, error) {
	policyIdentifiers, err := iacControlPolicyIdentifiers(path, controlIDs)
	if err != nil {
		return nil, err
	}
	fileHandler := resourcehandler.NewFileResourceHandler()
	scanData, _, err := executeScan(ctx, ksServer, "", policyIdentifiers, "Local IaC Remediation", false, fileHandler, []string{path}, nil)
	if err != nil {
		return nil, err
	}
	report := printerv2.FinalizeResults(scanData)
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal posture report: %w", err)
	}
	return reportJSON, nil
}
