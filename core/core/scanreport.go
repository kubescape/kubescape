package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/remediationverify"
)

// ScanReport is the report of a completed scan, held in memory.
type ScanReport struct {
	// JSON is the report in the form `kubescape scan --format json` writes: the
	// posture report with its resources and a top-level scanCoverage. It always
	// carries the coverage, which ResultsHandler.ToJson leaves out when the scan
	// was clean, so that a reader can tell a clean scan from one that reports
	// nothing about itself.
	JSON []byte
	// Degraded is set when the scan could not evaluate everything it was asked
	// to; see cautils.ScanCoverage.
	Degraded bool
}

// ScanToReport scans local inputs through the same ScanContext `kubescape scan`
// uses and returns the report in memory. No results are handled, so nothing is
// printed, written or submitted, and no output file is opened or truncated.
//
// It does not change scanInfo: every call scans a copy, so one ScanInfo can
// serve a series of scans, or scans running at the same time. The copy is
// stripped of its output settings and, as with ScanInfo.CloneForContext, its
// kube-context override; this is for scans of local manifests, and a scan of a
// cluster is refused. A scan of local manifests that is not to touch a cluster
// or the network sets NoClusterAccess and Local. A series of scans sets
// ReleasedPolicyStore to download the released policies once.
//
// The report holds the resources the scan read unless scanInfo omits them
// (OmitRawResources), in which case it has none, and a reader that identifies
// findings by their resources cannot use it.
//
// Any error, including a partial failure to process the rules and the end of ctx,
// is returned as an error and not as a report: a conclusion is only drawn from a
// scan that completed. An error from ScanContext is returned as it is, so what it
// wraps, a context's error for one, can still be found in it.
func (ks *Kubescape) ScanToReport(ctx context.Context, scanInfo *cautils.ScanInfo, policyIdentifiers []cautils.PolicyIdentifier) (*ScanReport, error) {
	if scanInfo == nil {
		return nil, errors.New("scan info is required")
	}
	if scanInfo.DryRun {
		return nil, errors.New("a dry run collects nothing, so there is no report to return")
	}
	if scanInfo.EncryptionEnabled {
		// The scan encrypts the sensitive fields of its results in place, so the
		// report would come back unreadable.
		return nil, errors.New("an encrypted scan cannot be returned as an in-memory report")
	}

	scan := scanInfo.CloneForContext("", "")
	scan.Format = ""
	// Asked of the copy: working out the scanning context remembers it in the
	// ScanInfo, which for the caller's, shared by scans that run at once, would
	// be a write.
	if scan.GetScanningContext() == cautils.ContextCluster {
		return nil, errors.New("only a scan of local inputs can be returned as an in-memory report")
	}

	results, err := ks.ScanContext(ctx, scan, policyIdentifiers)
	if err != nil {
		return nil, err
	}
	if results == nil || results.GetData() == nil {
		return nil, errors.New("the scan returned no results")
	}
	coverage := &results.GetData().ScanCoverage
	reportJSON, err := remediationverify.ReportJSON(results.GetResults(), coverage)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize the scan report: %w", err)
	}
	return &ScanReport{JSON: reportJSON, Degraded: coverage.Degraded}, nil
}
