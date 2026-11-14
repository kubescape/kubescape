package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/remediationverify"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
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
// stripped of its output settings (the format and the severity filters, which
// are applied only when results are handled) and, as with
// ScanInfo.CloneForContext, its kube-context override; this is for scans of
// local manifests, and a scan of a cluster is refused, as is an image scan,
// whose results this report does not carry.
//
// NoClusterAccess keeps a scan away from the cluster and Local skips the check
// for a newer version. Neither stops the released policies from being
// downloaded, which is a network request. A series of scans sets
// ReleasedPolicyStore to download them once. A caller that needs a scan with no
// network access must also point it at local policy sources (UseFrom, plus the
// exceptions and controls configuration it reads) that hold everything the scan
// needs.
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
	results, err := ks.scanLocal(ctx, scanInfo, policyIdentifiers)
	if err != nil {
		return nil, err
	}
	coverage := &results.GetData().ScanCoverage
	reportJSON, err := remediationverify.ReportJSON(results.GetResults(), coverage)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize the scan report: %w", err)
	}
	return &ScanReport{JSON: reportJSON, Degraded: coverage.Degraded}, nil
}

// scanLocal is the scan behind ScanToReport and LocalScanner: it refuses what
// cannot be returned as an in-memory result, scans a copy of scanInfo through
// ScanContext and returns the results, never nil, with no results handled.
func (ks *Kubescape) scanLocal(ctx context.Context, scanInfo *cautils.ScanInfo, policyIdentifiers []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	if scanInfo == nil {
		return nil, errors.New("scan info is required")
	}
	if err := refuseUnreportable(scanInfo); err != nil {
		return nil, err
	}

	scan := scanInfo.CloneForContext("", "")
	scan.Format = ""
	// Output filters, applied only when results are handled. The report holds
	// every finding the scan made, as with `--format json` of an unfiltered scan.
	scan.MinSeverity = ""
	scan.MaxSeverity = ""
	// Asked of the copy: working out the scanning context remembers it in the
	// ScanInfo, which for the caller's, shared by scans that run at once, would
	// be a write.
	if scan.GetScanningContext() == cautils.ContextCluster {
		return nil, unsupportedScan("only a scan of local inputs can be returned as an in-memory report")
	}

	results, err := ks.ScanContext(ctx, scan, policyIdentifiers)
	if err != nil {
		return nil, err
	}
	if results == nil || results.GetData() == nil {
		return nil, errors.New("the scan returned no results")
	}
	return results, nil
}

// refuseUnreportable refuses the settings that make a scan's result unfit to
// be returned in memory.
func refuseUnreportable(scanInfo *cautils.ScanInfo) error {
	if scanInfo.DryRun {
		return unsupportedScan("a dry run collects nothing, so there is no report to return")
	}
	if scanInfo.EncryptionEnabled {
		// The scan encrypts the sensitive fields of its results in place, so the
		// report would come back unreadable.
		return unsupportedScan("an encrypted scan cannot be returned as an in-memory report")
	}
	if scanInfo.ScanImages {
		// ScanContext records an image scan's failure for the results handler to
		// report and returns no error, and this report holds posture results only,
		// so a failed image scan would come back as a report that looks complete.
		return unsupportedScan("an image scan cannot be returned as an in-memory report")
	}
	return nil
}

// ErrUnsupportedScan is what a scan that cannot be returned in memory is
// refused with: a cluster scan, an image scan, a dry run or an encrypted scan.
var ErrUnsupportedScan = errors.New("unsupported scan")

type unsupportedScanError string

func unsupportedScan(reason string) error { return unsupportedScanError(reason) }

func (e unsupportedScanError) Error() string        { return string(e) }
func (e unsupportedScanError) Is(target error) bool { return target == ErrUnsupportedScan }
