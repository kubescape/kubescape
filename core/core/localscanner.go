package core

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/pkg/remediationverify"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

// LocalScanner scans local manifests again and again with one configuration, for
// a caller that keeps a series of scans: a watch, an editor integration, a
// verification. It owns what the series shares: the scan settings, the policies
// to scan with, and the store the released policies are downloaded into, once
// for the series instead of once per scan.
//
// Every scan is a scan through ScanContext, the one `kubescape scan` runs, of a
// copy of the settings. Nothing is printed, written or submitted, no cluster is
// reached, and no scan changes the settings, so Scan is safe to call from
// several goroutines. How many scans run at once, when a scan is due and what is
// done with its result are the caller's.
type LocalScanner struct {
	ks   *Kubescape
	base *cautils.ScanInfo
	ids  []cautils.PolicyIdentifier
}

// LocalInput says what to scan.
type LocalInput struct {
	// Paths are the files and directories to scan. When none are given the scan
	// uses the input patterns of the settings the scanner was made with.
	Paths []string
}

// NewLocalScanner makes a scanner from a copy of base, so the caller's ScanInfo
// is not kept or changed. The copy scans without a cluster and without the
// version check, and without output: base's Local and NoClusterAccess settings
// are overridden, and its output settings are not used. A scan that cannot be
// returned in memory (see ErrUnsupportedScan) is refused here.
func (ks *Kubescape) NewLocalScanner(base *cautils.ScanInfo, ids []cautils.PolicyIdentifier) (*LocalScanner, error) {
	if base == nil {
		return nil, errors.New("scan info is required")
	}
	if err := refuseUnreportable(base); err != nil {
		return nil, err
	}
	own := base.CloneForContext("", "")
	own.Format = ""
	own.MinSeverity = ""
	own.MaxSeverity = ""
	own.Local = true
	own.NoClusterAccess = true
	if own.ReleasedPolicyStore == nil {
		own.ReleasedPolicyStore = getter.NewDownloadReleasedPolicyWithVersion(own.ControlsVersion)
	}
	return &LocalScanner{ks: ks, base: own, ids: slices.Clone(ids)}, nil
}

// Scan scans the input and returns the result. An error, including a partial
// failure to process the rules and the end of ctx, is returned as an error and
// not as a result, and what it wraps, a context's error for one, can be found in
// it. A scan of something that is not local input is refused with
// ErrUnsupportedScan.
func (s *LocalScanner) Scan(ctx context.Context, in LocalInput) (*ScanResult, error) {
	paths := in.Paths
	if len(paths) == 0 {
		paths = s.base.InputPatterns
	}
	if len(paths) == 0 {
		return nil, errors.New("nothing to scan: no path was given")
	}
	scan := s.base.CloneForContext("", "")
	scan.InputPatterns = slices.Clone(paths)
	if len(in.Paths) > 0 {
		// The context worked out for the base, which may have had other inputs or
		// none, was copied with it. These paths are what is scanned, so it is
		// worked out again for the copy; the base keeps its own.
		scan.ResetScanningContext()
	}

	results, err := s.ks.scanLocal(ctx, scan, s.ids)
	if err != nil {
		return nil, err
	}
	data := results.GetData()
	return &ScanResult{
		Session:  data,
		Coverage: data.ScanCoverage,
		Degraded: data.ScanCoverage.Degraded,
		finalize: results.GetResults,
	}, nil
}

// ScanResult is the result of one scan.
type ScanResult struct {
	// Session holds what the scan read and found. It is shared with JSON, so a
	// caller treats it as read-only.
	Session *cautils.OPASessionObj
	// Coverage is what the scan could and could not evaluate.
	Coverage cautils.ScanCoverage
	// Degraded is set when the scan could not evaluate everything it was asked to.
	Degraded bool

	finalize func() *reporthandlingv2.PostureReport
	once     sync.Once
	json     []byte
	jsonErr  error
}

// JSON is the report in the form ScanToReport returns. It is made once and the
// same bytes are returned after that.
func (r *ScanResult) JSON() ([]byte, error) {
	r.once.Do(func() {
		report := r.finalize()
		r.json, r.jsonErr = remediationverify.ReportJSON(report, &r.Coverage)
		if r.jsonErr != nil {
			r.jsonErr = fmt.Errorf("failed to serialize the scan report: %w", r.jsonErr)
		}
	})
	return r.json, r.jsonErr
}
