package core

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/pkg/fixhandler"
	"github.com/kubescape/kubescape/v4/core/pkg/remediationverify"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
)

const (
	noFixesToVerify = "Verification skipped: no fix was applied, so there is nothing to verify."

	// verifyConfigNote is printed with every verification. The report keeps only
	// the controls configuration of the scan that made it, so a rescan cannot
	// promise to run under the settings that scan had.
	verifyConfigNote = "Verification rescans with the controls configuration named above and the defaults for the settings the report does not record (exceptions, controls version, policy sources). A verdict holds for that configuration; if the original scan used others, scan again with them."
)

// verifyRescan is what one verification rescan has to cover.
type verifyRescan struct {
	// Roots are the directories the original scan read the manifests through.
	Roots []string
	// ControlIDs are the controls of the fixes being verified.
	ControlIDs []string
	// ControlsInputs is the controls configuration file to scan with, or "".
	ControlsInputs string
}

// verifyRescanResult is a rescan's report in the form `scan --format json`
// writes, with the scan's own degraded signal.
type verifyRescanResult struct {
	ReportJSON []byte
	Degraded   bool
}

// verifyRescanFn runs the rescan. It is a variable so tests can supply a canned
// report instead of running a scan.
var verifyRescanFn = func(ks *Kubescape, ctx context.Context, req verifyRescan) (verifyRescanResult, error) {
	return ks.rescanForVerification(ctx, req)
}

// verifyScanInfoHook lets a test adjust the rescan's ScanInfo, to point it at
// local policy files. It is nil outside tests.
var verifyScanInfoHook func(*cautils.ScanInfo)

// rescanForVerification scans the roots again for the given controls, through
// the same ScanContext `kubescape scan` uses, and returns the report in memory.
// No results are handled, so nothing is printed, written or submitted, and
// nothing is read back from a file. Any error, including a partial failure to
// process the rules, is returned as an error: verdicts are only drawn from a
// scan that completed.
func (ks *Kubescape) rescanForVerification(ctx context.Context, req verifyRescan) (verifyRescanResult, error) {
	scanInfo := &cautils.ScanInfo{
		InputPatterns:  req.Roots,
		ControlsInputs: req.ControlsInputs,
		Local:          true, // nothing of a verification is reported anywhere
		// Rescanning manifests has no use for a cluster. A local scan reaches for
		// one whenever the kubeconfig loads, to resolve its tenant configuration
		// and to record ExceptionMatched events, which starts with API discovery
		// that has no deadline, so a kubeconfig whose server is down stalls it for
		// minutes. This is a property of this scan and not of the process, so
		// another scan running at the same time is not affected.
		NoClusterAccess: true,
	}
	scanInfo.SetScanType(cautils.ScanTypeControl)
	if verifyScanInfoHook != nil {
		verifyScanInfoHook(scanInfo)
	}

	report, err := ks.ScanToReport(ctx, scanInfo, cautils.BuildPolicyIdentifiers(req.ControlIDs, apisv1.KindControl))
	if err != nil {
		return verifyRescanResult{}, err
	}
	return verifyRescanResult{ReportJSON: report.JSON, Degraded: report.Degraded}, nil
}

// verificationItems are the findings the fixer remediated, each once, and how
// to name them. Only a control the fixer counted as fixed is verified: a partial
// or manual control is known to need work and stays in the unfixed listing, and
// a control of a declined resource was not fixed at all.
func verificationItems(outcomes []fixhandler.ControlOutcome) (items []remediationverify.Item, labels map[remediationverify.Item]string) {
	labels = make(map[remediationverify.Item]string)
	for _, o := range outcomes {
		if !o.Fixed || o.InMemory {
			continue
		}
		item := remediationverify.Item{ResourceID: o.ResourceID, ControlID: o.ControlID}
		if _, seen := labels[item]; seen {
			continue
		}
		labels[item] = resourceLabel(o)
		items = append(items, item)
	}
	return items, labels
}

func resourceLabel(o fixhandler.ControlOutcome) string {
	switch {
	case o.ResourceKind != "" && o.ResourceName != "":
		return o.ResourceKind + "/" + o.ResourceName
	case o.ResourceName != "":
		return o.ResourceName
	default:
		return o.ResourceID
	}
}

// verificationConfig decides which controls configuration the rescan runs
// under, and says in a sentence what that is. The configuration decides what a
// control demands, so a rescan under another is not a check of the fix: a
// default that is more lenient than the original would call a finding resolved
// that the original configuration still fails. It is therefore never
// substituted. The file given with --controls-config is used, otherwise the one
// the report records, and when that cannot be used this is an error, not a
// fallback to the default.
func verificationConfig(recorded, override string) (path, used string, err error) {
	switch {
	case override != "":
		if err := loadableControlsConfig(override); err != nil {
			return "", "", fmt.Errorf("cannot verify: the --controls-config file %q cannot be used: %w", override, err)
		}
		if recorded != "" && recorded != override {
			return override, fmt.Sprintf("the controls configuration given with --controls-config (%q) in place of the one the report records (%q)", override, recorded), nil
		}
		return override, fmt.Sprintf("the controls configuration given with --controls-config (%q)", override), nil
	case recorded != "":
		if err := loadableControlsConfig(recorded); err != nil {
			return "", "", fmt.Errorf("cannot verify: the controls configuration the report records (%q) cannot be used (%w), and a rescan under another could judge a control differently. Pass the file with --controls-config, or run without --verify", recorded, err)
		}
		return recorded, fmt.Sprintf("the controls configuration the report records (%q)", recorded), nil
	}
	return "", "the default controls configuration, since the report records none", nil
}

// loadableControlsConfig is nil when the rescan can use path as its controls
// configuration. The file is read and decoded the way the scan loads it, not
// only looked up: one that is there but cannot be opened, is not a JSON object
// of control inputs or holds none would make the rescan fall back to the
// default configuration and report itself degraded, leaving every fix
// unverified after the manifests were changed.
func loadableControlsConfig(path string) error {
	inputs, err := getter.ReadControlsInputsFile(path)
	if err != nil {
		return err
	}
	if len(inputs) == 0 {
		return errors.New("it holds no control inputs")
	}
	return nil
}

// versionDrift says so when the report was made by another Kubescape version
// than this one, whose policies may judge a control differently, or returns "".
func versionDrift(recorded string) string {
	current := versioncheck.BuildNumber
	if recorded == "" || current == "" || recorded == current {
		return ""
	}
	return fmt.Sprintf("The report was made by Kubescape %s and this is %s: the policies can differ between releases, so the rescan may judge a control differently than the original scan did.", recorded, current)
}

// verifyFixes rescans the roots the fixes were applied under and reports whether
// each fixed finding is gone. It returns an error unless every one is resolved,
// so that a run that could not confirm its fixes does not read as a success.
func (ks *Kubescape) verifyFixes(handler *fixhandler.FixHandler, fixInfo *metav1.FixInfo) error {
	items, labels := verificationItems(handler.ControlOutcomes())
	if len(items) == 0 {
		logger.L().Info(noFixesToVerify)
		return nil
	}
	roots := handler.ScanRoots()
	if len(roots) == 0 {
		return errors.New("cannot verify: the report does not say which directories were scanned")
	}
	controlsInputs, used, err := verificationConfig(handler.RecordedControlsInputs(), fixInfo.ControlsConfig)
	if err != nil {
		return err
	}

	logger.L().Info(fmt.Sprintf("Verifying %d fixed control instance(s) by rescanning %s with %s...", len(items), strings.Join(roots, ", "), used))
	rescan, err := verifyRescanFn(ks, ks.Context(), verifyRescan{
		Roots:          roots,
		ControlIDs:     remediationverify.ControlIDs(items),
		ControlsInputs: controlsInputs,
	})
	if err != nil {
		return fmt.Errorf("verification failed: the rescan did not complete: %w", err)
	}
	resp, err := remediationverify.ClassifyReportJSON(rescan.ReportJSON, rescan.Degraded, items)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	printVerification(resp, items, labels)
	if drift := versionDrift(handler.RecordedKubescapeVersion()); drift != "" {
		logger.L().Warning(drift)
	}
	logger.L().Info(verifyConfigNote)

	unresolved := resp.Summary.StillFailing + resp.Summary.Unverified
	if unresolved > 0 {
		return fmt.Errorf("verification did not confirm every fix: %d still failing, %d unverified", resp.Summary.StillFailing, resp.Summary.Unverified)
	}
	return nil
}

// printVerification prints the counts and then, for each fixed finding, its
// verdict and why, so a resolved finding is named as well as one that is not.
// Only a finding that is not resolved is a warning.
func printVerification(resp remediationverify.Response, items []remediationverify.Item, labels map[remediationverify.Item]string) {
	logger.L().Info(fmt.Sprintf("Verification: %d resolved, %d still failing, %d unverified",
		resp.Summary.Resolved, resp.Summary.StillFailing, resp.Summary.Unverified))
	if resp.Degraded && resp.Summary.Resolved == 0 {
		logger.L().Warning("The rescan did not fully complete or reports no coverage information, so no fix can be confirmed.")
	}
	for _, result := range resp.Results {
		label := labels[items[result.Index]]
		line := fmt.Sprintf("  %s: %s %s (%s): %s", label, result.ControlID, result.Verdict, result.Reason, remediationverify.Explanation(result.Reason))
		if result.Verdict == remediationverify.VerdictResolved {
			logger.L().Info(line)
		} else {
			logger.L().Warning(line)
		}
	}
}
