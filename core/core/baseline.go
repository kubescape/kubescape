package core

import (
	"context"
	"fmt"
	"os"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/diff"
	printerv2 "github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2"
)

// EnforceBaseline compares the just-completed scan against scanInfo.Baseline
// (a saved JSON report) using the same diff engine as kubescape diff, prints
// the resulting change set, and returns the count of new and incomparable
// failures at or above scanInfo.BaselineSeverityThreshold. Incomparable
// failures are counted alongside new ones because the diff engine cannot
// safely classify them as resolved or unchanged, so treating them as passing
// would risk a false-green result. It is a no-op when scanInfo.Baseline is
// empty.
func EnforceBaseline(ctx context.Context, results *resultshandling.ResultsHandler, scanInfo *cautils.ScanInfo) (newFailures int, err error) {
	if scanInfo.Baseline == "" {
		return 0, nil
	}

	granularity := diff.GranularityEvidence
	if scanInfo.BaselineGranularity != "" {
		granularity = diff.Granularity(scanInfo.BaselineGranularity)
	}

	if results == nil || results.GetData() == nil {
		return 0, fmt.Errorf("baseline comparison requires scan results")
	}

	headFile, cleanup, err := writeBaselineHeadReport(ctx, results)
	if err != nil {
		return 0, fmt.Errorf("preparing scan results for baseline comparison: %w", err)
	}
	defer cleanup()

	cs, err := diff.ComputeWithOptions(scanInfo.Baseline, headFile, diff.Options{Granularity: granularity})
	if err != nil {
		return 0, fmt.Errorf("comparing against baseline %q: %w", scanInfo.Baseline, err)
	}

	printBaselineChangeSet(cs, scanInfo.Hide)

	failing := append([]diff.ControlChange{}, cs.New...)
	failing = append(failing, cs.Incomparable...)

	return len(diff.FilterBySeverity(failing, scanInfo.BaselineSeverityThreshold)), nil
}

// printBaselineChangeSet prints a plain summary of the baseline diff to
// stderr, so it never interleaves with --format json/junit output written to
// stdout.
func printBaselineChangeSet(cs *diff.ChangeSet, hide bool) {
	fmt.Fprintf(os.Stderr, "\nBaseline drift summary: %d new, %d resolved, %d unchanged, %d incomparable\n",
		len(cs.New), len(cs.Resolved), len(cs.Unchanged), len(cs.Incomparable))
	if len(cs.New) > 0 {
		fmt.Fprintln(os.Stderr, "\nNew failures:")
		for _, c := range cs.New {
			fmt.Fprintf(os.Stderr, "  [%s] %s / %s (%s)\n", c.Severity, redactIfHidden(c.ResourceID, hide), c.ControlID, c.ControlName)
		}
	}
	if len(cs.Incomparable) > 0 {
		fmt.Fprintln(os.Stderr, "\nIncomparable (scan scope or coverage changed, treated as failing):")
		for _, c := range cs.Incomparable {
			fmt.Fprintf(os.Stderr, "  [%s] %s / %s (%s)\n", c.Severity, redactIfHidden(c.ResourceID, hide), c.ControlID, c.ControlName)
		}
	}
	if len(cs.Resolved) > 0 {
		fmt.Fprintln(os.Stderr, "\nResolved failures:")
		for _, c := range cs.Resolved {
			fmt.Fprintf(os.Stderr, "  [%s] %s / %s (%s)\n", c.Severity, redactIfHidden(c.ResourceID, hide), c.ControlID, c.ControlName)
		}
	}
}

// redactIfHidden mirrors the --hide flag's intent for the drift summary: it
// masks the resource identifier so a scan run with --hide does not leak it
// through this separate stderr report.
func redactIfHidden(resourceID string, hide bool) string {
	if hide {
		return "[hidden]"
	}
	return resourceID
}

// writeBaselineHeadReport renders the fresh scan results to a private,
// unfiltered temp JSON file so diff.ComputeWithOptions (disk-only) can
// compare it against the baseline. The report is intentionally rendered
// without --min-severity filtering: filtering it would make findings below
// the display threshold vanish from the head report, causing the diff
// engine to misreport still-failing baseline findings as resolved.
func writeBaselineHeadReport(ctx context.Context, results *resultshandling.ResultsHandler) (path string, cleanup func(), err error) {
	tmp, err := os.CreateTemp("", "kubescape-baseline-head-*.json")
	if err != nil {
		return "", func() {}, err
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return "", func() {}, err
	}
	cleanup = func() { _ = os.Remove(tmpPath) }

	jsonPrinter := printerv2.NewJsonPrinter("")
	jsonPrinter.SetWriter(ctx, tmpPath)
	if err := jsonPrinter.ActionPrint(ctx, results.GetData(), results.ImageScanData); err != nil {
		jsonPrinter.CloseWriter()
		cleanup()
		return "", func() {}, err
	}
	jsonPrinter.CloseWriter()

	return tmpPath, cleanup, nil
}
