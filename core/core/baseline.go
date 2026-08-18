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
// the resulting change set, and returns the count of new failures at or
// above scanInfo.BaselineSeverityThreshold. It is a no-op when
// scanInfo.Baseline is empty.
func EnforceBaseline(ctx context.Context, results *resultshandling.ResultsHandler, scanInfo *cautils.ScanInfo) (newFailures int, err error) {
	if scanInfo.Baseline == "" {
		return 0, nil
	}
	if results == nil || results.GetData() == nil {
		return 0, fmt.Errorf("baseline comparison requires scan results")
	}

	headFile, cleanup, err := writeBaselineHeadReport(ctx, results, scanInfo)
	if err != nil {
		return 0, fmt.Errorf("preparing scan results for baseline comparison: %w", err)
	}
	defer cleanup()

	cs, err := diff.Compute(scanInfo.Baseline, headFile)
	if err != nil {
		return 0, fmt.Errorf("comparing against baseline %q: %w", scanInfo.Baseline, err)
	}

	printBaselineChangeSet(cs)

	return len(diff.FilterBySeverity(cs.New, scanInfo.BaselineSeverityThreshold)), nil
}

// printBaselineChangeSet prints a plain summary of the baseline diff.
func printBaselineChangeSet(cs *diff.ChangeSet) {
	fmt.Printf("\nBaseline drift summary: %d new, %d resolved, %d unchanged\n", len(cs.New), len(cs.Resolved), len(cs.Unchanged))
	if len(cs.New) > 0 {
		fmt.Println("\nNew failures:")
		for _, c := range cs.New {
			fmt.Printf("  [%s] %s / %s (%s)\n", c.Severity, c.ResourceID, c.ControlID, c.ControlName)
		}
	}
	if len(cs.Resolved) > 0 {
		fmt.Println("\nResolved failures:")
		for _, c := range cs.Resolved {
			fmt.Printf("  [%s] %s / %s (%s)\n", c.Severity, c.ResourceID, c.ControlID, c.ControlName)
		}
	}
}

// writeBaselineHeadReport renders the fresh scan results to a private temp
// JSON file so diff.Compute (disk-only) can compare it against the baseline.
func writeBaselineHeadReport(ctx context.Context, results *resultshandling.ResultsHandler, scanInfo *cautils.ScanInfo) (path string, cleanup func(), err error) {
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

	jsonPrinter := printerv2.NewJsonPrinter(scanInfo.MinSeverity)
	jsonPrinter.SetWriter(ctx, tmpPath)
	if err := jsonPrinter.ActionPrint(ctx, results.GetData(), results.ImageScanData); err != nil {
		cleanup()
		return "", func() {}, err
	}
	jsonPrinter.CloseWriter()

	return tmpPath, cleanup, nil
}
