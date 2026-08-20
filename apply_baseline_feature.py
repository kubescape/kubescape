#!/usr/bin/env python3
"""
Patch script for kubescape feature: `scan --baseline` (issue #3352).
Matched to this repo's actual diff package API:
  - diff.Compute(basePath, headPath) (*ChangeSet, error)
  - diff.ChangeSet{New, Resolved, Unchanged []ControlChange}
  - diff.FilterBySeverity(changes, threshold) []ControlChange
  - JsonPrinter.SetWriter(ctx, path)      -- no error return
  - JsonPrinter.CloseWriter()             -- no error return
Run from repo root (where go.mod lives):
    python3 apply_baseline_feature.py
"""
import sys
from pathlib import Path

ROOT = Path(".").resolve()

def patch(path, old, new, desc):
    p = ROOT / path
    if not p.exists():
        sys.exit(f"[FAIL] {desc}: file not found: {p}")
    text = p.read_text(encoding="utf-8")
    count = text.count(old)
    if count == 0:
        sys.exit(f"[FAIL] {desc}: anchor text not found in {path}. Aborting.")
    if count > 1:
        sys.exit(f"[FAIL] {desc}: anchor text found {count} times in {path}, expected once. Aborting.")
    p.write_text(text.replace(old, new), encoding="utf-8")
    print(f"[OK]   {desc}")

def create(path, content, desc):
    p = ROOT / path
    if p.exists():
        sys.exit(f"[FAIL] {desc}: {path} already exists. Aborting (won't overwrite).")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    print(f"[OK]   {desc}")

# ----------------------------------------------------------------------
# 1. core/cautils/scaninfo.go — add Baseline* fields (no Granularity field,
#    your diff.Compute doesn't support it)
# ----------------------------------------------------------------------
patch(
    "core/cautils/scaninfo.go",
    old="""\tImageScanConcurrency  int               // Number of concurrent workers for image scanning
\tMinSeverity           string            // Only include controls at or above this severity in the output
}""",
    new="""\tImageScanConcurrency  int               // Number of concurrent workers for image scanning
\tMinSeverity           string            // Only include controls at or above this severity in the output
\tBaseline              string            // Path to a saved JSON scan report; when set, the fresh scan is diffed against it
\tBaselineFailOnNew     bool              // Exit with code 1 when the baseline diff finds new failures
\tBaselineSeverityThreshold string        // Only count new baseline failures at or above this severity when enforcing BaselineFailOnNew
}""",
    desc="scaninfo.go: add Baseline* fields to ScanInfo struct",
)

# ----------------------------------------------------------------------
# 2. core/core/baseline.go — new file, matches this repo's real diff API
# ----------------------------------------------------------------------
create(
    "core/core/baseline.go",
    '''package core

import (
\t"context"
\t"fmt"
\t"os"

\t"github.com/kubescape/kubescape/v3/core/cautils"
\t"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
\t"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/diff"
\tprinterv2 "github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2"
)

// EnforceBaseline compares the just-completed scan against scanInfo.Baseline
// (a saved JSON report) using the same diff engine as `kubescape diff`,
// prints the resulting change set, and returns the count of new failures at
// or above scanInfo.BaselineSeverityThreshold. It is a no-op when
// scanInfo.Baseline is empty.
func EnforceBaseline(ctx context.Context, results *resultshandling.ResultsHandler, scanInfo *cautils.ScanInfo) (newFailures int, err error) {
\tif scanInfo.Baseline == "" {
\t\treturn 0, nil
\t}
\tif results == nil || results.GetData() == nil {
\t\treturn 0, fmt.Errorf("baseline comparison requires scan results")
\t}

\theadFile, cleanup, err := writeBaselineHeadReport(ctx, results, scanInfo)
\tif err != nil {
\t\treturn 0, fmt.Errorf("preparing scan results for baseline comparison: %w", err)
\t}
\tdefer cleanup()

\tcs, err := diff.Compute(scanInfo.Baseline, headFile)
\tif err != nil {
\t\treturn 0, fmt.Errorf("comparing against baseline %q: %w", scanInfo.Baseline, err)
\t}

\tprintBaselineChangeSet(cs)

\treturn len(diff.FilterBySeverity(cs.New, scanInfo.BaselineSeverityThreshold)), nil
}

// printBaselineChangeSet prints a plain summary of the baseline diff. This
// repo's diff package has no exported pretty-printer, so we render one here
// rather than depending on an internal/undefined function.
func printBaselineChangeSet(cs *diff.ChangeSet) {
\tfmt.Printf("\\nBaseline drift summary: %d new, %d resolved, %d unchanged\\n", len(cs.New), len(cs.Resolved), len(cs.Unchanged))
\tif len(cs.New) > 0 {
\t\tfmt.Println("\\nNew failures:")
\t\tfor _, c := range cs.New {
\t\t\tfmt.Printf("  [%s] %s / %s (%s)\\n", c.Severity, c.ResourceID, c.ControlID, c.ControlName)
\t\t}
\t}
\tif len(cs.Resolved) > 0 {
\t\tfmt.Println("\\nResolved failures:")
\t\tfor _, c := range cs.Resolved {
\t\t\tfmt.Printf("  [%s] %s / %s (%s)\\n", c.Severity, c.ResourceID, c.ControlID, c.ControlName)
\t\t}
\t}
}

// writeBaselineHeadReport renders the fresh scan results to a private temp
// JSON file in the same schema --format json produces, so diff.Compute (which
// only reads from disk) can compare it against the baseline with no format
// conversion. The caller must invoke the returned cleanup.
func writeBaselineHeadReport(ctx context.Context, results *resultshandling.ResultsHandler, scanInfo *cautils.ScanInfo) (path string, cleanup func(), err error) {
\ttmp, err := os.CreateTemp("", "kubescape-baseline-head-*.json")
\tif err != nil {
\t\treturn "", func() {}, err
\t}
\ttmpPath := tmp.Name()
\tif err := tmp.Close(); err != nil {
\t\tos.Remove(tmpPath) // #nosec G104 -- best-effort cleanup on setup failure
\t\treturn "", func() {}, err
\t}
\tcleanup = func() { _ = os.Remove(tmpPath) }

\tjsonPrinter := printerv2.NewJsonPrinter(scanInfo.MinSeverity)
\tjsonPrinter.SetWriter(ctx, tmpPath)
\tif err := jsonPrinter.ActionPrint(ctx, results.GetData(), results.ImageScanData); err != nil {
\t\tcleanup()
\t\treturn "", func() {}, err
\t}
\tjsonPrinter.CloseWriter()

\treturn tmpPath, cleanup, nil
}
''',
    desc="core/core/baseline.go: create EnforceBaseline helper (matches repo's real diff API)",
)

# ----------------------------------------------------------------------
# 3. cmd/scan/scan.go — imports
# ----------------------------------------------------------------------
patch(
    "cmd/scan/scan.go",
    old="""\t\"github.com/kubescape/kubescape/v3/core/cautils/getter\"
\t\"github.com/kubescape/kubescape/v3/core/meta\"""",
    new="""\t\"github.com/kubescape/kubescape/v3/core/cautils/getter\"
\t\"github.com/kubescape/kubescape/v3/core/core\"
\t\"github.com/kubescape/kubescape/v3/core/meta\"""",
    desc="scan.go: add core import",
)

patch(
    "cmd/scan/scan.go",
    old="""\t\"github.com/kubescape/kubescape/v3/pkg/imagescan\"""",
    new="""\t\"github.com/kubescape/kubescape/v3/core/pkg/resultshandling\"
\t\"github.com/kubescape/kubescape/v3/pkg/imagescan\"""",
    desc="scan.go: add resultshandling import",
)

# ----------------------------------------------------------------------
# 4. cmd/scan/scan.go — register flags (append at end of GetScanCommand,
#    right before it returns scanCmd)
# ----------------------------------------------------------------------
patch(
    "cmd/scan/scan.go",
    old="""\tscanCmd.AddCommand(getControlCmd(ks, &scanInfo))""",
    new="""\tscanCmd.PersistentFlags().StringVar(&scanInfo.Baseline, "baseline", "", "Path to a saved JSON scan report to diff the fresh scan against. Detects drift in one command instead of saving two reports and running 'diff' separately.")
\tscanCmd.PersistentFlags().BoolVar(&scanInfo.BaselineFailOnNew, "baseline-fail-on-new", false, "With --baseline, exit with code 1 when new failures are found versus the baseline (combine with --baseline-severity-threshold to limit the gate)")
\tscanCmd.PersistentFlags().StringVar(&scanInfo.BaselineSeverityThreshold, "baseline-severity-threshold", "", "With --baseline, only count new failures at or above this severity when using --baseline-fail-on-new (low, medium, high, critical)")

\tscanCmd.AddCommand(getControlCmd(ks, &scanInfo))""",
    desc="scan.go: register --baseline* persistent flags",
)

# ----------------------------------------------------------------------
# 5. cmd/scan/scan.go — wire into securityScan()
# ----------------------------------------------------------------------
patch(
    "cmd/scan/scan.go",
    old="""\tif err := enforcePolicyDegradation(results.GetData().ScanCoverage, &scanInfo); err != nil {
\t\treturn err
\t}

\treturn nil
}

func enforceImageSeverityThresholds""",
    new="""\tif err := enforcePolicyDegradation(results.GetData().ScanCoverage, &scanInfo); err != nil {
\t\treturn err
\t}

\treturn enforceBaselineDrift(ks.Context(), results, &scanInfo)
}

// enforceBaselineDrift is a no-op unless --baseline is set. It diffs the
// completed scan against the baseline report using the same engine as
// `kubescape diff` and turns a positive new-failure count into an error when
// --baseline-fail-on-new is set.
func enforceBaselineDrift(ctx context.Context, results *resultshandling.ResultsHandler, scanInfo *cautils.ScanInfo) error {
\tnewFailures, err := core.EnforceBaseline(ctx, results, scanInfo)
\tif err != nil {
\t\treturn err
\t}
\tif scanInfo.BaselineFailOnNew && newFailures > 0 {
\t\treturn fmt.Errorf("baseline drift: found %d new failure(s) at or above baseline severity threshold %q",
\t\t\tnewFailures, severityLabelOrAll(scanInfo.BaselineSeverityThreshold))
\t}
\treturn nil
}

func severityLabelOrAll(s string) string {
\tif s == "" {
\t\treturn "all"
\t}
\treturn s
}

func enforceImageSeverityThresholds""",
    desc="scan.go: wire enforceBaselineDrift() into securityScan()",
)

# ----------------------------------------------------------------------
# 6. cmd/scan/framework.go — wire into RunE
# ----------------------------------------------------------------------
patch(
    "cmd/scan/framework.go",
    old="""\t\t\tif err := enforcePolicyDegradation(results.GetData().ScanCoverage, scanInfo); err != nil {
\t\t\t\treturn err
\t\t\t}
\t\t\treturn nil
\t\t},
\t}

}""",
    new="""\t\t\tif err := enforcePolicyDegradation(results.GetData().ScanCoverage, scanInfo); err != nil {
\t\t\t\treturn err
\t\t\t}
\t\t\treturn enforceBaselineDrift(ks.Context(), results, scanInfo)
\t\t},
\t}

}""",
    desc="framework.go: wire enforceBaselineDrift() into `scan framework` RunE",
)

# ----------------------------------------------------------------------
# 7. cmd/scan/control.go — wire into RunE
# ----------------------------------------------------------------------
patch(
    "cmd/scan/control.go",
    old="""\t\t\tif err := enforcePolicyDegradation(results.GetData().ScanCoverage, scanInfo); err != nil {
\t\t\t\treturn err
\t\t\t}

\t\t\treturn nil
\t\t},
\t}""",
    new="""\t\t\tif err := enforcePolicyDegradation(results.GetData().ScanCoverage, scanInfo); err != nil {
\t\t\t\treturn err
\t\t\t}

\t\t\treturn enforceBaselineDrift(ks.Context(), results, scanInfo)
\t\t},
\t}""",
    desc="control.go: wire enforceBaselineDrift() into `scan control` RunE",
)

# ----------------------------------------------------------------------
# 8. cmd/scan/workload.go — wire into RunE
# ----------------------------------------------------------------------
patch(
    "cmd/scan/workload.go",
    old="""\t\t\tif err := enforcePolicyDegradation(results.GetData().ScanCoverage, scanInfo); err != nil {
\t\t\t\treturn err
\t\t\t}

\t\t\treturn nil
\t\t},""",
    new="""\t\t\tif err := enforcePolicyDegradation(results.GetData().ScanCoverage, scanInfo); err != nil {
\t\t\t\treturn err
\t\t\t}

\t\t\treturn enforceBaselineDrift(ks.Context(), results, scanInfo)
\t\t},""",
    desc="workload.go: wire enforceBaselineDrift() into `scan workload` RunE",
)

print("\\nAll patches applied successfully.")
print("Next: gofmt -w core/core/baseline.go core/cautils/scaninfo.go cmd/scan/scan.go cmd/scan/framework.go cmd/scan/control.go cmd/scan/workload.go && go build ./...")
