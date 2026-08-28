package diff

import (
	"fmt"
	"slices"
	"strings"

	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/meta"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	resultsdiff "github.com/kubescape/kubescape/v4/core/pkg/resultshandling/diff"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/spf13/cobra"
)

var diffCmdExamples = fmt.Sprintf(`
  Diff command compares two Kubescape scan JSON reports and shows what changed.

  # Scan base branch, then the PR branch, then compare
  1) %[1]s scan --format json --output base.json .
  2) (make your changes)
  3) %[1]s scan --format json --output head.json .
  4) %[1]s diff base.json head.json

	# Fail CI when new high-severity or above failures are introduced
	%[1]s diff base.json head.json --fail-on-new --severity-threshold high

	# Compare resource-and-control aggregates while keeping safety checks
	%[1]s diff base.json head.json --granularity control

  # Output only new and incomparable regressions as SARIF for GitHub Code Scanning
  %[1]s diff base.json head.json --format sarif --output kubescape-diff

  # Output diff as JSON
  %[1]s diff base.json head.json --format json --output diff.json

  # Output aggregate diff counts for dashboards and CI annotations
  %[1]s diff base.json head.json --format summary-json --output diff-summary.json

  # Output aggregate diff counts as CSV for spreadsheet-friendly artifacts
  %[1]s diff base.json head.json --format summary-csv --output diff-summary.csv
`, cautils.ExecName())

func GetDiffCmd(ks meta.IKubescape) *cobra.Command {
	var diffInfo metav1.DiffInfo

	diffCmd := &cobra.Command{
		Use:     "diff <base-report.json> <head-report.json>",
		Short:   "Compare two Kubescape scan JSON reports and show what changed",
		Long:    `Compare a base scan report against a head scan report to surface new failures, resolved issues, unchanged evidence, and results that cannot be compared safely. By default, failed rules and paths are compared so regressions inside an already-failing control are detected.`,
		Example: diffCmdExamples,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			diffInfo.BaseFile = args[0]
			diffInfo.HeadFile = args[1]

			// diff honors a single output format, so validate against the exact value rather than scan's comma-separated multi-format set.
			supportedFormats := diffFormats()
			if !slices.Contains(supportedFormats, diffInfo.Format) {
				return fmt.Errorf("invalid format %q, supported formats: %s", diffInfo.Format, strings.Join(supportedFormats, ", "))
			}

			if diffInfo.SeverityThreshold != "" {
				if err := shared.ValidateSeverity(diffInfo.SeverityThreshold); err != nil {
					return err
				}
			}
			if err := resultsdiff.ValidateGranularity(diffInfo.Granularity); err != nil {
				return err
			}

			newFailures, err := ks.Diff(&diffInfo)
			if err != nil {
				return err
			}

			if diffInfo.FailOnNew && newFailures > 0 {
				return fmt.Errorf("found %d new or incomparable failure(s) at or above severity threshold %q",
					newFailures, severityLabel(diffInfo.SeverityThreshold))
			}

			return nil
		},
	}

	diffCmd.Flags().BoolVar(&diffInfo.FailOnNew, "fail-on-new", false, "Exit with code 1 when new or incomparable failures are found (combine with --severity-threshold to limit the gate)")
	diffCmd.Flags().StringVar(&diffInfo.SeverityThreshold, "severity-threshold", "", "Only count new and incomparable failures at or above this severity when using --fail-on-new (low, medium, high, critical)")
	diffCmd.Flags().StringVarP(&diffInfo.Format, "format", "f", "pretty-printer", fmt.Sprintf(`Output format: "%s"`, strings.Join(diffFormats(), `", "`)))
	diffCmd.Flags().StringVarP(&diffInfo.Output, "output", "o", "", "Output file; defaults to stdout")
	diffCmd.Flags().StringVar(&diffInfo.Granularity, "granularity", string(resultsdiff.GranularityEvidence), `Comparison unit: "evidence" or "control"`)

	return diffCmd
}

func severityLabel(s string) string {
	if s == "" {
		return "all"
	}
	return s
}

func diffFormats() []string {
	return []string{
		printer.PrettyFormat,
		resultsdiff.SummaryJSONFormat,
		resultsdiff.SummaryYAMLFormat,
		resultsdiff.SummaryCSVFormat,
		printer.JsonFormat,
		printer.YamlFormat,
		printer.SARIFFormat,
		printer.JunitResultFormat,
		printer.GitLabSASTFormat,
		printer.MarkdownFormat,
	}
}
