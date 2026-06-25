package diff

import (
	"fmt"
	"slices"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/cmd/shared"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/meta"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
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

  # Output diff as JSON
  %[1]s diff base.json head.json --format json --output diff.json
`, cautils.ExecName())

func GetDiffCmd(ks meta.IKubescape) *cobra.Command {
	var diffInfo metav1.DiffInfo

	diffCmd := &cobra.Command{
		Use:     "diff <base-report.json> <head-report.json>",
		Short:   "Compare two Kubescape scan JSON reports and show what changed",
		Long:    `Compare a base scan report against a head scan report to surface new failures, resolved issues, and controls that are still failing.`,
		Example: diffCmdExamples,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			diffInfo.BaseFile = args[0]
			diffInfo.HeadFile = args[1]

			// diff honors a single output format, so validate against the exact value rather than scan's comma-separated multi-format set.
			supportedFormats := []string{printer.PrettyFormat, printer.JsonFormat}
			if !slices.Contains(supportedFormats, diffInfo.Format) {
				return fmt.Errorf("invalid format %q, supported formats: %s", diffInfo.Format, strings.Join(supportedFormats, ", "))
			}

			if diffInfo.SeverityThreshold != "" {
				if err := shared.ValidateSeverity(diffInfo.SeverityThreshold); err != nil {
					return err
				}
			}

			newFailures, err := ks.Diff(&diffInfo)
			if err != nil {
				return err
			}

			if diffInfo.FailOnNew && newFailures > 0 {
				logger.L().Fatal(fmt.Sprintf("found %d new failure(s) at or above severity threshold %q",
					newFailures, severityLabel(diffInfo.SeverityThreshold)))
			}

			return nil
		},
	}

	diffCmd.Flags().BoolVar(&diffInfo.FailOnNew, "fail-on-new", false, "Exit with code 1 when new failures are found (combine with --severity-threshold to limit the gate)")
	diffCmd.Flags().StringVar(&diffInfo.SeverityThreshold, "severity-threshold", "", "Only count failures at or above this severity when using --fail-on-new (low, medium, high, critical)")
	diffCmd.Flags().StringVarP(&diffInfo.Format, "format", "f", "pretty-printer", `Output format: "pretty-printer" or "json"`)
	diffCmd.Flags().StringVarP(&diffInfo.Output, "output", "o", "", "Output file; defaults to stdout")

	return diffCmd
}

func severityLabel(s string) string {
	if s == "" {
		return "all"
	}
	return s
}
