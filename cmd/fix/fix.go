package fix

import (
	"errors"

	"github.com/kubescape/kubescape/v2/core/meta"
	metav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"

	"github.com/spf13/cobra"
)

var fixCmdExamples = `
  Fix command is for fixing kubernetes manifest files based on a scan command output.
  Use with caution, this command will change your files in-place.

  # Fix kubernetes YAML manifest files based on a scan command output (output.json)
  1) kubescape scan --format json --format-version v2 --output output.json
  2) kubescape fix output.json

`

func GetFixCmd(ks meta.IKubescape) *cobra.Command {
	var fixInfo metav1.FixInfo

	fixCmd := &cobra.Command{
		Use:     "fix <report output file>",
		Short:   "Fix misconfiguration in files",
		Long:    ``,
		Example: fixCmdExamples,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("report output file is required")
			}
			fixInfo.ReportFile = args[0]

			return ks.Fix(&fixInfo)
		},
	}

	fixCmd.PersistentFlags().BoolVar(&fixInfo.NoConfirm, "no-confirm", false, "No confirmation will be given to the user before applying the fix (default false)")
	fixCmd.PersistentFlags().BoolVar(&fixInfo.DryRun, "dry-run", false, "No changes will be applied (default false)")
	fixCmd.PersistentFlags().BoolVar(&fixInfo.SkipUserValues, "skip-user-values", true, "Changes which involve user-defined values will be skipped")

	return fixCmd
}
