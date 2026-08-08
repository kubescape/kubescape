package fix

import (
	"errors"
	"fmt"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/meta"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

var fixCmdExamples = fmt.Sprintf(`
  Fix command is for fixing kubernetes manifest files based on a scan command output.
  Use with caution, this command will change your files in-place.

  # Fix kubernetes YAML manifest files based on a scan command output (output.json)
  1) %[1]s scan . --format json --output output.json
  2) %[1]s fix output.json

  The report file's own recorded scan location is trusted by default. If the
  report comes from a source you don't fully trust (e.g. a shared CI
  artifact), pass --base-path to require that location to resolve inside a
  directory you control:
  3) %[1]s fix output.json --base-path .

`, cautils.ExecName())

func GetFixCmd(ks meta.IKubescape) *cobra.Command {
	var fixInfo metav1.FixInfo

	fixCmd := &cobra.Command{
		Use:     "fix <report output file>",
		Short:   "Propose a fix for the misconfiguration found when scanning Kubernetes manifest files",
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
	fixCmd.PersistentFlags().StringVar(&fixInfo.BasePath, "base-path", "", "Restrict fixes to this directory: the report's own recorded scan location must resolve inside it. Use this when the report file comes from a source you don't fully trust (e.g. a shared CI artifact); without it, the report's recorded location is trusted as-is")

	return fixCmd
}
