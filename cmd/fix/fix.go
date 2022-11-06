package fix

import (
	"github.com/kubescape/kubescape/v2/core/meta"
	"github.com/spf13/cobra"
)

var fixCmdExamples = `
  Fix command is for fixing kubernetes manifest files based on a scan command output.
  Use with caution, this command will change your files.

  # Fix kubernetes YAML manifest files based on a scan command output (output.json)
  1) kubescape scan --format json --format-version v2 --output output.json
  2) kubescape fix output.json

`

func GetFixCmd(ks meta.IKubescape) *cobra.Command {
	fixCmd := &cobra.Command{
		Use:     "fix",
		Short:   "Fix misconfiguration in files",
		Long:    ``,
		Example: fixCmdExamples,
		RunE: func(cmd *cobra.Command, args []string) error {
			reportPath := args[0]
			return ks.Fix(reportPath)
		},
	}
	// TODO: Should we add a confirmation for the user? listing the files that will be changed.

	return fixCmd
}
