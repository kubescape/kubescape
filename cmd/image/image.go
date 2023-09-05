package image

import (
	"fmt"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/meta"
	"github.com/spf13/cobra"
)

type imageCredentials struct {
	Username string
	Password string
}

var imageCmdExamples = fmt.Sprintf(`
# Scan an image
%[1]s image scan <image>:<tag>

# Patch an image
%[1]s image patch  <image>:<tag>
`, cautils.ExecName())

func GetImageCmd(ks meta.IKubescape) *cobra.Command {
	var scanInfo cautils.ScanInfo
	var imgCredentials imageCredentials

	imageCmd := &cobra.Command{
		Use:     "image",
		Short:   "Scan or patch an image",
		Example: imageCmdExamples,
	}

	imageCmd.PersistentFlags().StringVarP(&scanInfo.Format, "format", "f", "", `Output file format. Supported formats: "pretty-printer", "json", "sarif"`)
	imageCmd.PersistentFlags().StringVarP(&scanInfo.Output, "output", "o", "", "Output file. Print output to file and not stdout")
	imageCmd.PersistentFlags().BoolVarP(&scanInfo.VerboseMode, "verbose", "v", false, "Display full report. Default to false")

	imageCmd.PersistentFlags().StringVarP(&scanInfo.FailThresholdSeverity, "severity-threshold", "s", "", "Severity threshold is the severity of a vulnerability at which the command fails and returns exit code 1")

	imageCmd.PersistentFlags().StringVarP(&imgCredentials.Username, "username", "u", "", "Username for registry login")
	imageCmd.PersistentFlags().StringVarP(&imgCredentials.Password, "password", "p", "", "Password for registry login")

	imageCmd.AddCommand(getScanCmd(ks, &scanInfo, &imgCredentials))
	imageCmd.AddCommand(getPatchCmd(ks, &scanInfo, &imgCredentials))

	imageCmd.SetHelpFunc(func(command *cobra.Command, strings []string) {
		// hide kube-context and server flags
		command.Flags().MarkHidden("kube-context")
		command.Flags().MarkHidden("server")

		// this will prevent an infinite recursive call for the sub-commands of 'image'
		if parent := command.Parent().Parent(); parent != nil {
			parent.HelpFunc()(command, strings)
			return
		}

		command.Parent().HelpFunc()(command, strings)
	})

	return imageCmd
}
