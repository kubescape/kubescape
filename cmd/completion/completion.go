package completion

import (
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var completionCmdExamples = `

  # Enable BASH shell autocompletion
  $ source <(kubescape completion bash)
  $ echo 'source <(kubescape completion bash)' >> ~/.bashrc

  # Enable ZSH shell autocompletion
  $ source <(kubectl completion zsh)
  $ echo 'source <(kubectl completion zsh)' >> "${fpath[1]}/_kubectl"

`

func GetCompletionCmd() *cobra.Command {
	completionCmd := &cobra.Command{
		Use:                   "completion [bash|zsh|fish|powershell]",
		Short:                 "Generate autocompletion script",
		Long:                  "To load completions",
		Example:               completionCmdExamples,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		Run: func(cmd *cobra.Command, args []string) {
			switch strings.ToLower(args[0]) {
			case "bash":
				cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			}
		},
	}
	return completionCmd
}
