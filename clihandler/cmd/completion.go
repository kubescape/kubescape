package cmd

import (
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var completionCmdExamples = `

  # Enable BASH shell autocompletion 
  echo 'source <(kubescape completion bash)' >> ~/.bashrc

  # Enable ZSH shell autocompletion 
  echo 'source <(kubectl completion zsh)' >> "${fpath[1]}/_kubectl"

`
var completionCmd = &cobra.Command{
	Use:                   "completion [bash|zsh|fish|powershell]",
	Short:                 "Generate autocompletion script",
	Long:                  "To load completions",
	Example:               completionCmdExamples,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.ExactValidArgs(1),
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

func init() {
	rootCmd.AddCommand(completionCmd)
}
