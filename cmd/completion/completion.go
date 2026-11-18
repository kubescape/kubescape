package completion

import (
	"fmt"
	"strings"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/spf13/cobra"
)

var completionCmdExamples = fmt.Sprintf(`
  # Enable BASH shell autocompletion
  $ source <(%[1]s completion bash)
  $ echo 'source <(%[1]s completion bash)' >> ~/.bashrc

  # Enable ZSH shell autocompletion
  $ source <(%[1]s completion zsh)
  $ %[1]s completion zsh > "${fpath[1]}/_%[1]s"

  # Enable FISH shell autocompletion
  $ %[1]s completion fish > ~/.config/fish/completions/%[1]s.fish

  # Enable PowerShell shell autocompletion
  PS> %[1]s completion powershell >> $PROFILE
`, cautils.ExecName())

func GetCompletionCmd() *cobra.Command {
	completionCmd := &cobra.Command{
		Use:                   "completion [bash|zsh|fish|powershell]",
		Short:                 "Generate shell completion scripts",
		Long:                  "Generate completion scripts for Bash, Zsh, Fish, and PowerShell.\n\nUse the examples below to enable completion in your shell.",
		Example:               completionCmdExamples,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch strings.ToLower(args[0]) {
			case "bash":
				return cmd.Root().GenBashCompletion(cmd.OutOrStdout())
			case "zsh":
				return cmd.Root().GenZshCompletion(cmd.OutOrStdout())
			case "fish":
				return cmd.Root().GenFishCompletion(cmd.OutOrStdout(), true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletionWithDesc(cmd.OutOrStdout())
			default:
				return fmt.Errorf("invalid shell %q", args[0])
			}
		},
	}
	return completionCmd
}
