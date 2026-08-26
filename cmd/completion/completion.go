package completion

import (
	"fmt"
	"os"
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
  $ echo 'source <(%[1]s completion zsh)' >> "${fpath[1]}/_%[1]s"
`, cautils.ExecName())

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
			// Check if args array is not empty
			if len(args) == 0 {
				fmt.Println("No arguments provided.")
				return
			}

			switch strings.ToLower(args[0]) {
			case "bash":
				_ = cmd.Root().GenBashCompletion(os.Stdout) // #nosec G104 -- writing completion script to stdout
			case "zsh":
				_ = cmd.Root().GenZshCompletion(os.Stdout) // #nosec G104 -- writing completion script to stdout
			case "fish":
				_ = cmd.Root().GenFishCompletion(os.Stdout, true) // #nosec G104 -- writing completion script to stdout
			case "powershell":
				_ = cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout) // #nosec G104 -- writing completion script to stdout
			default:
				fmt.Printf("Invalid argument %s", args[0])
			}
		},
	}
	return completionCmd
}
