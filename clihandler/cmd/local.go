package cmd

import (
	"github.com/spf13/cobra"
)

var localCmd = &cobra.Command{
	Use:        "local",
	Short:      "Set configuration locally (for config.json)",
	Long:       ``,
	Deprecated: "use the 'set' command instead",
	Run: func(cmd *cobra.Command, args []string) {
	},
}

func init() {
	configCmd.AddCommand(localCmd)
}
