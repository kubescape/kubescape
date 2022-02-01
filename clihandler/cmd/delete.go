package cmd

import (
	"fmt"
	"os"

	"github.com/armosec/kubescape/clihandler"
	"github.com/spf13/cobra"
)

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete cached configurations and other data",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

var deleteConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Delete cached configurations",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if err := clihandler.CliDelete(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(deleteCmd)
	deleteCmd.AddCommand(deleteConfigCmd)
}
