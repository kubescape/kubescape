package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	sha1ver   string
	buildTime string
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Get current version",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("version")
		fmt.Println(sha1ver)
		fmt.Println(buildTime)

	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
