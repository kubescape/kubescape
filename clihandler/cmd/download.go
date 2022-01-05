package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/spf13/cobra"
)

var downloadCmd = &cobra.Command{
	Use:   fmt.Sprintf("download framework/control <framework-name>/<control-name> [flags]\nSupported frameworks: %s", getter.NativeFrameworks),
	Short: "Download framework/control",
	Long:  ``,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 2 {
			return fmt.Errorf("requires two arguments : framework/control <framework-name>/<control-name>")
		}
		if !strings.EqualFold(args[0], "framework") && !strings.EqualFold(args[0], "control") {
			return fmt.Errorf("invalid parameter '%s'. Supported parameters: framework, control", args[0])
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := CliDownload(args); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(downloadCmd)
	downloadInfo := cautils.DownloadInfo{}
	downloadCmd.Flags().StringVarP(&downloadInfo.Path, "output", "o", "", "Output file. If specified, will store save to `~/.kubescape/<framework name>.json`")
}
