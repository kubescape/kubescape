package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/clihandler"
	"github.com/spf13/cobra"
)

var downloadInfo = cautils.DownloadInfo{}

var (
	downloadExample = `
  # Download all artifacts and save them in the default path (~/.kubescape)
  kubescape download artifacts
  
  # Download all artifacts and save them in /tmp path
  kubescape download artifacts --output /tmp
  
  # Download the NSA framework. Run 'kubescape list frameworks' for all frameworks names
  kubescape download frameworks nsa

  # Download the "Allowed hostPath" control. Run 'kubescape list controls' for all controls names
  kubescape download control "Allowed hostPath"

  # Download the "C-0001" control. Run 'kubescape list controls --id' for all controls ids
  kubescape download control C-0001

  # Download the configured exceptions
  kubescape download exceptions 

  # Download the configured controls-inputs 
  kubescape download controls-inputs 

`
)
var downloadCmd = &cobra.Command{
	Use:     "download <policy> <policy name>",
	Short:   fmt.Sprintf("Download %s", strings.Join(clihandler.DownloadSupportCommands(), ",")),
	Long:    ``,
	Example: downloadExample,
	Args: func(cmd *cobra.Command, args []string) error {
		supported := strings.Join(clihandler.DownloadSupportCommands(), ",")
		if len(args) < 1 {
			return fmt.Errorf("policy type required, supported: %v", supported)
		}
		if cautils.StringInSlice(clihandler.DownloadSupportCommands(), args[0]) == cautils.ValueNotFound {
			return fmt.Errorf("invalid parameter '%s'. Supported parameters: %s", args[0], supported)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		downloadInfo.Target = args[0]
		if len(args) >= 2 {
			downloadInfo.Name = args[1]
		}
		if err := clihandler.CliDownload(&downloadInfo); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	// cobra.OnInitialize(initConfig)

	rootCmd.AddCommand(downloadCmd)
	downloadCmd.Flags().StringVarP(&downloadInfo.Path, "output", "o", "", "Output file. If not specified, will save in `~/.kubescape/<policy name>.json`")
	downloadCmd.PersistentFlags().StringVarP(&downloadInfo.Account, "account", "", "", "Armo portal account ID. Default will load account ID from configMap or config file")

}
