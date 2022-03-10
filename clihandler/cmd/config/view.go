package config

import (
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/clihandler"
	"github.com/spf13/cobra"
)

func getViewCmd() *cobra.Command {

	// configCmd represents the config command
	return &cobra.Command{
		Use:   "view",
		Short: "View cached configurations",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
			if err := clihandler.CliView(); err != nil {
				logger.L().Fatal(err.Error())
			}
		},
	}
}
