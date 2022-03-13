package config

import (
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/core/core"
	"github.com/spf13/cobra"
)

func getDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete",
		Short: "Delete cached configurations",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
			if err := core.DeleteCachedConfig(); err != nil {
				logger.L().Fatal(err.Error())
			}
		},
	}
}
