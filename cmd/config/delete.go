package config

import (
	"github.com/armosec/kubescape/v2/core/meta"
	v1 "github.com/armosec/kubescape/v2/core/meta/datastructures/v1"
	logger "github.com/dwertent/go-logger"
	"github.com/spf13/cobra"
)

func getDeleteCmd(ks meta.IKubescape) *cobra.Command {
	return &cobra.Command{
		Use:   "delete",
		Short: "Delete cached configurations",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
			if err := ks.DeleteCachedConfig(&v1.DeleteConfig{}); err != nil {
				logger.L().Fatal(err.Error())
			}
		},
	}
}
