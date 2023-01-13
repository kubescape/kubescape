package config

import (
	"context"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v2/core/meta"
	v1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

func getDeleteCmd(ctx context.Context, ks meta.IKubescape) *cobra.Command {
	return &cobra.Command{
		Use:   "delete",
		Short: "Delete cached configurations",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
			if err := ks.DeleteCachedConfig(ctx, &v1.DeleteConfig{}); err != nil {
				logger.L().Ctx(ctx).Fatal(err.Error())
			}
		},
	}
}
