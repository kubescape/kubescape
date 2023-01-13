package config

import (
	"context"
	"os"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v2/core/meta"
	v1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

func getViewCmd(ctx context.Context, ks meta.IKubescape) *cobra.Command {

	// configCmd represents the config command
	return &cobra.Command{
		Use:   "view",
		Short: "View cached configurations",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
			if err := ks.ViewCachedConfig(&v1.ViewConfig{Writer: os.Stdout}); err != nil {
				logger.L().Ctx(ctx).Fatal(err.Error())
			}
		},
	}
}
